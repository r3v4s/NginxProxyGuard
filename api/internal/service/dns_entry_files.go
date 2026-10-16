package service

import (
	"context"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

const (
	dnsUnusedRowTTL = 7 * 24 * time.Hour // a name re-added within 7 days keeps its review and pin
	dnsEmptyFileTTL = 24 * time.Hour     // a file is deleted after a day empty
	dnsGCInterval   = 24 * time.Hour
)

// dnsDiskEntry is what this process last wrote for one (scope, name): the
// name's generation and addresses. Addrs is never changed in place, so a copy
// of the entry (a reload token) stays valid.
type dnsDiskEntry struct {
	Scope, Name string
	Gen         int64
	Addrs       []string
}

// dnsRevokeEntry holds addresses removed from a segment's file that nginx may
// still allow: no reload that read a file without them has been accepted
// yet. Gen is the generation of the write that removed the latest of them.
type dnsRevokeEntry struct {
	Scope, Name string
	Gen         int64
	Addrs       []string
}

// dnsViewEntry is what nginx is known to run for one name, for the
// dns_entry_applied audit's "before".
type dnsViewEntry struct {
	Gen   int64
	Addrs []string
}

// dnsNameChange is one transition to report once the locks are released.
type dnsNameChange struct {
	name string
	eff  dnsentry.Effects
	st   model.DNSEntryState
}

// dnsReportable: a status change or a review entry is worth an event.
func dnsReportable(eff dnsentry.Effects) bool {
	return eff.FromStatus != eff.ToStatus || eff.EnteredReview != ""
}

// dnsMergeEffects folds the effects of two transitions applied one after the
// other into one.
func dnsMergeEffects(a, b dnsentry.Effects, first bool) dnsentry.Effects {
	if first {
		return b
	}
	out := a
	out.Revoked = dnsUnion(a.Revoked, b.Revoked)
	out.Added = dnsUnion(a.Added, b.Added)
	if b.EnteredReview != "" {
		out.EnteredReview = b.EnteredReview
	}
	out.Recorded = a.Recorded || b.Recorded
	out.ToStatus = b.ToStatus
	return out
}

// dnsSettle applies the transitions that need no DNS answer: the grace expiry
// at boot (expireGrace > 0), the feature switch and used ↔ unused. An
// unused name used again without an answer keeps nothing published
// (Reactivate with no observation). touched reports whether
// any transition ran.
func dnsSettle(prev model.DNSEntryState, used bool, sw dnsSwitch, now time.Time, expireGrace time.Duration) (model.DNSEntryState, dnsentry.Effects, bool) {
	next := prev
	var eff dnsentry.Effects
	touched := false
	apply := func(st model.DNSEntryState, e dnsentry.Effects) {
		eff = dnsMergeEffects(eff, e, !touched)
		next = st
		touched = true
	}
	if expireGrace > 0 && len(next.Published) > 0 {
		st, e := dnsentry.ExpireStale(next, now, expireGrace)
		if !dnsSameSet(st.Published, next.Published) || st.Status != next.Status {
			apply(st, e)
		}
	}
	if sw.known && !sw.enabled && !next.Disabled {
		apply(dnsentry.Disable(next, now))
	}
	if sw.known && sw.enabled && next.Disabled {
		st := dnsentry.Enable(next)
		apply(st, dnsentry.Effects{FromStatus: next.Status, ToStatus: st.Status})
	}
	if !used && next.UnusedSince == nil {
		apply(dnsentry.MarkUnused(next, now))
	}
	if used && next.UnusedSince != nil {
		apply(dnsentry.Reactivate(next, nil, now))
	}
	return next, eff, touched
}

// dnsDesired is what a referenced (scope, name) file holds: the name's
// published addresses while the name may be used, else nothing.
func dnsDesired(st model.DNSEntryState, ok bool) []string {
	if !ok || st.Disabled || st.UnusedSince != nil {
		return nil
	}
	return st.Published
}

// writeSegment is the only place the service writes DNS include files. It
// writes one (scope, name) file set and then records it: the disk table, and
// in pendingRevoke every address the set held before (oldExtra: what a
// directory read found in it) that it no longer holds. The file is written
// first: a reload that reads the new file while the table still shows the old
// entry under-claims, which is the safe side.
//
// A write that fails keeps the table's entry. When there is none yet (the
// first write since start), the set is recorded as it is on disk (onDisk: a
// directory read): the lowest generation its headers carry, 0 for a file
// without one or a missing file, and the addresses it holds. Without that, a
// reload token would claim the name's generation from its other files alone
// while this file still holds older addresses, and dnsAllows would miss
// them. The next sync writes it again. Caller holds dnsMu.
func (s *DNSEntryService) writeSegment(scope, name string, gen int64, addrs, oldExtra []string, onDisk func() []nginx.DNSIncludeFile) (bool, error) {
	addrs = dnsSortedUnique(addrs)
	changed, err := s.nginx.WriteDNSIncludeFiles(scope, name, gen, addrs)
	key := dnsSegKey(scope, name)
	if err != nil {
		s.diskMu.Lock()
		_, known := s.disk[key]
		s.diskMu.Unlock()
		if !known {
			fileGen, fileAddrs := dnsSegmentOnDisk(onDisk(), scope, name)
			s.diskMu.Lock()
			if _, known := s.disk[key]; !known {
				s.disk[key] = dnsDiskEntry{Scope: scope, Name: name, Gen: fileGen, Addrs: fileAddrs}
			}
			s.diskMu.Unlock()
		}
		return false, err
	}
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	old := s.disk[key]
	removed := dnsMinus(dnsUnion(old.Addrs, oldExtra), addrs)
	s.disk[key] = dnsDiskEntry{Scope: scope, Name: name, Gen: gen, Addrs: addrs}
	pr, had := s.pendingRevoke[key]
	if !had {
		pr = dnsRevokeEntry{Scope: scope, Name: name}
	}
	if len(removed) > 0 {
		pr.Addrs = dnsUnion(pr.Addrs, removed)
		pr.Gen = gen
	}
	// An address written again is allowed by the file itself.
	pr.Addrs = dnsMinus(pr.Addrs, addrs)
	if len(pr.Addrs) == 0 {
		delete(s.pendingRevoke, key)
	} else {
		s.pendingRevoke[key] = pr
	}
	return changed, nil
}

// dnsSegmentOnDisk returns what the files of (scope, name) hold in a
// directory read: the lowest generation their headers carry (0 when one has
// no header or is missing) and the addresses they hold.
func dnsSegmentOnDisk(dir []nginx.DNSIncludeFile, scope, name string) (int64, []string) {
	key := nginx.DNSIncludeKey(scope, name)
	exts := nginx.DNSIncludeExts(scope)
	var gen int64
	var addrs []string
	found := 0
	for _, f := range dir {
		if f.Key != key || !slices.Contains(exts, f.Ext) {
			continue
		}
		var g int64
		if f.HasHeader {
			g = f.Gen
		}
		if found == 0 || g < gen {
			gen = g
		}
		found++
		addrs = dnsUnion(addrs, f.Addrs)
	}
	if found < len(exts) {
		gen = 0
	}
	return gen, addrs
}

// dnsAllows reports whether nginx may allow addr through a file of scope: an
// address a file holds now — published, maybe not yet taken by nginx
// — or one removed that nginx may not have dropped yet. The fail2ban
// evaluator asks this from the log goroutine: memory only.
func (s *DNSEntryService) dnsAllows(scope, addr string) bool {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	for _, e := range s.disk {
		if e.Scope == scope {
			for _, a := range e.Addrs {
				if a == addr {
					return true
				}
			}
		}
	}
	for _, e := range s.pendingRevoke {
		if e.Scope == scope {
			for _, a := range e.Addrs {
				if a == addr {
					return true
				}
			}
		}
	}
	return false
}

// syncFilesLocked makes the DNS include files hold what the database
// wants: every referenced (scope, name) of the names in scope gets
// the name's published addresses when the name may be used, and nothing
// otherwise; every other segment of those names — a scope that dropped the
// name — is written empty with the name's generation, so a reload token can
// report the name's generation as taken. With only == nil every name is in
// scope and dir (a directory read) is swept too: a file whose header names a
// segment nothing references is emptied. All files are compared, not just the
// changed names, so a lost volume, a failed write or an empty file a render
// made is put right. Caller holds dnsMu. Returns whether a file changed.
func (s *DNSEntryService) syncFilesLocked(refs []model.DNSReference, rows map[string]model.DNSEntryState, dir []nginx.DNSIncludeFile, only map[string]bool) bool {
	inScope := func(name string) bool { return only == nil || only[name] }
	type seg struct{ scope, name string }
	want := make(map[string]seg)
	for _, r := range refs {
		if inScope(r.Name) {
			want[dnsSegKey(r.Scope, r.Name)] = seg{r.Scope, r.Name}
		}
	}
	fileAddrs := make(map[string][]string)
	for _, f := range dir {
		if f.HasHeader {
			k := dnsSegKey(f.Scope, f.Name)
			fileAddrs[k] = dnsUnion(fileAddrs[k], f.Addrs)
		}
	}
	// What a failed write records the files from: dir, else one directory
	// read made the first time a write fails.
	onDisk, looked := dir, dir != nil
	readOnce := func() []nginx.DNSIncludeFile {
		if !looked {
			onDisk, looked = s.readDir(), true
		}
		return onDisk
	}
	wrote := false
	write := func(scope, name string, gen int64, addrs []string) {
		key := "write:" + dnsSegKey(scope, name)
		changed, err := s.writeSegment(scope, name, gen, addrs, fileAddrs[dnsSegKey(scope, name)], readOnce)
		if err != nil {
			s.logs.fail(key, "[DNSEntries] ERROR: could not write the include file of %s (scope %s); retrying at every check: %v", name, scope, err)
			return
		}
		s.logs.ok(key)
		wrote = wrote || changed
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sg := want[k]
		row, ok := rows[sg.name]
		write(sg.scope, sg.name, row.Generation, dnsDesired(row, ok))
	}
	done := make(map[string]bool, len(want))
	for k := range want {
		done[k] = true
	}
	if only == nil {
		for _, f := range dir {
			k := dnsSegKey(f.Scope, f.Name)
			if !f.HasHeader || done[k] || !dnsValidSegment(f.Scope, f.Name) {
				continue
			}
			done[k] = true
			gen := f.Gen
			if row, ok := rows[f.Name]; ok {
				gen = row.Generation
			}
			write(f.Scope, f.Name, gen, nil)
		}
	}
	// Segments this process wrote before that are no longer referenced.
	type stale struct {
		key string
		e   dnsDiskEntry
	}
	var rest []stale
	s.diskMu.Lock()
	for k, e := range s.disk {
		if !done[k] && inScope(e.Name) {
			rest = append(rest, stale{k, e})
		}
	}
	s.diskMu.Unlock()
	sort.Slice(rest, func(i, j int) bool { return rest[i].key < rest[j].key })
	for _, r := range rest {
		gen := r.e.Gen
		if row, ok := rows[r.e.Name]; ok {
			gen = row.Generation
		}
		if gen != r.e.Gen || len(r.e.Addrs) > 0 {
			write(r.e.Scope, r.e.Name, gen, nil)
		}
	}
	return wrote
}

// ReconcileFiles puts the database and the files in line without asking DNS
// or nginx anything: at boot before any reload and
// after a restore. It gives every referenced name a row (pending when
// new), applies the grace expiry of names that went unchecked while the API
// was down, sets the feature switch, writes every file, and with scanDisk
// creates, empty, every npg_dns file a configuration references but that is
// missing (a restored configuration can name keys the database does not know).
func (s *DNSEntryService) ReconcileFiles(ctx context.Context, scanDisk bool) error {
	st, known := s.currentSettings(ctx)
	sw := dnsSwitch{known: known, enabled: st.Enabled}
	now := s.now()
	var changes []dnsNameChange
	err := func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		var refs []model.DNSReference
		rows := make(map[string]model.DNSEntryState)
		err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			r, err := tx.ListReferences(ctx)
			if err != nil {
				return err
			}
			refs = r
			cur, err := tx.GetStates(ctx, nil)
			if err != nil {
				return err
			}
			used := dnsUseCounts(refs)
			for _, name := range dnsNamesOf(cur, used) {
				prev, exists := cur[name]
				if !exists {
					prev = dnsNewRow(tx, name, now, sw)
				}
				next, eff, touched := dnsSettle(prev, used[name] > 0, sw, now, st.StaleGrace())
				if !exists || touched {
					if err := tx.UpsertState(ctx, next); err != nil {
						return err
					}
				}
				rows[name] = next
				if touched && dnsReportable(eff) {
					changes = append(changes, dnsNameChange{name, eff, next})
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.syncFilesLocked(refs, rows, s.readDir(), nil)
		if scanDisk {
			s.ensureReferencedFilesLocked()
		}
		s.seedNginxViewLocked(refs, rows)
		return nil
	}()
	if err != nil {
		return err
	}
	for _, c := range changes {
		s.events.nameChanged(ctx, c.name, c.eff, c.st)
	}
	s.reconciled.Store(true)
	return nil
}

// dnsValidSegment: a header names a scope and a name the service could have
// written; anything else is not ours to rewrite.
func dnsValidSegment(scope, name string) bool {
	_, _, ok := model.ParseDNSScope(scope)
	return ok && model.ValidateDNSName(name) == nil
}

// readDir reads the include directory. A failed read is logged once and gives
// no files: the sweep of unreferenced files waits for the next check.
func (s *DNSEntryService) readDir() []nginx.DNSIncludeFile {
	dir, err := s.nginx.ReadDNSIncludeDir()
	if err != nil {
		s.logs.fail("dir", "[DNSEntries] WARN: could not read the domain include directory: %v", err)
		return nil
	}
	s.logs.ok("dir")
	return dir
}

// dnsNamesOf returns the names that have a row or a use, sorted.
func dnsNamesOf(rows map[string]model.DNSEntryState, used map[string]int) []string {
	seen := make(map[string]bool, len(rows)+len(used))
	var out []string
	for n := range rows {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for n := range used {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ensureReferencedFilesLocked creates, empty, every npg_dns file a
// configuration on disk references but that does not exist.
// Caller holds dnsMu.
func (s *DNSEntryService) ensureReferencedFilesLocked() {
	referenced, err := s.nginx.ScanDNSIncludeReferences()
	if err != nil {
		log.Printf("[DNSEntries] WARN: could not scan the nginx configuration for domain include files: %v", err)
		return
	}
	dir, err := s.nginx.ReadDNSIncludeDir()
	if err != nil {
		log.Printf("[DNSEntries] WARN: could not read the domain include directory: %v", err)
		return
	}
	present := make(map[string]bool, len(dir))
	for _, f := range dir {
		present[dnsFileName(f.Key, f.Ext)] = true
	}
	names := make([]string, 0, len(referenced))
	for k, ok := range referenced {
		if ok && !present[k] {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		key, ext := splitDNSIncludeName(k)
		if err := s.nginx.EnsureDNSIncludeFile(key, ext); err != nil {
			log.Printf("[DNSEntries] ERROR: could not create the missing include file %s: %v", k, err)
		}
	}
}

// dnsFileName is a file's name in the directory, "<key>.<ext>", whether ext
// was given with its dot (DNSIncludeExts) or without.
func dnsFileName(key, ext string) string {
	if ext != "" && ext[0] != '.' {
		return key + "." + ext
	}
	return key + ext
}

// splitDNSIncludeName splits "<key>.<ext>" into the key and ".<ext>".
func splitDNSIncludeName(file string) (key, ext string) {
	for i := len(file) - 1; i >= 0; i-- {
		if file[i] == '.' {
			return file[:i], file[i:]
		}
	}
	return file, ""
}

// seedNginxViewLocked fills nginxView once at boot from the rows: a name whose
// applied generation is its generation is in nginx as the database says; any
// other name is unknown until a reload is taken. Caller holds dnsMu.
func (s *DNSEntryService) seedNginxViewLocked(refs []model.DNSReference, rows map[string]model.DNSEntryState) {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	if s.viewSeeded {
		return
	}
	s.viewSeeded = true
	used := dnsUseCounts(refs)
	for name, row := range rows {
		if row.AppliedGeneration != row.Generation {
			continue
		}
		var addrs []string
		if used[name] > 0 {
			addrs = dnsDesired(row, true)
		}
		s.nginxView[name] = dnsViewEntry{Gen: row.Generation, Addrs: dnsSortedUnique(addrs)}
	}
}

// collectGarbage runs once a day from the tick (and at its first run): it
// deletes the rows of names unused for 7 days and the files nothing references
// that have been empty for a day.
func (s *DNSEntryService) collectGarbage(ctx context.Context) {
	now := s.now()
	rows, err := s.states.GetStates(ctx, nil)
	if err != nil {
		log.Printf("[DNSEntries] WARN: domain entry cleanup skipped: %v", err)
		return
	}
	var old []string
	for name, st := range rows {
		if st.UnusedSince != nil && now.Sub(*st.UnusedSince) > dnsUnusedRowTTL {
			old = append(old, name)
		}
	}
	sort.Strings(old)
	if len(old) > 0 {
		// Close a review alert before its row goes: nothing could close it after.
		for _, name := range old {
			if rows[name].Status == model.DNSStatusNeedsReview {
				s.closeReview(ctx, name, false)
			}
		}
		var deleted []string
		err := func() error {
			s.dnsMu.Lock()
			defer s.dnsMu.Unlock()
			err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
				deleted = nil
				refs, err := tx.ListReferences(ctx)
				if err != nil {
					return err
				}
				used := dnsUseCounts(refs)
				cur, err := tx.GetStates(ctx, old)
				if err != nil {
					return err
				}
				for _, name := range old {
					st, ok := cur[name]
					if !ok || used[name] > 0 || st.UnusedSince == nil || now.Sub(*st.UnusedSince) <= dnsUnusedRowTTL {
						continue
					}
					if err := tx.DeleteState(ctx, name); err != nil {
						return err
					}
					deleted = append(deleted, name)
				}
				return nil
			})
			if err == nil {
				// What nginx ran under a deleted row says nothing about a row
				// the name gets later: its first reload is audited with the
				// "before" unknown. Its files, while they stay, still keep that
				// row above their generations (dnsFloorTx).
				s.diskMu.Lock()
				for _, name := range deleted {
					delete(s.nginxView, name)
				}
				s.diskMu.Unlock()
			}
			return err
		}()
		if err != nil {
			log.Printf("[DNSEntries] WARN: could not delete unused domain entries: %v", err)
		}
	}
	removed, err := s.nginx.GCDNSIncludeFiles(ctx, s.referencedForGC(ctx), dnsEmptyFileTTL)
	if err != nil {
		log.Printf("[DNSEntries] WARN: could not remove unused domain include files: %v", err)
	}
	if removed > 0 {
		s.forgetMissingFiles()
	}
}

// referencedForGC answers, for the file GC (which calls it inside nginx's
// lock), whether the database references a (scope, name). It reads the
// references once, without any DNS lock; when they cannot be read every file
// counts as referenced and nothing is deleted.
func (s *DNSEntryService) referencedForGC(ctx context.Context) func(scope, name string) bool {
	var once sync.Once
	var used map[string]bool
	return func(scope, name string) bool {
		once.Do(func() {
			refs, err := s.states.ListReferences(ctx)
			if err != nil {
				return
			}
			used = make(map[string]bool, len(refs))
			for _, r := range refs {
				used[dnsSegKey(r.Scope, r.Name)] = true
			}
		})
		return used == nil || used[dnsSegKey(scope, name)]
	}
}

// forgetMissingFiles drops the table entries of segments whose files the GC
// deleted (empty for a day, so nothing nginx still allows is lost).
func (s *DNSEntryService) forgetMissingFiles() {
	dir, err := s.nginx.ReadDNSIncludeDir()
	if err != nil {
		return
	}
	present := make(map[string]bool, len(dir))
	for _, f := range dir {
		present[dnsFileName(f.Key, f.Ext)] = true
	}
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	gone := func(scope, name string) bool {
		key := nginx.DNSIncludeKey(scope, name)
		for _, ext := range nginx.DNSIncludeExts(scope) {
			if present[dnsFileName(key, ext)] {
				return false
			}
		}
		return true
	}
	for k, e := range s.disk {
		if gone(e.Scope, e.Name) {
			delete(s.disk, k)
		}
	}
	for k, e := range s.pendingRevoke {
		if gone(e.Scope, e.Name) {
			delete(s.pendingRevoke, k)
		}
	}
}
