package service

import (
	"context"
	"slices"
	"sort"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

const (
	dnsHookTimeout     = 30 * time.Second
	dnsApplyAlertAfter = 15 * time.Minute // an addition waiting this long fails subject "apply"
)

// dnsReloadToken is the disk table at the moment nginx is signalled (Before):
// what a reload reads if nginx takes it. gens holds, per name, the lowest
// generation among the name's segments, so a write that failed for one scope
// never lets the name be reported as fully taken. reconciled says whether
// the rows and files were in line in this process then (finishTaken).
type dnsReloadToken struct {
	seq        int64
	segs       map[string]dnsDiskEntry
	gens       map[string]int64
	reconciled bool
}

// dnsPostHoc is a reload nginx was signalled for whose acceptance was not
// seen (unconfirmed, or signalled by an operation that then failed): the
// ticks look for a child nginx started after snap. Several
// can be open at once: a revocation newer than an open one is
// signalled without waiting for it.
type dnsPostHoc struct {
	snap  *nginx.ReloadSnapshot
	token *dnsReloadToken
	since time.Time
}

// dnsRetryState is the apply loop's memory (under applyMu).
type dnsRetryState struct {
	failures   int       // failed applies in a row, for the backoff
	retryAt    time.Time // zero: no retry waiting
	failing    bool      // the last apply failed (system log transitions)
	last       nginx.DNSApplyResult
	notUpSince time.Time // start of an unbroken run of not_up results
}

// dnsApplyView is the part of the retry state readers need (under diskMu),
// so a status read never waits for an apply run.
type dnsApplyView struct {
	failing bool
	last    nginx.DNSApplyResult
	retryAt time.Time
}

// dnsAppliedChange is one name whose addresses in nginx changed.
type dnsAppliedChange struct {
	name          string
	before, after []string // before nil = unknown
	gen           int64
}

// dnsAlertMirror is what this process last recorded for one subject of
// dns_entry.apply_failed.
type dnsAlertMirror int8

const (
	dnsAlertUnknown dnsAlertMirror = iota // nothing recorded since start
	dnsAlertOK
	dnsAlertFailing
)

// ReloadHooks are the callbacks nginx.Manager runs around every reload
// signal (bootstrap: Manager.SetReloadHooks). They are how a reload of any
// path — a save, SyncAll, a rollback, the applier — marks the DNS files it
// read as applied, so a save that added a name does not need a reload of its
// own.
func (s *DNSEntryService) ReloadHooks() nginx.ReloadHooks {
	return nginx.ReloadHooks{Before: s.beforeReload, After: s.afterReload}
}

// beforeReload copies the disk table, and whether the rows and files are in
// line in this process yet. It runs inside nginx's lock and takes only
// diskMu. The flag is read under it: a flag set after the files were written
// comes with a copy that holds them.
func (s *DNSEntryService) beforeReload() any {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	s.tokenSeq++
	tok := &dnsReloadToken{
		seq:        s.tokenSeq,
		segs:       make(map[string]dnsDiskEntry, len(s.disk)),
		gens:       make(map[string]int64),
		reconciled: s.reconciled.Load(),
	}
	for k, e := range s.disk {
		tok.segs[k] = e
		if g, ok := tok.gens[e.Name]; !ok || e.Gen < g {
			tok.gens[e.Name] = e.Gen
		}
	}
	return tok
}

// afterReload learns how a signalled reload ended. Accepted and signalled
// (no probe) reloads read the token's files; so did an unconfirmed one when
// there is no snapshot to check it against. An unconfirmed or
// unchecked reload with a snapshot is kept for the post-hoc check, next to
// the older ones still open. Rejected and superseded reloads read
// nothing. It runs in the reload path and takes only diskMu; the database
// work runs in a goroutine.
func (s *DNSEntryService) afterReload(token any, outcome nginx.ReloadOutcome, snap *nginx.ReloadSnapshot) {
	tok, ok := token.(*dnsReloadToken)
	if !ok || tok == nil {
		return
	}
	switch outcome {
	case nginx.ReloadAccepted, nginx.ReloadSignalled:
		s.tokenTaken(tok)
	case nginx.ReloadUnconfirmed, nginx.ReloadNotChecked:
		if snap == nil {
			s.tokenTaken(tok)
			return
		}
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		s.addPostHocLocked(&dnsPostHoc{snap: snap, token: tok, since: s.now()})
	}
}

// addPostHocLocked keeps a reload whose acceptance is to be seen, in token
// order. The older ones stay open: nginx may have taken one of them
// and not the newest. A reload older than one nginx is known to have taken
// is not kept: that one read at least its files. Caller holds diskMu.
func (s *DNSEntryService) addPostHocLocked(ph *dnsPostHoc) {
	if ph.token.seq <= s.takenSeq {
		return
	}
	i := sort.Search(len(s.postHocs), func(i int) bool { return s.postHocs[i].token.seq > ph.token.seq })
	s.postHocs = slices.Insert(s.postHocs, i, ph)
}

// tokenTaken records that nginx runs the files tok describes. The open
// post-hoc tokens up to tok are taken first and closed: nginx took a later
// reload, so it read at least those files too. The record of what nginx
// allowed moves to tok only when tok is the newest reload taken: an older
// reload's hook can run after a newer one's.
func (s *DNSEntryService) tokenTaken(tok *dnsReloadToken) {
	gens, changes := func() (map[string]int64, []dnsAppliedChange) {
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		toks := make([]*dnsReloadToken, 0, 2)
		var open []*dnsPostHoc
		for _, ph := range s.postHocs {
			switch {
			case ph.token.seq > tok.seq:
				open = append(open, ph)
			case ph.token != tok:
				toks = append(toks, ph.token)
			}
		}
		s.postHocs = open
		if tok.seq > s.takenSeq {
			s.takenSeq = tok.seq
			s.recordAllowedLocked(tok, s.now())
		}
		s.markHostIndexDirty() // a host save's reload: what hosts render may have changed
		toks = append(toks, tok)
		gens := make(map[string]int64)
		var changes []dnsAppliedChange
		for _, t := range toks {
			changes = append(changes, s.takeTokenLocked(t)...)
			for name, g := range t.gens {
				if g > gens[name] {
					gens[name] = g
				}
			}
		}
		return gens, changes
	}()
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), dnsHookTimeout)
		defer cancel()
		s.finishTaken(ctx, gens, changes, tok.reconciled)
	}()
}

// takeTokenLocked clears the revocations nginx no longer has and moves
// nginxView forward, never back: after-hooks of different reloads can run
// out of order. It returns the names whose addresses in nginx changed.
// Caller holds diskMu.
func (s *DNSEntryService) takeTokenLocked(t *dnsReloadToken) []dnsAppliedChange {
	for k, pr := range s.pendingRevoke {
		if g, ok := t.gens[pr.Name]; ok && g >= pr.Gen {
			delete(s.pendingRevoke, k)
		}
	}
	byName := make(map[string][]string, len(t.gens))
	for _, e := range t.segs {
		byName[e.Name] = dnsUnion(byName[e.Name], e.Addrs)
	}
	names := make([]string, 0, len(t.gens))
	for name := range t.gens {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []dnsAppliedChange
	for _, name := range names {
		gen := t.gens[name]
		after := byName[name]
		view, known := s.nginxView[name]
		if known && view.Gen > gen {
			continue
		}
		s.nginxView[name] = dnsViewEntry{Gen: gen, Addrs: after}
		if known && dnsSameSet(view.Addrs, after) {
			continue
		}
		ch := dnsAppliedChange{name: name, after: dnsNonNil(after), gen: gen}
		if known {
			ch.before = dnsNonNil(view.Addrs)
		}
		out = append(out, ch)
	}
	return out
}

// dnsNonNil returns in, or an empty (non-nil) slice: a known empty set.
func dnsNonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// finishTaken records the taken generations, audits the changed names and
// looks at the apply alerts again when the taken reload was signalled with
// the rows and files in line in this process (reconciled: a ReconcileFiles
// or a check had finished). A reload at boot can be signalled before that
// (the raw log settings are applied while startup runs): it read files
// ReconcileFiles had not written, the rows are still as the last process
// left them, and an addition that waited across the restart would open
// dns_entry.apply_failed until startup's own reload takes it. The signal
// decides, not this call: nginx confirms a reload for a while after it,
// and ReconcileFiles does not wait for that. A check that runs no apply,
// and an apply that fails, look at the alerts either way.
func (s *DNSEntryService) finishTaken(ctx context.Context, gens map[string]int64, changes []dnsAppliedChange, reconciled bool) {
	if len(gens) > 0 {
		if err := s.states.MarkApplied(ctx, gens); err != nil {
			s.logs.fail("mark", "[DNSEntries] WARN: could not record which domain entries nginx applied; the next check applies them again: %v", err)
		} else {
			s.logs.ok("mark")
		}
	}
	for _, ch := range changes {
		s.events.applied(ctx, ch.name, ch.before, ch.after, ch.gen)
	}
	if reconciled {
		s.evaluateApplyAlerts(ctx, nil)
	}
}

// evaluateApplyAlerts sets dns_entry.apply_failed from the rows.
// Subject "revoke" fails the first time an apply fails while a revocation
// waits (failure: the apply result that just failed, nil otherwise) and
// recovers once no revocation waits. Subject "apply" fails while an addition
// has waited longer than 15 minutes and recovers when none has. Evaluations
// overlap (reload hooks, the apply loop, the check), so the rows are read
// under alertMu: a read made before another is never applied after it.
func (s *DNSEntryService) evaluateApplyAlerts(ctx context.Context, failure *nginx.DNSApplyResult) {
	s.alertMu.Lock()
	defer s.alertMu.Unlock()
	rows, err := s.states.GetStates(ctx, nil)
	if err != nil {
		return
	}
	now := s.now()
	var revoke, apply []string
	for name, st := range rows {
		switch {
		case st.RevokePendingSince != nil:
			revoke = append(revoke, name)
		case st.Generation > st.AppliedGeneration && st.LastChangedAt != nil && now.Sub(*st.LastChangedAt) > dnsApplyAlertAfter:
			apply = append(apply, name)
		}
	}
	sort.Strings(revoke)
	sort.Strings(apply)
	switch {
	case failure != nil && len(revoke) > 0:
		s.setApplyAlertLocked(ctx, &s.revokeMirror, dnsApplyAlert{Subject: "revoke", Failing: true,
			Outcome: failure.Outcome, File: failure.BlockingFile, Names: revoke})
	case len(revoke) == 0:
		s.setApplyAlertLocked(ctx, &s.revokeMirror, dnsApplyAlert{Subject: "revoke"})
	}
	s.setApplyAlertLocked(ctx, &s.applyMirror, dnsApplyAlert{Subject: "apply", Failing: len(apply) > 0, Names: apply})
}

// setApplyAlertLocked records one subject's change, and nothing when the
// mirror already says so. Caller holds alertMu.
func (s *DNSEntryService) setApplyAlertLocked(ctx context.Context, mirror *dnsAlertMirror, a dnsApplyAlert) {
	want := dnsAlertOK
	if a.Failing {
		want = dnsAlertFailing
	}
	if *mirror == want {
		return
	}
	a.Quiet = !a.Failing && *mirror == dnsAlertUnknown
	if err := s.events.applyAlert(ctx, a); err != nil {
		s.logs.fail("alert:"+a.Subject, "[DNSEntries] WARN: could not record the %s alert; retrying at every check: %v", a.Subject, err)
		return
	}
	s.logs.ok("alert:" + a.Subject)
	*mirror = want
}

// announceReviews keeps dns_entry.review failing for every used name in
// review: one that just entered review, and after a restart every one
// still in review — the set starts empty, and the alert's stored state keeps
// that silent when it was failing already. It also retries closes that
// failed. rows may be a subset; scopes counts each name's uses.
func (s *DNSEntryService) announceReviews(ctx context.Context, rows map[string]model.DNSEntryState, scopes map[string]int) {
	s.reviewMu.Lock()
	defer s.reviewMu.Unlock()
	closing := make([]string, 0, len(s.reviewClosing))
	for name := range s.reviewClosing {
		closing = append(closing, name)
	}
	sort.Strings(closing)
	for _, name := range closing {
		if err := s.events.reviewClosed(ctx, name, s.reviewClosing[name]); err == nil {
			delete(s.reviewClosing, name)
		}
	}
	names := make([]string, 0, len(rows))
	for name := range rows {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		st := rows[name]
		if st.Status != model.DNSStatusNeedsReview {
			delete(s.reviewAnnounced, name)
			continue
		}
		if s.reviewAnnounced[name] || scopes[name] == 0 || s.reviewClosing[name] {
			continue
		}
		if err := s.events.reviewAlert(ctx, name, st, scopes[name]); err != nil {
			s.logs.fail("review", "[DNSEntries] WARN: could not record a review alert; retrying at every check: %v", err)
			continue
		}
		s.logs.ok("review")
		s.reviewAnnounced[name] = true
	}
}

// closeReview ends dns_entry.review for name: recovered after a confirm,
// quietly when the name is no longer used or its row goes. A close that
// cannot be recorded is retried by announceReviews.
func (s *DNSEntryService) closeReview(ctx context.Context, name string, confirmed bool) {
	s.reviewMu.Lock()
	defer s.reviewMu.Unlock()
	delete(s.reviewAnnounced, name)
	if err := s.events.reviewClosed(ctx, name, confirmed); err != nil {
		s.logs.fail("review", "[DNSEntries] WARN: could not record a review alert; retrying at every check: %v", err)
		s.reviewClosing[name] = confirmed
		return
	}
	delete(s.reviewClosing, name)
}
