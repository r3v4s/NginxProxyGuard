package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// DNSLimitError is a save that would put more domain names in one list, or
// in the whole install, than the limits allow. Handlers answer
// 400 with Error().
type DNSLimitError struct {
	Field string // "items" (max_per_list) or "dns_entry_settings.max_total"
	Limit int
	Got   int
}

func (e *DNSLimitError) Error() string {
	return fmt.Sprintf("%s: at most %d domains (got %d)", e.Field, e.Limit, e.Got)
}

// ValidateScopeNames refuses a save that ends above a limit and raises that
// count: lowering a limit never freezes a list that is already over
// it, it only stops it growing. names are the names the scope will hold.
func (s *DNSEntryService) ValidateScopeNames(ctx context.Context, scope string, names []string) error {
	st := s.Settings(ctx)
	names = dnsCleanNames(names)
	refs, err := s.states.ListReferences(ctx)
	if err != nil {
		return fmt.Errorf("list domain references: %w", err)
	}
	inScope := make(map[string]bool)
	before := make(map[string]bool)
	after := make(map[string]bool)
	for _, r := range refs {
		before[r.Name] = true
		if r.Scope == scope {
			inScope[r.Name] = true
			continue
		}
		after[r.Name] = true
	}
	for _, n := range names {
		after[n] = true
	}
	if len(names) > st.MaxPerList && len(names) > len(inScope) {
		return &DNSLimitError{Field: "items", Limit: st.MaxPerList, Got: len(names)}
	}
	if len(after) > st.MaxTotal && len(after) > len(before) {
		return &DNSLimitError{Field: "dns_entry_settings.max_total", Limit: st.MaxTotal, Got: len(after)}
	}
	return nil
}

// SyncScope brings one scope's names up to date right after the caller
// committed them and before it regenerates nginx configs. It
// is the save path's half of the work; the tick does the same from the
// database within one interval if a caller forgets it.
//  1. (no lock) resolve, within SaveResolveTimeout, the names that are new to
//     the service: no row, unused, or pending and never published.
//  2. (dnsMu) the feature switch read again (the answers are dropped when
//     it changed), then one transaction: rows for new names; a pending
//     name's first answer published at once (an operator action, outside
//     the budget); a name re-added within 7 days takes back its state
//     (Reactivate); a name that left the scope — its file here held
//     addresses — gets a new generation and a revocation, or is marked
//     unused when nothing else uses it.
//  3. (dnsMu) the files of every touched name.
//
// The caller's own reload carries the change to nginx: the reload hooks mark
// it applied. When that reload fails, the next tick applies it.
func (s *DNSEntryService) SyncScope(ctx context.Context, scope string, names []string) error {
	if _, _, ok := model.ParseDNSScope(scope); !ok {
		return fmt.Errorf("invalid dns scope %q", scope)
	}
	names = dnsCleanNames(names)
	st, known := s.currentSettings(ctx)
	sw := dnsSwitch{known: known, enabled: st.Enabled}

	var obs map[string]dnsentry.Observation
	if st.Enabled && len(names) > 0 {
		cur, err := s.states.GetStates(ctx, names)
		if err != nil {
			return fmt.Errorf("read domain entries: %w", err)
		}
		var fresh []string
		for _, n := range names {
			row, ok := cur[n]
			if !ok || row.UnusedSince != nil || (row.Status == model.DNSStatusPending && len(row.LastApplied) == 0) {
				fresh = append(fresh, n)
			}
		}
		if len(fresh) > 0 {
			rctx, cancel := context.WithTimeout(ctx, s.saveResolve)
			obs, _ = s.resolveAll(rctx, fresh, st, min(s.perLookup, s.saveResolve))
			cancel()
		}
	}

	now := s.now()
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	var changes []dnsNameChange
	var unused []string
	var refs []model.DNSReference
	rows := make(map[string]model.DNSEntryState)
	err := func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		if cur := s.currentSwitch(ctx); cur != sw {
			// As in a check: a switch stored during the lookups drops the
			// answers, so a save publishes nothing once "off" is stored.
			sw, obs = cur, nil
		}
		gone := s.scopeNamesLocked(scope, keep)
		err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			changes, unused = nil, nil
			r, err := tx.ListReferences(ctx)
			if err != nil {
				return err
			}
			refs = r
			used := dnsUseCounts(refs)
			all := append(append([]string(nil), names...), gone...)
			if len(all) == 0 {
				return nil
			}
			cur, err := tx.GetStates(ctx, all)
			if err != nil {
				return err
			}
			for _, name := range names {
				prev, exists := cur[name]
				if !exists {
					prev = dnsNewRow(tx, name, now, sw)
				}
				var o *dnsentry.Observation
				if v, ok := obs[name]; ok {
					o = &v
				}
				next, eff, touched := dnsSaveTransition(prev, o, now)
				if exists && next.Generation == prev.Generation && len(dnsDesired(next, true)) > 0 &&
					s.newSegmentLocked([]string{scope}, name) {
					next.Generation++
					changed := now
					next.LastChangedAt = &changed
					touched = true
				}
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
			for _, name := range gone {
				prev, ok := cur[name]
				if !ok {
					continue
				}
				next := prev
				switch {
				case used[name] == 0 && prev.UnusedSince == nil:
					var eff dnsentry.Effects
					next, eff = dnsentry.MarkUnused(prev, now)
					if dnsReportable(eff) {
						changes = append(changes, dnsNameChange{name, eff, next})
					}
					if next.Status == model.DNSStatusNeedsReview {
						unused = append(unused, name)
					}
				case len(s.diskAddrsLocked(scope, name)) > 0:
					// The name stays in other scopes: its file here is emptied, which
					// is a revocation nginx has to take.
					next.Generation++
					if next.RevokePendingSince == nil {
						t := now
						next.RevokePendingSince = &t
					}
				default:
					rows[name] = prev
					continue
				}
				if err := tx.UpsertState(ctx, next); err != nil {
					return err
				}
				rows[name] = next
			}
			return nil
		})
		if err != nil {
			return err
		}
		only := make(map[string]bool, len(rows))
		for name := range rows {
			only[name] = true
		}
		s.syncFilesLocked(refs, rows, nil, only)
		return nil
	}()
	if err != nil {
		return err
	}

	for _, c := range changes {
		s.events.nameChanged(ctx, c.name, c.eff, c.st)
	}
	for _, name := range unused {
		s.closeReview(ctx, name, false)
	}
	s.announceReviews(ctx, rows, dnsUseCounts(refs))
	if kind, owner, ok := model.ParseDNSScope(scope); ok && kind == model.DNSScopeKindAccessList {
		s.rebuildHostIndex(ctx, refs, owner)
		s.markHostIndexDirty() // and every list again, in the background
	}
	return nil
}

// dnsSaveTransition is one name's transition on the save path: Reactivate
// for a name re-added within 7 days (with the answer when it came in
// time), FirstPublish for a pending name's first answer. The feature switch
// is the tick's: a switched-off name publishes nothing here.
func dnsSaveTransition(prev model.DNSEntryState, o *dnsentry.Observation, now time.Time) (model.DNSEntryState, dnsentry.Effects, bool) {
	if prev.UnusedSince != nil {
		if prev.Disabled {
			o = nil
		}
		next, eff := dnsentry.Reactivate(prev, o, now)
		return next, eff, true
	}
	if o != nil && !prev.Disabled && prev.Status == model.DNSStatusPending && len(prev.LastApplied) == 0 {
		next, eff := dnsentry.FirstPublish(prev, *o, now)
		return next, eff, true
	}
	return prev, dnsentry.Effects{FromStatus: prev.Status, ToStatus: prev.Status}, false
}

// scopeNamesLocked returns the names this process has a file of scope for
// that are not in keep. Caller holds dnsMu.
func (s *DNSEntryService) scopeNamesLocked(scope string, keep map[string]bool) []string {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	seen := make(map[string]bool)
	var out []string
	for _, e := range s.disk {
		if e.Scope == scope && !keep[e.Name] && !seen[e.Name] {
			seen[e.Name] = true
			out = append(out, e.Name)
		}
	}
	return dnsSortedUnique(out)
}

// newSegmentLocked reports whether one of scopes is a scope of name this
// process has no file of yet. When the name has addresses for it, nginx must
// read that file: the generation moves, as for any change of what the name's
// files hold (published values and uses). Caller holds dnsMu.
func (s *DNSEntryService) newSegmentLocked(scopes []string, name string) bool {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	for _, scope := range scopes {
		if _, ok := s.disk[dnsSegKey(scope, name)]; !ok {
			return true
		}
	}
	return false
}

// dnsScopesByName lists the scopes using each name.
func dnsScopesByName(refs []model.DNSReference) map[string][]string {
	out := make(map[string][]string)
	for _, r := range refs {
		out[r.Name] = append(out[r.Name], r.Scope)
	}
	return out
}

// diskAddrsLocked returns what this process last wrote for a segment.
func (s *DNSEntryService) diskAddrsLocked(scope, name string) []string {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	return s.disk[dnsSegKey(scope, name)].Addrs
}

// SettingsChanged applies a change of the stored settings.
// Turning the feature off disables every name and empties every file at
// once, a revocation outside the budget; turning it on lifts the flag and
// the next check decides (review stays, pending names publish
// their first answer, the rest follow the empty-state rule). A shorter
// interval or a switch wakes the scheduler. Nothing here waits for nginx:
// the check that Kick starts applies the files.
func (s *DNSEntryService) SettingsChanged(ctx context.Context, before, after model.DNSEntrySettings) {
	after = after.Normalize()
	s.settingsMu.Lock()
	stored := after
	s.lastGood = &stored
	s.settingsMu.Unlock()
	wasOn := before.Enabled && !s.envDisabled
	isOn := after.Enabled && !s.envDisabled
	if wasOn != isOn {
		if err := s.switchAll(ctx, isOn); err != nil {
			log.Printf("[DNSEntries] WARN: could not switch the domain entries %s at once; the next check does it: %v", dnsOnOff(isOn), err)
		}
	}
	s.markHostIndexDirty() // rebuilt in the background
	if wasOn != isOn || after.CheckIntervalSeconds < before.CheckIntervalSeconds {
		s.Kick()
	}
}

func dnsOnOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// switchAll sets the feature switch on every row and writes every file.
func (s *DNSEntryService) switchAll(ctx context.Context, on bool) error {
	sw := dnsSwitch{known: true, enabled: on}
	now := s.now()
	var changes []dnsNameChange
	var refs []model.DNSReference
	rows := make(map[string]model.DNSEntryState)
	err := func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			changes = nil
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
			for _, name := range dnsSortedKeys(cur) {
				prev := cur[name]
				next, eff, touched := dnsSettle(prev, used[name] > 0, sw, now, 0)
				if touched {
					if err := tx.UpsertState(ctx, next); err != nil {
						return err
					}
					if dnsReportable(eff) {
						changes = append(changes, dnsNameChange{name, eff, next})
					}
				}
				rows[name] = next
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.syncFilesLocked(refs, rows, s.readDir(), nil)
		return nil
	}()
	if err != nil {
		return err
	}
	for _, c := range changes {
		s.events.nameChanged(ctx, c.name, c.eff, c.st)
	}
	return nil
}
