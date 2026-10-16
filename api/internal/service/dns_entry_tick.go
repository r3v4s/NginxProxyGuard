package service

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// dnsResolveWorkers is how many names a check resolves at once.
const dnsResolveWorkers = 4

// dnsTickResult is what one check leaves for the steps after it.
type dnsTickResult struct {
	refs   []model.DNSReference
	rows   map[string]model.DNSEntryState
	scopes map[string]int
	notes  map[string]dnsentry.ObserveNotes
	wrote  bool
	st     model.DNSEntrySettings
}

// Tick runs one check and returns how long the scheduler waits
// before the next: the interval (NPG_DNS_ENTRIES_INTERVAL first), shorter
// when a retry falls due sooner or while a reload's acceptance is still to
// be seen (nextDelay).
//  1. (no lock) read the references; resolve every used name, four at a
//     time, while the feature is on — names in review too, for display.
//  2. (dnsMu) the feature switch read again (the answers are dropped when
//     it changed), then one transaction: the references read again (a save
//     between 1 and 2 must not see its name marked unused), then every
//     name's transition, then every file compared with what the rows want.
//  3. (no lock) apply when something is not in nginx yet; alerts and events.
func (s *DNSEntryService) Tick(ctx context.Context) time.Duration {
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	if s.lastGC.IsZero() || s.now().Sub(s.lastGC) >= dnsGCInterval {
		s.collectGarbage(ctx)
		s.lastGC = s.now()
	}
	res, err := s.checkNames(ctx)
	if err != nil {
		s.logs.fail("tick", "[DNSEntries] WARN: the domain entry check failed; retrying at every interval: %v", err)
		return s.nextDelay(res.st)
	}
	s.logs.ok("tick")
	if !s.applyStep(ctx, res.wrote, res.rows) {
		// No apply ran, so no hook re-reads the rows: look at the alerts here
		// (an addition can pass 15 minutes while a retry waits).
		s.evaluateApplyAlerts(ctx, nil)
	}
	s.announceReviews(ctx, res.rows, res.scopes)
	s.refreshHostIndex(ctx, res.refs)
	s.refreshWarnings(ctx, res.refs, res.notes)
	return s.nextDelay(res.st)
}

// checkNames is steps 1 and 2 of a check.
func (s *DNSEntryService) checkNames(ctx context.Context) (dnsTickResult, error) {
	st, known := s.currentSettings(ctx)
	res := dnsTickResult{st: st}
	sw := dnsSwitch{known: known, enabled: st.Enabled}
	refs, err := s.states.ListReferences(ctx)
	if err != nil {
		return res, fmt.Errorf("list domain references: %w", err)
	}
	var names []string
	if st.Enabled {
		names = dnsNamesOf(nil, dnsUseCounts(refs))
	}
	rctx, cancel := dnsResolveContext(ctx)
	obs, notes := s.resolveAll(rctx, names, st, s.perLookup)
	cancel()
	res.notes = notes
	now := s.now()
	in := dnsentry.Input{Now: now, Settings: st, LastDNSReloadAt: s.lastReloadAt()}

	var changes []dnsNameChange
	var unused []string
	err = func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		if cur := s.currentSwitch(ctx); cur != sw {
			// The switch changed during the lookups. A settings save stores it,
			// then switches every name under dnsMu, so it is read again here: the
			// answers are dropped, and nothing looked up while the feature was on
			// publishes once "off" is stored.
			sw, obs, res.notes = cur, nil, nil
		}
		err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			changes, unused = nil, nil
			r, err := tx.ListReferences(ctx)
			if err != nil {
				return err
			}
			cur, err := tx.GetStates(ctx, nil)
			if err != nil {
				return err
			}
			res.refs = r
			res.scopes = dnsUseCounts(r)
			scopesOf := dnsScopesByName(r)
			dropped := s.droppedSegmentsLocked(scopesOf)
			res.rows = make(map[string]model.DNSEntryState, len(cur))
			for _, name := range dnsNamesOf(cur, res.scopes) {
				prev, exists := cur[name]
				if !exists {
					prev = dnsNewRow(tx, name, now, sw)
				}
				var o *dnsentry.Observation
				if v, ok := obs[name]; ok {
					o = &v
				}
				next, eff, touched := dnsTickTransition(prev, res.scopes[name] > 0, sw, o, in)
				if exists && next.Generation == prev.Generation && len(dnsDesired(next, res.scopes[name] > 0)) > 0 &&
					s.newSegmentLocked(scopesOf[name], name) {
					next.Generation++
					changed := now
					next.LastChangedAt = &changed
					touched = true
				}
				if held, ok := dropped[name]; ok {
					next = dnsRevokeDropped(next, held, now)
					touched = true
				}
				if !exists || touched {
					if err := tx.UpsertState(ctx, next); err != nil {
						return err
					}
				}
				res.rows[name] = next
				if touched && dnsReportable(eff) {
					changes = append(changes, dnsNameChange{name, eff, next})
				}
				if prev.UnusedSince == nil && next.UnusedSince != nil && next.Status == model.DNSStatusNeedsReview {
					unused = append(unused, name)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		res.wrote = s.syncFilesLocked(res.refs, res.rows, s.readDir(), nil)
		return nil
	}()
	if err != nil {
		return res, err
	}

	for _, c := range changes {
		s.events.nameChanged(ctx, c.name, c.eff, c.st)
	}
	for _, name := range unused {
		s.closeReview(ctx, name, false)
	}
	return res, nil
}

// currentSwitch reads the feature switch again.
func (s *DNSEntryService) currentSwitch(ctx context.Context) dnsSwitch {
	st, known := s.currentSettings(ctx)
	return dnsSwitch{known: known, enabled: st.Enabled}
}

// droppedSegmentsLocked returns, per name, the highest generation of the
// files this process holds with addresses for a scope that no longer uses
// the name. The check empties them, which is a revocation nginx has to
// take. Caller holds dnsMu.
func (s *DNSEntryService) droppedSegmentsLocked(scopesOf map[string][]string) map[string]int64 {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	out := make(map[string]int64)
	for _, e := range s.disk {
		if len(e.Addrs) == 0 || slices.Contains(scopesOf[e.Name], e.Scope) {
			continue
		}
		if g, ok := out[e.Name]; !ok || e.Gen > g {
			out[e.Name] = e.Gen
		}
	}
	return out
}

// dnsRevokeDropped records, as a save does, that files of scopes which
// dropped the name are emptied while they held addresses: a revocation that
// waits for a reload, alerted and retried like any other. The generation
// moves above held, the highest one those files were written with, so no
// reload that read them counts as having read the emptied ones.
func dnsRevokeDropped(st model.DNSEntryState, held int64, now time.Time) model.DNSEntryState {
	if st.Generation <= held {
		st.Generation = held + 1
		changed := now
		st.LastChangedAt = &changed
	}
	if st.RevokePendingSince == nil {
		since := now
		st.RevokePendingSince = &since
	}
	return st
}

// dnsTickTransition is one name's transition in a check. Used and on: the
// answer goes through Decide, or Reactivate when the name was unused (an
// operator re-added it). Without an answer, or unused, or off:
// only the transitions dnsSettle makes.
func dnsTickTransition(prev model.DNSEntryState, used bool, sw dnsSwitch, o *dnsentry.Observation, in dnsentry.Input) (model.DNSEntryState, dnsentry.Effects, bool) {
	if !used || o == nil {
		return dnsSettle(prev, used, sw, in.Now, 0)
	}
	// The switch first. An unused name is not reactivated there but below,
	// with the answer.
	next, eff, touched := dnsSettle(prev, prev.UnusedSince == nil, sw, in.Now, 0)
	if next.Disabled {
		return dnsSettle(prev, used, sw, in.Now, 0)
	}
	if prev.UnusedSince != nil {
		st, e := dnsentry.Reactivate(next, o, in.Now)
		return st, dnsMergeEffects(eff, e, !touched), true
	}
	st, e := dnsentry.Decide(next, *o, in)
	return st, dnsMergeEffects(eff, e, !touched), true
}

// dnsResolveContext bounds the lookups of a check to three quarters of the
// time ctx has left, so the transaction, the file writes and the apply keep
// the rest (30 s of the scheduler's 2 minutes). When DNS times out, a name
// takes up to 15 s (three lookups in a row) and four at a time fit about 32
// names in 2 minutes: without this, a larger set would leave no time for the
// transaction, no check would commit, and no name would reach the end of
// its grace. A name the budget cuts off gets a
// timeout, which never counts as a change.
func dnsResolveContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)*3/4)
}

// resolveAll resolves names, dnsResolveWorkers at a time, and puts every
// answer through the address policy. A name that did not finish (ctx ended)
// still gets an answer: a timeout, which never counts as a change.
func (s *DNSEntryService) resolveAll(ctx context.Context, names []string, st model.DNSEntrySettings, perLookup time.Duration) (map[string]dnsentry.Observation, map[string]dnsentry.ObserveNotes) {
	obs := make(map[string]dnsentry.Observation, len(names))
	notes := make(map[string]dnsentry.ObserveNotes, len(names))
	if len(names) == 0 {
		return obs, notes
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan string)
	for i := 0; i < dnsResolveWorkers && i < len(names); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range work {
				a := dnsentry.Resolve(ctx, s.lookuper, name, perLookup)
				o, n := dnsentry.Observe(a, s.policy, st.MaxAddressesPerFamily)
				mu.Lock()
				obs[name], notes[name] = o, n
				mu.Unlock()
			}
		}()
	}
	for _, name := range names {
		work <- name
	}
	close(work)
	wg.Wait()
	return obs, notes
}

// lastReloadAt is when the applier last signalled a reload, nil since start:
// the first apply after a restart needs no gap.
func (s *DNSEntryService) lastReloadAt() *time.Time {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	if s.lastReload.IsZero() {
		return nil
	}
	t := s.lastReload
	return &t
}

// nextDelay is the wait before the next check: NPG_DNS_ENTRIES_INTERVAL when
// set, else the configured interval; sooner when a retry falls due sooner;
// at most 15 seconds while a post-hoc check is open, so the check that sees
// nginx take the reload, or gives up on it, comes in time; never under a
// second. A retry time that has passed shortens nothing: the check that was
// to run it did not (a post-hoc check held it back, or the check failed),
// and asking again at once would only spin.
func (s *DNSEntryService) nextDelay(st model.DNSEntrySettings) time.Duration {
	d := s.envInterval
	if d <= 0 {
		d = st.CheckInterval()
	}
	now := s.now()
	s.diskMu.Lock()
	retryAt := s.applyView.retryAt
	open := len(s.postHocs) > 0
	s.diskMu.Unlock()
	if retryAt.After(now) && retryAt.Sub(now) < d {
		d = retryAt.Sub(now)
	}
	if open && d > dnsPostHocPoll {
		d = dnsPostHocPoll
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// Wake is the channel the scheduler waits on besides its timer.
func (s *DNSEntryService) Wake() <-chan struct{} { return s.wake }

// Kick asks for a check now, without waiting for it.
func (s *DNSEntryService) Kick() {
	select {
	case s.wake <- struct{}{}:
	default: // one is already queued
	}
}

// dnsSortedKeys returns a map's keys, sorted.
func dnsSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
