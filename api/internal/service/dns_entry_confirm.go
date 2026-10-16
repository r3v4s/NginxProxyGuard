package service

import (
	"context"
	"errors"
	"log"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// References returns every use of name (the confirm route checks the
// caller's write permission on each).
func (s *DNSEntryService) References(ctx context.Context, name string) ([]model.DNSReference, error) {
	name = model.NormalizeDNSName(name)
	refs, err := s.states.ListReferences(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.DNSReference
	for _, r := range refs {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out, nil
}

// Confirm is an operator's "allow again" for a name in review.
// The server resolves the name again within SaveResolveTimeout and publishes
// only what it sees itself, and only when that is what the operator saw
// (expected, expectedCanonical). Otherwise dnsentry.Confirm answers
// ErrNotInReview or ErrLookupUnavailable, and nothing changes, or
// *ObservationChangedError: nothing is published then either, but the new
// answer is kept on the row the way a check keeps it for a name in review,
// so the dialog shows it when it reads the name again. A
// confirmed name is published at once and nginx reads it at once,
// outside the budget (an operator action). With the feature off the review
// is closed but the name stays switched off. The switch is read again under
// dnsMu: a settings save stores "off" before it switches the names off, and
// a confirm that comes in between counts as one made while the feature is
// off. The handler maps the errors and a rejected apply. The status is
// returned whole (the handler filters it); its observed_addresses and
// observed_canonical_name are what was confirmed, also while the feature is
// off and addresses is empty: the dns_entry_confirmed audit records them.
func (s *DNSEntryService) Confirm(ctx context.Context, name string, expected []string, expectedCanonical string) (model.DNSEntryStatus, nginx.DNSApplyResult, error) {
	name = model.NormalizeDNSName(name)
	if err := model.ValidateDNSName(name); err != nil {
		return model.DNSEntryStatus{}, nginx.DNSApplyResult{}, err
	}
	rows, err := s.states.GetStates(ctx, []string{name})
	if err != nil {
		return model.DNSEntryStatus{}, nginx.DNSApplyResult{}, err
	}
	if row, ok := rows[name]; !ok || row.Status != model.DNSStatusNeedsReview {
		return model.DNSEntryStatus{}, nginx.DNSApplyResult{}, dnsentry.ErrNotInReview
	}
	st, _ := s.currentSettings(ctx)
	rctx, cancel := context.WithTimeout(ctx, s.saveResolve)
	answer := dnsentry.Resolve(rctx, s.lookuper, name, min(s.perLookup, s.saveResolve))
	cancel()
	obs, _ := dnsentry.Observe(answer, s.policy, st.MaxAddressesPerFamily)
	expected = dnsCanonicalAddrs(expected)
	expectedCanonical = dnsentry.NormalizeCanonical(expectedCanonical)

	now := s.now()
	var next, confirmed model.DNSEntryState
	var eff dnsentry.Effects
	var refs []model.DNSReference
	var changed *dnsentry.ObservationChangedError
	err = func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		switchedOff := !st.Enabled
		if sw := s.currentSwitch(ctx); sw.known && !sw.enabled {
			switchedOff = true // stored during the lookup; the names are switched off next
		}
		err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			r, err := tx.ListReferences(ctx)
			if err != nil {
				return err
			}
			refs = r
			cur, err := tx.GetStates(ctx, []string{name})
			if err != nil {
				return err
			}
			prev, ok := cur[name]
			if !ok {
				return dnsentry.ErrNotInReview
			}
			n, e, err := dnsentry.Confirm(prev, obs, expected, expectedCanonical, now)
			if errors.As(err, &changed) {
				// The name answers what the operator did not see. The 409 goes
				// out; the new answer is kept as a check keeps it for a name in
				// review (families, canonical_seen, candidate; nothing
				// published), so the dialog shows it when it reads the name
				// again.
				seen, _ := dnsentry.Decide(prev, obs, dnsentry.Input{Now: now, Settings: st})
				return tx.UpsertState(ctx, seen)
			}
			if err != nil {
				return err
			}
			confirmed = n
			if switchedOff || n.Disabled {
				off, e2 := dnsentry.Disable(n, now)
				n, e = off, dnsMergeEffects(e, e2, false)
			}
			next, eff = n, e
			return tx.UpsertState(ctx, next)
		})
		if err == nil && changed != nil {
			err = changed
		}
		if err != nil {
			return err
		}
		s.syncFilesLocked(refs, map[string]model.DNSEntryState{name: next}, nil, map[string]bool{name: true})
		return nil
	}()
	if err != nil {
		return model.DNSEntryStatus{}, nginx.DNSApplyResult{}, err
	}

	s.closeReview(ctx, name, true)
	if dnsReportable(eff) {
		s.events.nameChanged(ctx, name, eff, next)
	}
	res := s.runApply(ctx)
	shown := next
	switch res.Outcome {
	case "accepted", "signalled", "skipped":
		// The reload hook records this in the background; answer with it.
		shown.AppliedGeneration, shown.RevokePendingSince = shown.Generation, nil
	}
	apply, lastReload := s.applySnapshot()
	status := dnsStatusOf(shown, st, apply, lastReload, s.now(), model.DNSStatusView{Banned: true, SelfIP: true, BlockingFile: true})
	status.ObservedAddresses = dnsSortedUnique(confirmed.Published)
	status.ObservedCanonicalName = dnsStringPtr(confirmed.CanonicalName)
	return status, res, nil
}

// ApplyNow is "apply now" (POST /dns-entries/apply): the files
// are put in line with the database first — no state transition — and nginx
// reads them at once, whatever the retry schedule says. It changes no trust.
func (s *DNSEntryService) ApplyNow(ctx context.Context) nginx.DNSApplyResult {
	s.repairFiles(ctx)
	return s.runApply(ctx)
}

// repairFiles rewrites every file that differs from what the rows want. The
// rows are read in a transaction, as a check reads them: a row below a
// generation the process still holds for its name (a restored row) is
// raised above it first, so no file is written with a generation an older
// file of the name carries.
func (s *DNSEntryService) repairFiles(ctx context.Context) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	var refs []model.DNSReference
	var rows map[string]model.DNSEntryState
	err := s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
		r, err := tx.ListReferences(ctx)
		if err != nil {
			return err
		}
		cur, err := tx.GetStates(ctx, nil)
		if err != nil {
			return err
		}
		refs, rows = r, cur
		return nil
	})
	if err != nil {
		log.Printf("[DNSEntries] WARN: apply now: could not read the domain entries: %v", err)
		return
	}
	s.syncFilesLocked(refs, rows, s.readDir(), nil)
}
