package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

const (
	dnsPostHocMaxWait  = 10 * time.Minute // no new nginx child this long after the signal = failed
	dnsPostHocPoll     = 15 * time.Second // the longest wait between checks while a post-hoc check is open
	dnsNotUpAlertAfter = 15 * time.Minute // nginx not up this long counts for the alerts
	dnsMaxRetryDelay   = 10 * time.Minute // backoff 1, 2, 4, 8, then every 10 minutes
)

// applyStep is step 3 of a check: have nginx read the files when they
// changed, when the database says a generation is not in nginx yet, or when
// a retry is due. The reloads whose acceptance was not seen
// are checked first. While one may still be taken, an addition is
// not signalled again; a revocation that reload does not cover is
// signalled: it must not wait up to 10 minutes. A revocation written outside
// a check since the last one (revokeWritten) counts as a file this check
// changed: it gets one attempt now, whatever the retry schedule says and
// whichever older reload nginx is found to have taken, and a blocked attempt
// raises the revoke alert. A retry of the same failure still backs off.
// Returns whether an apply ran.
func (s *DNSEntryService) applyStep(ctx context.Context, wrote bool, rows map[string]model.DNSEntryState) bool {
	// Swapped first, whatever wrote is: the flag is this check's to consume.
	if s.revokeWritten.Swap(false) {
		wrote = true
	}
	now := s.now()
	force := false
	switch s.checkPostHoc(ctx, now) {
	case dnsPostHocTaken:
		// The rows were read before the hook marked them: only new files
		// need an apply now.
		if !wrote {
			return false
		}
	case dnsPostHocExpired:
		force = true // signalling again is allowed now
	case dnsPostHocOpen:
		if !s.revocationNotCovered() {
			return false
		}
		force = true // a new signal, with its own snapshot
	}
	if !wrote && !force {
		unapplied := false
		for _, st := range rows {
			if st.Generation > st.AppliedGeneration {
				unapplied = true
				break
			}
		}
		if !unapplied {
			// Nothing waits: a reload of another path took the files, so a
			// retry has nothing left to do.
			s.applyWorks(ctx)
			return false
		}
		retryAt := func() time.Time {
			s.diskMu.Lock()
			defer s.diskMu.Unlock()
			return s.applyView.retryAt
		}()
		if !retryAt.IsZero() && now.Before(retryAt) {
			return false
		}
	}
	s.runApply(ctx)
	return true
}

// dnsPostHocState is what checkPostHoc found.
type dnsPostHocState int

const (
	dnsPostHocNone    dnsPostHocState = iota // no reload waits for a check
	dnsPostHocTaken                          // nginx took them: every open one is closed
	dnsPostHocOpen                           // one nginx may still take is open
	dnsPostHocExpired                        // none was taken within 10 minutes: a failed apply
)

// checkPostHoc looks at the open post-hoc checks, newest first, and takes
// the first reload nginx took: tokenTaken closes the older ones with it (a
// later reload read at least their files). A check open for more than 10
// minutes is dropped; when that leaves none open, the apply counts as failed
// and may signal again.
func (s *DNSEntryService) checkPostHoc(ctx context.Context, now time.Time) dnsPostHocState {
	open := func() []*dnsPostHoc {
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		return append([]*dnsPostHoc(nil), s.postHocs...)
	}()
	if len(open) == 0 {
		return dnsPostHocNone
	}
	for i := len(open) - 1; i >= 0; i-- {
		if taken, err := s.nginx.ReloadTakenSince(ctx, open[i].snap); err == nil && taken {
			s.postHocTaken(ctx, open[i])
			open = open[i+1:]
			break
		}
	}
	if len(open) == 0 {
		return dnsPostHocTaken
	}
	waiting := false
	for _, ph := range open {
		if now.Sub(ph.since) > dnsPostHocMaxWait {
			s.dropPostHoc(ph)
		} else {
			waiting = true
		}
	}
	if waiting {
		return dnsPostHocOpen
	}
	s.recordPostHocFailure(ctx)
	return dnsPostHocExpired
}

// revocationNotCovered reports whether an address left a name's file in a
// generation newer than the one the newest open post-hoc token carries for
// the name, and the file on disk is that new. Taking that reload
// would not clear the revocation, so it does not wait for the check.
func (s *DNSEntryService) revocationNotCovered() bool {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	if len(s.postHocs) == 0 {
		return false
	}
	gens := s.postHocs[len(s.postHocs)-1].token.gens
	disk := make(map[string]int64)
	for _, e := range s.disk {
		if g, ok := disk[e.Name]; !ok || e.Gen < g {
			disk[e.Name] = e.Gen
		}
	}
	for _, pr := range s.pendingRevoke {
		if pr.Gen > gens[pr.Name] && disk[pr.Name] > gens[pr.Name] {
			return true
		}
	}
	return false
}

// postHocTaken takes the token of a checked reload that nginx did take,
// unless a later reload's hook took care of it meanwhile.
func (s *DNSEntryService) postHocTaken(ctx context.Context, ph *dnsPostHoc) {
	still := func() bool {
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		return slices.Contains(s.postHocs, ph)
	}()
	if still {
		s.tokenTaken(ph.token)
	}
	s.applyWorks(ctx)
}

// applyWorks ends a failing run when nginx took the files some other way,
// and forgets the run's backoff and any nginx outage with it: a retry left
// waiting by an unconfirmed reload has no retry time, but its failure count
// and the start of the outage must not carry over to the next one.
func (s *DNSEntryService) applyWorks(ctx context.Context) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.retry.failing && s.retry.retryAt.IsZero() && s.retry.failures == 0 && s.retry.notUpSince.IsZero() {
		return
	}
	s.recordSuccessLocked(ctx, nginx.DNSApplyResult{Outcome: "accepted"})
	s.publishApplyViewLocked()
}

// dropPostHoc forgets a checked reload nginx never took.
func (s *DNSEntryService) dropPostHoc(ph *dnsPostHoc) {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	s.postHocs = slices.DeleteFunc(s.postHocs, func(p *dnsPostHoc) bool { return p == ph })
}

// recordPostHocFailure counts a reload nginx never took as a failed apply.
func (s *DNSEntryService) recordPostHocFailure(ctx context.Context) {
	res := nginx.DNSApplyResult{Outcome: "failed", Detail: "nginx started no new worker process after the reload"}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.recordFailureLocked(ctx, res, s.now())
	s.publishApplyViewLocked()
	s.evaluateApplyAlerts(ctx, &res)
}

// runApply has nginx test and read the include files once
// (Manager.ApplyDNSIncludes) and keeps the retry state. A
// failure is retried after 1, 2, 4, 8, then every 10 minutes; it never
// rewrites a file. nginx not up yet is retried the same way
// but is never the urgent revoke alert: no nginx holds an old allow in
// memory, and it reads the current files when it starts. After 15 minutes
// it counts as a failing apply loop, and the apply alert follows from the
// rows. An apply cut short by a cancelled ctx (dnsApplyCutShort) records
// nothing.
func (s *DNSEntryService) runApply(ctx context.Context) nginx.DNSApplyResult {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	res := s.nginx.ApplyDNSIncludes(ctx)
	now := s.now()
	switch res.Outcome {
	case "accepted", "signalled", "unconfirmed", "rejected":
		func() {
			s.diskMu.Lock()
			defer s.diskMu.Unlock()
			s.lastReload = now
		}()
	}
	if dnsApplyCutShort(ctx, res) {
		// No failing loop, no ERROR row that nothing would close (the next
		// process starts with the loop working), no backoff, no alert: the
		// retry state stays as it was. The rows still say what nginx has not
		// taken, so a later check, or the next start, applies it.
		return res
	}
	var failure *nginx.DNSApplyResult
	switch res.Outcome {
	case "skipped":
		// NGINX_SKIP_TEST: nothing reloads nginx here, so what is on disk
		// counts as applied.
		s.tokenTaken(s.beforeReload().(*dnsReloadToken))
		s.recordSuccessLocked(ctx, res)
	case "accepted", "signalled":
		s.recordSuccessLocked(ctx, res)
	case "unconfirmed":
		if res.Snapshot == nil {
			s.recordSuccessLocked(ctx, res) // nothing to check it against: counts as applied
		} else {
			// The post-hoc check decides (applyStep): it ends the retry when
			// nginx took the reload, and signals again after 10 minutes when
			// it did not. A retry time left from an earlier failure would only
			// pass unused while the check is open.
			s.retry.retryAt = time.Time{}
		}
	case "not_up":
		if s.retry.notUpSince.IsZero() {
			s.retry.notUpSince = now
		}
		long := now.Sub(s.retry.notUpSince) >= dnsNotUpAlertAfter
		s.scheduleRetryLocked(now)
		if long {
			s.markFailingLocked(ctx, res)
		}
	default: // blocked, failed, rejected
		s.recordFailureLocked(ctx, res, now)
		failure = &res
	}
	s.publishApplyViewLocked()
	if failure != nil || res.Outcome == "not_up" {
		// No reload ran, so no hook looks at the alerts after this apply.
		s.evaluateApplyAlerts(ctx, failure)
	}
	return res
}

// dnsApplyCutShort reports whether an apply that did not go through was cut
// short by its caller: the scheduler's Stop cancelled the check it
// interrupted, or the request that asked for it went away. That says nothing about nginx, so it
// is no failure. A deadline that passed is one: the apply took too long.
func dnsApplyCutShort(ctx context.Context, res nginx.DNSApplyResult) bool {
	switch res.Outcome {
	case "accepted", "signalled", "unconfirmed", "skipped":
		return false
	}
	return errors.Is(ctx.Err(), context.Canceled)
}

// recordSuccessLocked resets the retry state. Caller holds applyMu.
func (s *DNSEntryService) recordSuccessLocked(ctx context.Context, res nginx.DNSApplyResult) {
	if s.retry.failing {
		s.events.applyFailing(ctx, false, res)
	}
	s.retry = dnsRetryState{}
}

// recordFailureLocked schedules the retry and marks the loop failing.
// Caller holds applyMu.
func (s *DNSEntryService) recordFailureLocked(ctx context.Context, res nginx.DNSApplyResult, now time.Time) {
	s.retry.notUpSince = time.Time{}
	s.scheduleRetryLocked(now)
	s.markFailingLocked(ctx, res)
}

// scheduleRetryLocked moves the backoff one step. Caller holds applyMu.
func (s *DNSEntryService) scheduleRetryLocked(now time.Time) {
	s.retry.failures++
	d := dnsMaxRetryDelay
	if s.retry.failures <= 4 {
		d = time.Minute << (s.retry.failures - 1)
	}
	s.retry.retryAt = now.Add(d)
}

// markFailingLocked remembers the failed result and reports the change from
// working to failing once. Caller holds applyMu.
func (s *DNSEntryService) markFailingLocked(ctx context.Context, res nginx.DNSApplyResult) {
	s.retry.last = res
	if !s.retry.failing {
		s.retry.failing = true
		s.events.applyFailing(ctx, true, res)
	}
}

// publishApplyViewLocked copies the retry state for readers. Caller holds
// applyMu.
func (s *DNSEntryService) publishApplyViewLocked() {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	s.applyView = dnsApplyView{failing: s.retry.failing, last: s.retry.last, retryAt: s.retry.retryAt}
}
