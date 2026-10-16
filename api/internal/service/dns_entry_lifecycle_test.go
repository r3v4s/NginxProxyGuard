package service

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// dnsPanickingStore panics, once armed, inside the next transaction's
// callback: where a bug in a transition would, with dnsMu held.
type dnsPanickingStore struct {
	*dnsTestStore
	armed atomic.Bool
}

func (p *dnsPanickingStore) WithTx(ctx context.Context, fn func(tx repository.DNSEntryTx) error) error {
	return p.dnsTestStore.WithTx(ctx, func(tx repository.DNSEntryTx) error {
		if p.armed.CompareAndSwap(true, false) {
			panic("injected: a transition panicked")
		}
		return fn(tx)
	})
}

// dnsPanics runs fn and reports whether it panicked, recovering the panic
// as the scheduler does.
func dnsPanics(fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	fn()
	return false
}

// dnsReturns fails the test when fn has not returned within five seconds, as
// when a lock it needs is never released.
func dnsReturns(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return: the panic left a lock held", what)
	}
}

// dnsPanickingClock is the test clock, except that its first read once
// armed panics.
type dnsPanickingClock struct {
	*dnsTestClock
	armed atomic.Bool
}

func (c *dnsPanickingClock) Now() time.Time {
	if c.armed.CompareAndSwap(true, false) {
		panic("injected: a clock read panicked")
	}
	return c.dnsTestClock.Now()
}

// A panic inside a section that holds diskMu on a check's goroutine (here the
// reload hook that keeps an unconfirmed reload for its post-hoc check reads
// the clock under it) reaches the scheduler, which recovers it. diskMu is
// released on the way out: the reload hooks take it inside nginx's global
// lock, so a diskMu left held would stop the next reload and every nginx
// operation waiting behind it.
func TestDNSPanicInsideTheDiskLockLeavesReloadsUsable(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	ctx := context.Background()
	r.settle()
	clock := &dnsPanickingClock{dnsTestClock: r.clock}
	r.svc.now = clock.Now
	r.lookup.set("partner.example.com", "127.0.0.1") // refused: the check revokes and applies at once
	hooks := r.svc.ReloadHooks()
	r.nginx.mu.Lock()
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "unconfirmed", Snapshot: &nginx.ReloadSnapshot{}}}
	r.nginx.hooks = &nginx.ReloadHooks{Before: hooks.Before,
		After: func(tok any, outcome nginx.ReloadOutcome, snap *nginx.ReloadSnapshot) {
			clock.armed.Store(true) // the hook's first clock read is the one under diskMu
			hooks.After(tok, outcome, snap)
		}}
	r.nginx.mu.Unlock()

	if !dnsPanics(func() { r.svc.Tick(ctx) }) {
		t.Fatal("the injected panic did not reach the caller")
	}
	dnsReturns(t, "the next reload's Before hook", func() { hooks.Before() })
	r.nginx.mu.Lock()
	r.nginx.hooks = &hooks
	r.nginx.mu.Unlock()
	dnsReturns(t, "the next check", func() { r.svc.Tick(ctx) })
	r.settle()
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("partner file = %v, want the refused address revoked", got)
	}
}

// A panic inside a section that holds dnsMu (a bug in a transition, a driver
// that panics) reaches the caller, which recovers it: the scheduler for a
// check, the HTTP server for a request. The lock is released on the way out,
// so the next check and the next save run instead of waiting for it forever.
func TestDNSPanicInsideTheLockLeavesTheServiceUsable(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		setup func(r *dnsTestRig)
		run   func(r *dnsTestRig)
	}{
		{name: "check", run: func(r *dnsTestRig) { r.svc.Tick(ctx) }},
		{name: "save", run: func(r *dnsTestRig) {
			_ = r.svc.SyncScope(ctx, dnsACL(dnsTestListA), []string{"partner.example.com"})
		}},
		{name: "switch", run: func(r *dnsTestRig) { _ = r.svc.switchAll(ctx, false) }},
		{name: "reconcile", run: func(r *dnsTestRig) { _ = r.svc.ReconcileFiles(ctx, true) }},
		{name: "cleanup", setup: func(r *dnsTestRig) {
			eightDays := r.clock.Now().Add(-8 * 24 * time.Hour)
			r.store.put(model.DNSEntryState{Hostname: "old.example.com", Status: model.DNSStatusOK, UnusedSince: &eightDays})
		}, run: func(r *dnsTestRig) { r.svc.collectGarbage(ctx) }},
		{name: "confirm", setup: func(r *dnsTestRig) {
			r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "review.example.com"))
			review := dnsOKRow("review.example.com", 2)
			review.Status, review.ReviewReason = model.DNSStatusNeedsReview, model.DNSReviewCNAMEChanged
			review.LastApplied, review.Candidate = []string{"203.0.113.30"}, []string{"203.0.113.31"}
			r.store.put(review)
			r.lookup.set("review.example.com", "203.0.113.31")
		}, run: func(r *dnsTestRig) {
			_, _, _ = r.svc.Confirm(ctx, "review.example.com", []string{"203.0.113.31"}, "")
		}},
		{name: "warnings", setup: func(r *dnsTestRig) {
			row, _ := r.store.row("partner.example.com")
			row.Warnings = []string{model.DNSWarnDuplicate} // no other name publishes its address
			r.store.put(row)
		}, run: func(r *dnsTestRig) { r.svc.refreshWarnings(ctx, r.mustRefs(), nil) }},
		{name: "apply now", run: func(r *dnsTestRig) { r.svc.ApplyNow(ctx) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := dnsPartnerRig(t, "203.0.113.10")
			if c.setup != nil {
				c.setup(r)
			}
			r.settle()
			ps := &dnsPanickingStore{dnsTestStore: r.store}
			r.svc.states = &dnsFloorStore{dnsStateStore: ps, svc: r.svc}

			ps.armed.Store(true)
			if !dnsPanics(func() { c.run(r) }) {
				t.Fatal("the injected panic did not reach the caller")
			}
			dnsReturns(t, "the next check", func() { r.svc.Tick(ctx) })
			dnsReturns(t, "the next save", func() {
				if err := r.svc.SyncScope(ctx, dnsACL(dnsTestListA), []string{"partner.example.com"}); err != nil {
					t.Errorf("the next save: %v", err)
				}
			})
			r.settle()
			if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
				t.Fatalf("partner file = %v after the next check, want its address still published", got)
			}
		})
	}
}

// dnsRevokingRig is partner.example.com with a revocation waiting for nginx,
// and the service's own event reporter writing to logs: a failed apply opens
// the revoke alert and logs the apply loop failing, both at ERROR.
func dnsRevokingRig(t *testing.T) (*dnsTestRig, *evtSystemLog) {
	t.Helper()
	r := dnsPartnerRig(t, "203.0.113.10")
	row, _ := r.store.row("partner.example.com")
	since := r.clock.Now()
	row.Generation, row.RevokePendingSince = 2, &since
	r.store.put(row)
	logs := &evtSystemLog{}
	r.svc.syslog = logs
	r.svc.events = &dnsEventReporter{svc: r.svc}
	return r, logs
}

func dnsRetryOf(r *dnsTestRig) dnsRetryState {
	r.svc.applyMu.Lock()
	defer r.svc.applyMu.Unlock()
	return r.svc.retry
}

// Stop cancels the check it interrupts, and an operator's request is
// cancelled when its client goes away. An apply cut short that way did not
// fail: the apply loop is not marked failing, no ERROR row is written that
// nothing would close (the next process starts with the loop working), and
// the retry state stays as it was. A deadline that passed is a failure: the
// apply took too long.
func TestDNSAnApplyCutShortIsNoFailure(t *testing.T) {
	for _, outcome := range []string{"failed", "blocked", "rejected", "not_up"} {
		t.Run("cancelled/"+outcome, func(t *testing.T) {
			r, logs := dnsRevokingRig(t)
			r.nginx.results = []nginx.DNSApplyResult{{Outcome: outcome}}
			// Two failures counted already, and nginx not up for 20 minutes:
			// one more failure, or not_up, would mark the loop failing.
			r.svc.applyMu.Lock()
			r.svc.retry = dnsRetryState{failures: 2, retryAt: r.clock.Now().Add(-time.Second),
				notUpSince: r.clock.Now().Add(-20 * time.Minute)}
			before := r.svc.retry
			r.svc.applyMu.Unlock()

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r.svc.runApply(ctx)
			r.settle()

			if got := dnsRetryOf(r); got != before {
				t.Errorf("retry state = %+v, want it unchanged %+v", got, before)
			}
			if len(logs.rows) != 0 {
				t.Errorf("system log rows = %+v, want none for an apply cut short", logs.rows)
			}
		})
	}

	t.Run("deadline", func(t *testing.T) {
		r, logs := dnsRevokingRig(t)
		r.nginx.results = []nginx.DNSApplyResult{{Outcome: "failed"}}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		r.svc.runApply(ctx)
		r.settle()

		if rs := dnsRetryOf(r); !rs.failing || rs.failures != 1 || !rs.retryAt.Equal(r.clock.Now().Add(time.Minute)) {
			t.Errorf("retry state = %+v, want the loop failing and the 1 minute retry", rs)
		}
		failing := false
		for _, row := range logs.rows {
			failing = failing || (row.Level == repository.LevelError && strings.HasPrefix(row.Message, "domain entry changes could not be applied"))
		}
		if !failing {
			t.Errorf("system log rows = %+v, want the apply loop logged failing at ERROR", logs.rows)
		}
	})
}

// At boot a reload can come before ReconcileFiles: the raw log settings are
// applied while startup runs. The rows are still as the last process left
// them then. Here an addition waited across the restart, more than 15
// minutes: looking at the alerts then would open apply_failed for the time
// until startup's own reload, which takes the addition. So the reload hooks
// look at no alert until ReconcileFiles has run; after it, they look at
// the alerts as before.
func TestDNSReloadHooksLookAtTheAlertsOnlyAfterReconcileFiles(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	row := dnsOKRow("partner.example.com", 2, "203.0.113.11")
	row.AppliedGeneration = 1 // the last process added 203.0.113.11, and nginx did not take it
	changed := dnsTestStart.Add(-20 * time.Minute)
	row.LastChangedAt = &changed
	r.store.put(row)
	hooks := r.svc.ReloadHooks()

	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // the raw log settings' reload
	r.settle()
	if ev := r.events.snapshot(); len(ev.alerts) != 0 {
		t.Fatalf("alerts = %+v after a reload before ReconcileFiles, want none looked at", ev.alerts)
	}

	if err := r.svc.ReconcileFiles(ctx, true); err != nil {
		t.Fatal(err)
	}
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // startup's reload reads the files
	r.settle()
	if st, _ := r.store.row("partner.example.com"); st.AppliedGeneration != st.Generation {
		t.Fatalf("row = %+v, want the addition applied by startup's reload", st)
	}
	ev := r.events.snapshot()
	if len(ev.alerts) == 0 {
		t.Fatal("no alert was looked at after ReconcileFiles: a reload's hook looks at them as before")
	}
	for _, a := range ev.alerts {
		if a.Failing {
			t.Fatalf("alerts = %+v, want none failing: nginx took the addition with startup's reload", ev.alerts)
		}
	}
}
