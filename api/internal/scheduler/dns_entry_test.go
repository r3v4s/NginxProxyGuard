package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeDNSEntryTicker hands every check's context to the test on ticks, then
// returns next. With block it first waits for that context to end; the first
// panics checks panic.
type fakeDNSEntryTicker struct {
	wake   chan struct{}
	ticks  chan context.Context
	next   time.Duration
	block  bool
	panics int

	mu    sync.Mutex
	calls int
}

func newFakeDNSEntryTicker() *fakeDNSEntryTicker {
	return &fakeDNSEntryTicker{wake: make(chan struct{}, 1), ticks: make(chan context.Context, 16), next: time.Hour}
}

func (f *fakeDNSEntryTicker) Tick(ctx context.Context) time.Duration {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	f.ticks <- ctx
	if n <= f.panics {
		panic("check failed")
	}
	if f.block {
		<-ctx.Done()
	}
	return f.next
}

func (f *fakeDNSEntryTicker) Wake() <-chan struct{} { return f.wake }

// startDNSEntryScheduler starts a scheduler whose first check comes after
// first and stops it when the test ends.
func startDNSEntryScheduler(t *testing.T, f *fakeDNSEntryTicker, first time.Duration) *DNSEntryScheduler {
	t.Helper()
	s := NewDNSEntryScheduler(f)
	s.firstDelay = first
	s.Start()
	t.Cleanup(s.Stop)
	return s
}

// nextDNSEntryCheck returns the context of the next check, failing after 5 s.
func nextDNSEntryCheck(t *testing.T, f *fakeDNSEntryTicker, what string) context.Context {
	t.Helper()
	select {
	case ctx := <-f.ticks:
		return ctx
	case <-time.After(5 * time.Second):
		t.Fatalf("no check: %s", what)
		return nil
	}
}

// noDNSEntryCheck fails when a check starts within d.
func noDNSEntryCheck(t *testing.T, f *fakeDNSEntryTicker, d time.Duration, what string) {
	t.Helper()
	select {
	case <-f.ticks:
		t.Fatalf("a check ran: %s", what)
	case <-time.After(d):
	}
}

// The first check comes after the first delay, under a deadline of its own;
// the next waits for the duration the check returned.
func TestDNSEntrySchedulerFirstCheckAfterTheDelay(t *testing.T) {
	f := newFakeDNSEntryTicker()
	start := time.Now()
	startDNSEntryScheduler(t, f, 80*time.Millisecond)

	ctx := nextDNSEntryCheck(t, f, "after the first delay")
	if waited := time.Since(start); waited < 80*time.Millisecond {
		t.Fatalf("first check after %v, want at least the 80ms first delay", waited)
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > dnsEntryTickTimeout || time.Until(deadline) < dnsEntryTickTimeout-time.Minute {
		t.Fatalf("check deadline in %v (set %v), want about %v", time.Until(deadline), ok, dnsEntryTickTimeout)
	}
	noDNSEntryCheck(t, f, 300*time.Millisecond, "the check asked for an hour's wait")
}

// A wake cuts the wait short: after a check, and during the first delay.
func TestDNSEntrySchedulerWakeRunsACheckAtOnce(t *testing.T) {
	f := newFakeDNSEntryTicker()
	startDNSEntryScheduler(t, f, 10*time.Millisecond)
	nextDNSEntryCheck(t, f, "the first check")
	f.wake <- struct{}{}
	nextDNSEntryCheck(t, f, "a wake during an hour's wait")

	f2 := newFakeDNSEntryTicker()
	f2.wake <- struct{}{}
	startDNSEntryScheduler(t, f2, time.Hour)
	nextDNSEntryCheck(t, f2, "a wake during the first delay")
}

// Stop cancels the check in progress and no check follows.
func TestDNSEntrySchedulerStopCancelsTheRunningCheck(t *testing.T) {
	f := newFakeDNSEntryTicker()
	f.block = true
	s := startDNSEntryScheduler(t, f, 10*time.Millisecond)
	ctx := nextDNSEntryCheck(t, f, "the first check")
	s.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the running check's context was not cancelled by Stop")
	}
	f.wake <- struct{}{}
	noDNSEntryCheck(t, f, 200*time.Millisecond, "after Stop")
}

// A check that panics does not end the loop.
func TestDNSEntrySchedulerSurvivesAPanic(t *testing.T) {
	f := newFakeDNSEntryTicker()
	f.panics = 1
	startDNSEntryScheduler(t, f, 10*time.Millisecond)
	nextDNSEntryCheck(t, f, "the check that panics")
	f.wake <- struct{}{}
	nextDNSEntryCheck(t, f, "the check after the panic")
}

func TestDNSEntryWaitIsBounded(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		-time.Second: time.Second, 0: time.Second, 500 * time.Millisecond: time.Second,
		30 * time.Second: 30 * time.Second, time.Hour: time.Hour, 2 * time.Hour: time.Hour,
	} {
		if got := dnsEntryWait(in); got != want {
			t.Errorf("dnsEntryWait(%v) = %v, want %v", in, got, want)
		}
	}
}
