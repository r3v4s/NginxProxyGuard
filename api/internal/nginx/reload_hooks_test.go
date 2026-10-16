package nginx

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// afterCall is one ReloadHooks.After call.
type afterCall struct {
	token   any
	outcome ReloadOutcome
	snap    *ReloadSnapshot
	locked  bool // globalNginxMutex was held during the call
}

// recordingHooks hands out the tokens 1, 2, 3... from Before and records
// every call, and whether the nginx lock was held at each. events, when set,
// also gets "before" and "after:<outcome>" in call order.
type recordingHooks struct {
	mu         sync.Mutex
	tokens     int
	beforeHeld []bool
	afters     []afterCall
	events     *[]string
}

func (r *recordingHooks) hooks() ReloadHooks {
	return ReloadHooks{
		Before: func() any {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.tokens++
			r.beforeHeld = append(r.beforeHeld, globalLockHeld())
			if r.events != nil {
				*r.events = append(*r.events, "before")
			}
			return r.tokens
		},
		After: func(token any, outcome ReloadOutcome, snap *ReloadSnapshot) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.afters = append(r.afters, afterCall{token: token, outcome: outcome, snap: snap, locked: globalLockHeld()})
			if r.events != nil {
				*r.events = append(*r.events, "after:"+string(outcome))
			}
		},
	}
}

// only returns the one After call, and fails the test unless there was
// exactly one.
func (r *recordingHooks) only(t *testing.T) afterCall {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.afters) != 1 {
		t.Fatalf("After was called %d time(s) (%+v), want once", len(r.afters), r.afters)
	}
	return r.afters[0]
}

// hookedManager is newConfirmManager with recording hooks. probe nil turns
// confirmation off.
func hookedManager(cli nginxCLI, probe reloadProbe) (*Manager, *recordingHooks) {
	rec := &recordingHooks{}
	m := newConfirmManager(cli, probe)
	m.SetReloadHooks(rec.hooks())
	return m, rec
}

// orderProbe records each Children call in events.
type orderProbe struct {
	fakeReloadProbe
	events *[]string
}

func (p *orderProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	*p.events = append(*p.events, "children")
	return p.fakeReloadProbe.Children(ctx)
}

// orderCLI records each reload signal in events.
type orderCLI struct {
	fakeNginxCLI
	events *[]string
}

func (c *orderCLI) Reload(ctx context.Context) error {
	*c.events = append(*c.events, "signal")
	return c.fakeNginxCLI.Reload(ctx)
}

// The token comes before the process snapshot, and without confirmation
// before the signal: whatever it records is no newer than the files nginx
// reads when it takes the signal. A master that restarts after the token
// counts as accepted, and it read files the token already covers.
func TestReloadHooksTakeTheTokenBeforeTheSnapshot(t *testing.T) {
	var events []string
	probe := &orderProbe{fakeReloadProbe: fakeReloadProbe{procs: []fakeProcs{
		{master: 1, children: []int{10}},
		{master: 1, children: []int{10, 20}},
	}}, events: &events}
	cli := &orderCLI{events: &events}
	rec := &recordingHooks{events: &events}
	m := newConfirmManager(cli, probe)
	m.SetReloadHooks(rec.hooks())
	if err := m.ReloadNginx(context.Background()); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	if got, want := strings.Join(events, " "), "before children signal children after:accepted"; got != want {
		t.Fatalf("events = %q, want %q", got, want)
	}

	events = nil
	m = &Manager{cli: cli}
	m.SetReloadHooks(rec.hooks())
	if err := m.ReloadNginx(context.Background()); err != nil {
		t.Fatalf("ReloadNginx without confirmation: %v", err)
	}
	if got, want := strings.Join(events, " "), "before signal after:signalled"; got != want {
		t.Fatalf("without confirmation: events = %q, want %q", got, want)
	}
}

// A reload signalled inside the nginx lock: Before runs under the lock, and
// After gets Before's token and nginx's answer once the lock is released.
func TestReloadHooksHearAnAcceptedReloadAfterTheLock(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{
		{master: 1, children: []int{10}},
		{master: 1, children: []int{10, 20}},
	}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	outcome, err := m.executeWithLockOutcome(context.Background(), func() error {
		return m.reloadNginxInternal(context.Background())
	})
	if err != nil || outcome != ReloadAccepted {
		t.Fatalf("outcome, err = %q, %v; want accepted, nil", outcome, err)
	}
	if len(rec.beforeHeld) != 1 || !rec.beforeHeld[0] {
		t.Fatalf("Before ran %d time(s), under the lock: %v; want once, under it", len(rec.beforeHeld), rec.beforeHeld)
	}
	got := rec.only(t)
	if got.token != 1 || got.outcome != ReloadAccepted || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want After(1, accepted, nil)", got.token, got.outcome, got.snap)
	}
	if got.locked {
		t.Error("After ran under the nginx lock; an in-lock reload is answered after the lock is released")
	}
}

func TestReloadHooksHearARefusedReload(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}, emerg: []string{rejectedZoneKeyLine}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	if err := m.ReloadNginx(context.Background()); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("err = %v, want ErrReloadRejected", err)
	}
	if got := rec.only(t); got.token != 1 || got.outcome != ReloadRejected || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want After(1, rejected, nil)", got.token, got.outcome, got.snap)
	}
}

// Outside executeWithLock (only tests do that) the reload is confirmed where
// it is signalled, and After hears the answer there.
func TestReloadHooksHearARefusalOutsideTheLock(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}, emerg: []string{rejectedZoneKeyLine}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	outcome, err := m.reloadNginxOutcome(context.Background())
	if !errors.Is(err, ErrReloadRejected) || outcome != ReloadRejected {
		t.Fatalf("outcome, err = %q, %v; want rejected, ErrReloadRejected", outcome, err)
	}
	if got := rec.only(t); got.outcome != ReloadRejected || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want rejected with no snapshot", got.token, got.outcome, got.snap)
	}
}

// nginx neither took nor refused the reload within the wait. The save still
// reports it as applied and nothing is signalled again; After gets the
// snapshot, so the DNS service can ask later whether nginx has taken it
// since.
func TestReloadHooksHearAnUnconfirmedReloadWithItsSnapshot(t *testing.T) {
	ctx := context.Background()
	cli := &fakeNginxCLI{}
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 11}}}}
	m, rec := hookedManager(cli, probe)
	if err := m.ReloadNginx(ctx); err != nil {
		t.Fatalf("an unconfirmed reload must not fail the save: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1 (no second signal)", cli.reloadCalls)
	}
	got := rec.only(t)
	if got.outcome != ReloadUnconfirmed || got.snap == nil {
		t.Fatalf("After(%v, %q, %v), want unconfirmed with a snapshot", got.token, got.outcome, got.snap)
	}
	m.reloadProbe = &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 11}}}}
	if taken, err := m.ReloadTakenSince(ctx, got.snap); err != nil || taken {
		t.Errorf("the same workers: ReloadTakenSince = %v, %v; want false, nil", taken, err)
	}
	m.reloadProbe = &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 11, 30}}}}
	if taken, err := m.ReloadTakenSince(ctx, got.snap); err != nil || !taken {
		t.Errorf("a new worker: ReloadTakenSince = %v, %v; want true, nil", taken, err)
	}
}

func TestReloadHooksWithoutConfirmationHearASignal(t *testing.T) {
	cli := &fakeNginxCLI{}
	m, rec := hookedManager(cli, nil)
	if err := m.ReloadNginx(context.Background()); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	if cli.reloadCalls != 1 {
		t.Fatalf("reload signals = %d, want 1", cli.reloadCalls)
	}
	if got := rec.only(t); got.token != 1 || got.outcome != ReloadSignalled || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want After(1, signalled, nil)", got.token, got.outcome, got.snap)
	}
}

// nginx's processes could not be read before the signal: the reload is
// unconfirmed at once, with no snapshot to ask about later.
func TestReloadHooksHearAnUnconfirmedReloadWithoutASnapshot(t *testing.T) {
	ctx := context.Background()
	probe := &fakeReloadProbe{procs: []fakeProcs{{err: errors.New("docker exec: i/o timeout")}}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	var inner ReloadOutcome
	outcome, err := m.executeWithLockOutcome(ctx, func() error {
		o, err := m.reloadNginxOutcome(ctx)
		inner = o
		return err
	})
	if err != nil || outcome != "" || inner != ReloadUnconfirmed {
		t.Fatalf("outcome %q, inner %q, err %v; want \"\", unconfirmed, nil", outcome, inner, err)
	}
	if got := rec.only(t); got.outcome != ReloadUnconfirmed || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want unconfirmed with no snapshot", got.token, got.outcome, got.snap)
	}
}

// A signal that failed sent nothing: Before ran, After never does.
func TestReloadHooksSkipAFailedSignal(t *testing.T) {
	signalErr := errors.New(`nginx -s reload failed: exit status 1: nginx: [error] open() "/var/run/nginx.pid" failed (2: No such file or directory)`)
	probes := map[string]reloadProbe{
		"confirmation on":  &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}},
		"confirmation off": nil,
	}
	for name, probe := range probes {
		m, rec := hookedManager(&fakeNginxCLI{reloadErrs: []error{signalErr}}, probe)
		if err := m.ReloadNginx(context.Background()); err != signalErr {
			t.Fatalf("%s: err = %v, want the signal's error", name, err)
		}
		if len(rec.beforeHeld) != 1 || len(rec.afters) != 0 {
			t.Errorf("%s: Before ran %d time(s) and After %d, want 1 and 0", name, len(rec.beforeHeld), len(rec.afters))
		}
	}
}

// The operation failed after its signal (a failed health probe, a rollback):
// nobody waits for nginx's answer, and nginx is not read again for it
// (TestReloadOfAFailedOperationIsNotConfirmed). The hook hears "not checked",
// with the snapshot, outside the lock.
func TestReloadHooksHearANotCheckedReload(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	failed := errors.New("post-reload health probe failed: http probe: exit status 22")
	outcome, err := m.executeWithLockOutcome(context.Background(), func() error {
		if err := m.reloadNginxInternal(context.Background()); err != nil {
			return err
		}
		return failed
	})
	if err != failed || outcome != ReloadNotChecked {
		t.Fatalf("outcome, err = %q, %v; want not_checked and the operation's error", outcome, err)
	}
	got := rec.only(t)
	if got.outcome != ReloadNotChecked || got.snap == nil || got.locked {
		t.Errorf("After(%v, %q, %v), locked %v; want not_checked with a snapshot, outside the lock", got.token, got.outcome, got.snap, got.locked)
	}
	if probe.childCalls != 1 || probe.emergCalls != 0 {
		t.Errorf("nginx was read %d time(s) and its log %d time(s), want only the snapshot", probe.childCalls, probe.emergCalls)
	}
}

// Two reloads in one operation (a reload, then a rollback reload): the first
// is superseded before anyone confirms it, and the second carries the
// answer.
func TestReloadHooksHearASupersededReload(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{
		{master: 1, children: []int{10}}, // before the first signal
		{master: 1, children: []int{10}}, // before the second
		{master: 1, children: []int{10, 20}},
	}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	outcome, err := m.executeWithLockOutcome(context.Background(), func() error {
		if err := m.reloadNginxInternal(context.Background()); err != nil {
			return err
		}
		return m.reloadNginxInternal(context.Background())
	})
	if err != nil || outcome != ReloadAccepted {
		t.Fatalf("outcome, err = %q, %v; want accepted, nil", outcome, err)
	}
	if len(rec.afters) != 2 {
		t.Fatalf("After was called %d time(s) (%+v), want twice", len(rec.afters), rec.afters)
	}
	if first := rec.afters[0]; first.token != 1 || first.outcome != ReloadSuperseded || first.snap != nil {
		t.Errorf("first After(%v, %q, %v), want After(1, superseded, nil)", first.token, first.outcome, first.snap)
	}
	if second := rec.afters[1]; second.token != 2 || second.outcome != ReloadAccepted {
		t.Errorf("second After(%v, %q, _), want After(2, accepted, _)", second.token, second.outcome)
	}
}

// freshWorkerProbe shows a new worker at every read, so nginx takes every
// reload.
type freshWorkerProbe struct{ reads int }

func (p *freshWorkerProbe) Children(context.Context) (int, map[int]bool, error) {
	p.reads++
	return 1, map[int]bool{100 + p.reads: true}, nil
}

func (p *freshWorkerProbe) EmergSince(context.Context, time.Time) ([]string, error) { return nil, nil }

// Saves, bulk regeneration, SyncAll, the debounced reloader and DeferredSteps
// all reach nginx through reloadNginxInternal, so the hooks hear each of
// them: a save's own reload marks the DNS files applied,
// and the next DNS tick does not reload again.
func TestReloadHooksHearEveryReloadPath(t *testing.T) {
	ctx := context.Background()
	m := NewManager(t.TempDir(), t.TempDir())
	m.modsecPath = t.TempDir()
	m.skipTest = false
	m.cli = &fakeNginxCLI{}
	m.reloadProbe = &freshWorkerProbe{}
	m.reloadConfirmWait = 60 * time.Millisecond
	m.reloadConfirmEvery = 2 * time.Millisecond
	rec := &recordingHooks{}
	m.SetReloadHooks(rec.hooks())

	paths := []struct {
		name string
		run  func() error
	}{
		{"host save", func() error { return m.GenerateConfigAndReload(ctx, fixtureHTTPOnly(), nil) }},
		{"bulk regeneration", func() error {
			return m.RegenerateConfigsAtomic(ctx, []HostConfigRender{{Data: fixtureHTTPOnly()}}, true)
		}},
		{"SyncAll (ReloadNginx)", func() error { return m.ReloadNginx(ctx) }},
		{"debounced reloader and DeferredSteps (TestAndReload)", func() error { return m.TestAndReload(ctx) }},
	}
	for i, p := range paths {
		if err := p.run(); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		if len(rec.afters) != i+1 {
			t.Fatalf("%s: After was called %d time(s) in all, want %d", p.name, len(rec.afters), i+1)
		}
		if got := rec.afters[i]; got.token != i+1 || got.outcome != ReloadAccepted {
			t.Errorf("%s: After(%v, %q), want After(%d, accepted)", p.name, got.token, got.outcome, i+1)
		}
	}
}

// A panic inside the lock leaves no reload behind
// (TestPanicInsideTheLockReleasesIt); its hook hears "superseded".
func TestReloadHooksHearAPanickedOperationsReloadAsSuperseded(t *testing.T) {
	probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}}
	m, rec := hookedManager(&fakeNginxCLI{}, probe)
	func() {
		defer func() { _ = recover() }()
		_ = m.executeWithLock(context.Background(), func() error {
			_ = m.reloadNginxInternal(context.Background())
			panic("render failed")
		})
	}()
	if got := rec.only(t); got.token != 1 || got.outcome != ReloadSuperseded || got.snap != nil {
		t.Errorf("After(%v, %q, %v), want After(1, superseded, nil)", got.token, got.outcome, got.snap)
	}
}

// NGINX_SKIP_TEST=true sends no signal, so the hooks hear nothing.
func TestReloadHooksHearNothingWhenNginxIsSkipped(t *testing.T) {
	ctx := context.Background()
	cli := &fakeNginxCLI{}
	m, rec := hookedManager(cli, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}})
	m.skipTest = true
	outcome, err := m.executeWithLockOutcome(ctx, func() error { return m.testAndReloadNginx(ctx) })
	if err != nil || outcome != "" {
		t.Fatalf("outcome, err = %q, %v; want \"\", nil", outcome, err)
	}
	if cli.reloadCalls != 0 || len(rec.beforeHeld) != 0 || len(rec.afters) != 0 {
		t.Errorf("signals %d, Before %d, After %d; want none", cli.reloadCalls, len(rec.beforeHeld), len(rec.afters))
	}
}

// Hooks are optional, together or one at a time.
func TestReloadHooksAreOptional(t *testing.T) {
	hooks := map[string]ReloadHooks{
		"none":        {},
		"before only": {Before: func() any { return 1 }},
		"after only":  {After: func(any, ReloadOutcome, *ReloadSnapshot) {}},
	}
	for name, h := range hooks {
		probe := &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}, {master: 1, children: []int{10, 20}}}}
		m := newConfirmManager(&fakeNginxCLI{}, probe)
		m.SetReloadHooks(h)
		if err := m.ReloadNginx(context.Background()); err != nil {
			t.Errorf("%s: ReloadNginx: %v", name, err)
		}
	}
}

// executeWithLock answers as before: an unconfirmed reload is no error.
// executeWithLockOutcome has nothing to report when fn left no reload to
// confirm.
func TestExecuteWithLockOutcomeKeepsExecuteWithLocksAnswers(t *testing.T) {
	ctx := context.Background()
	m := newConfirmManager(&fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}})
	if err := m.executeWithLock(ctx, func() error { return m.reloadNginxInternal(ctx) }); err != nil {
		t.Errorf("an unconfirmed reload: executeWithLock = %v, want nil", err)
	}
	if outcome, err := m.executeWithLockOutcome(ctx, func() error { return nil }); outcome != "" || err != nil {
		t.Errorf("nothing signalled: %q, %v; want \"\", nil", outcome, err)
	}
	opErr := errors.New("render failed")
	if outcome, err := m.executeWithLockOutcome(ctx, func() error { return opErr }); outcome != "" || err != opErr {
		t.Errorf("failed before signalling: %q, %v; want \"\" and the operation's error", outcome, err)
	}
}

func TestReloadTakenSince(t *testing.T) {
	ctx := context.Background()
	snap := &ReloadSnapshot{before: reloadSnapshot{master: 1, children: map[int]bool{10: true, 11: true}}}
	cases := []struct {
		name  string
		now   fakeProcs
		taken bool
		fails bool
	}{
		{"the same workers", fakeProcs{master: 1, children: []int{10, 11}}, false, false},
		{"fewer workers", fakeProcs{master: 1, children: []int{10}}, false, false},
		{"a new worker", fakeProcs{master: 1, children: []int{10, 11, 20}}, true, false},
		{"only new workers", fakeProcs{master: 1, children: []int{20, 21}}, true, false},
		{"a new master", fakeProcs{master: 7, children: []int{30}}, true, false},
		{"processes unreadable", fakeProcs{err: errors.New("docker exec: i/o timeout")}, false, true},
	}
	for _, c := range cases {
		probe := &fakeReloadProbe{procs: []fakeProcs{c.now}}
		m := newConfirmManager(&fakeNginxCLI{}, probe)
		taken, err := m.ReloadTakenSince(ctx, snap)
		if taken != c.taken || (err != nil) != c.fails {
			t.Errorf("%s: ReloadTakenSince = %v, %v; want %v, error %v", c.name, taken, err, c.taken, c.fails)
		}
		if probe.childCalls != 1 || probe.emergCalls != 0 {
			t.Errorf("%s: nginx was read %d time(s) and its log %d time(s), want one process read", c.name, probe.childCalls, probe.emergCalls)
		}
	}
	m := newConfirmManager(&fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}})
	if _, err := m.ReloadTakenSince(ctx, nil); err == nil {
		t.Error("no snapshot: want an error")
	}
	if _, err := (&Manager{cli: &fakeNginxCLI{}}).ReloadTakenSince(ctx, snap); err == nil {
		t.Error("confirmation off: nothing can be read, want an error")
	}
}

// The DNS service asks between its ticks, while saves hold the nginx lock.
func TestReloadTakenSinceDoesNotWaitForTheNginxLock(t *testing.T) {
	m := newConfirmManager(&fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 20}}}})
	snap := &ReloadSnapshot{before: reloadSnapshot{master: 1, children: map[int]bool{10: true}}}
	globalNginxMutex.Lock()
	defer globalNginxMutex.Unlock()
	done := make(chan bool, 1)
	go func() {
		taken, _ := m.ReloadTakenSince(context.Background(), snap)
		done <- taken
	}()
	select {
	case taken := <-done:
		if !taken {
			t.Error("ReloadTakenSince = false, want true (a new worker)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReloadTakenSince waited for the nginx lock")
	}
}
