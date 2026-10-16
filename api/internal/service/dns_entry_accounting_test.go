package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// Reload accounting: what a reload token may claim and what MarkApplied may
// record when a file cannot be written, when a name's row is created again,
// and when alert evaluations overlap.

// dnsFailScopeNginx fails every write of one scope's files, as a disk that
// filled up between two writes does.
type dnsFailScopeNginx struct {
	*dnsTestNginx
	mu        sync.Mutex
	failScope string
}

func (n *dnsFailScopeNginx) WriteDNSIncludeFiles(scope, name string, gen int64, addrs []string) (bool, error) {
	n.mu.Lock()
	fail := scope == n.failScope
	n.mu.Unlock()
	if fail {
		return false, errors.New("no space left on device")
	}
	return n.dnsTestNginx.WriteDNSIncludeFiles(scope, name, gen, addrs)
}

func (n *dnsFailScopeNginx) setFailScope(scope string) {
	n.mu.Lock()
	n.failScope = scope
	n.mu.Unlock()
}

// The previous process committed a revocation (generation 6) and never wrote
// the files. At boot list B's file cannot be written while list A's can: a
// reload then still reads 203.0.113.10 in list B's file, so it must not
// record the revocation as applied, and dnsAllows must still see the
// address, until a later pass writes the file.
func TestDNSAFailedWriteKeepsTheNameUnapplied(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const name = "partner.example.com"
	a, b := dnsACL(dnsTestListA), dnsACL(dnsTestListB)
	r.store.setRefs(dnsRef(dnsTestListA, name), dnsRef(dnsTestListB, name))
	row := dnsOKRow(name, 6) // nothing published at generation 6
	row.AppliedGeneration = 5
	since := dnsTestStart
	row.RevokePendingSince = &since
	r.store.put(row)
	r.nginx.putFile(a, name, 5, "203.0.113.10")
	r.nginx.putFile(b, name, 5, "203.0.113.10")
	failing := &dnsFailScopeNginx{dnsTestNginx: r.nginx, failScope: b}
	r.svc.nginx = failing

	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.nginx.file(b, name); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("setup: list B file = %v, want it as it was", got)
	}
	hooks := r.svc.ReloadHooks()
	tok := hooks.Before().(*dnsReloadToken)
	if tok.gens[name] != 5 {
		t.Fatalf("token claims generation %d, want 5: list B's file still holds generation 5", tok.gens[name])
	}
	hooks.After(tok, nginx.ReloadAccepted, nil)
	r.settle()
	if st, _ := r.store.row(name); st.AppliedGeneration != 5 || st.RevokePendingSince == nil {
		t.Fatalf("row: applied %d, revoke pending %v; want 5 and the revocation still waiting", st.AppliedGeneration, st.RevokePendingSince)
	}
	if !r.svc.dnsAllows(b, "203.0.113.10") {
		t.Fatal("list B's file still holds 203.0.113.10, and dnsAllows does not see it")
	}
	if ev := r.events.snapshot(); len(ev.applies) != 1 || !dnsEqual(ev.applies[0].after, []string{"203.0.113.10"}) {
		t.Fatalf("applied events = %+v, want one showing nginx still running 203.0.113.10", ev.applies)
	}

	// The disk has room again: the next pass writes list B's file, and the
	// reload that reads it applies the revocation.
	failing.setFailScope("")
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.nginx.file(b, name); len(got) != 0 {
		t.Fatalf("list B file = %v after the retry, want it empty", got)
	}
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()
	if st, _ := r.store.row(name); st.AppliedGeneration != 6 || st.RevokePendingSince != nil {
		t.Fatalf("row: applied %d, revoke pending %v; want 6 and no revocation waiting", st.AppliedGeneration, st.RevokePendingSince)
	}
	if r.svc.dnsAllows(a, "203.0.113.10") || r.svc.dnsAllows(b, "203.0.113.10") {
		t.Fatal("nginx read both files without 203.0.113.10: nothing may still allow it")
	}
}

// A file a write could not replace is recorded as it is on disk: one
// without a header claims no generation, and a missing one claims none and
// allows nothing.
func TestDNSAFailedWriteRecordsTheFileAsItIs(t *testing.T) {
	const name = "partner.example.com"
	for _, tc := range []struct {
		desc    string
		file    *dnsTestFile // list B's file before the pass; nil = missing
		allowed bool
	}{
		{"a file without a header", &dnsTestFile{addrs: []string{"203.0.113.10"}}, true},
		{"a missing file", nil, false},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			r := newDNSTestRig(t)
			a, b := dnsACL(dnsTestListA), dnsACL(dnsTestListB)
			r.store.setRefs(dnsRef(dnsTestListA, name), dnsRef(dnsTestListB, name))
			r.store.put(dnsOKRow(name, 3, "198.51.100.7"))
			if tc.file != nil {
				f := *tc.file
				f.mod = r.clock.Now()
				r.nginx.files[nginx.DNSIncludeKey(b, name)+".allow"] = f
			}
			r.svc.nginx = &dnsFailScopeNginx{dnsTestNginx: r.nginx, failScope: b}

			if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			if tok := r.svc.beforeReload().(*dnsReloadToken); tok.gens[name] != 0 {
				t.Fatalf("token claims generation %d, want 0: list B's file never got generation 3", tok.gens[name])
			}
			if got := r.svc.dnsAllows(b, "203.0.113.10"); got != tc.allowed {
				t.Fatalf("dnsAllows(list B, 203.0.113.10) = %v, want %v", got, tc.allowed)
			}
			if !r.svc.dnsAllows(a, "198.51.100.7") {
				t.Fatal("list A's file was written: dnsAllows must see its address")
			}
		})
	}
}

// A name used again after the cleanup deleted its row gets a new row whose
// generation is low again. The reload that reads its file is still audited
// and recorded.
func TestDNSANameAddedAgainAfterTheCleanupIsAudited(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	hooks := r.svc.ReloadHooks()
	r.store.setRefs(dnsRef(dnsTestListA, name))
	r.store.put(dnsOKRow(name, 8, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()
	r.store.setRefs() // the name leaves its list
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()
	r.clock.Advance(8 * 24 * time.Hour)
	r.svc.collectGarbage(ctx)
	if _, ok := r.store.row(name); ok {
		t.Fatal("setup: the cleanup kept the row")
	}

	// Added again; the save published its first answer.
	r.store.setRefs(dnsRef(dnsTestListA, name))
	row := dnsOKRow(name, 1, "198.51.100.7")
	row.AppliedGeneration = 0
	fresh := r.clock.Now()
	row.V4.AnswerAt, row.LastCheckedAt, row.LastChangedAt = &fresh, &fresh, &fresh
	r.store.put(row)
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	before := len(r.events.snapshot().applies)
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()

	st, _ := r.store.row(name)
	ev := r.events.snapshot().applies[before:]
	if len(ev) != 1 || !dnsEqual(ev[0].after, []string{"198.51.100.7"}) || ev[0].gen != st.Generation {
		t.Fatalf("applied events = %+v, want one: nginx runs 198.51.100.7 at generation %d", ev, st.Generation)
	}
	if st.AppliedGeneration != st.Generation {
		t.Fatalf("row: generation %d, applied %d; want the reload recorded", st.Generation, st.AppliedGeneration)
	}
	if got, _ := r.nginx.file(a, name); !dnsEqual(got, []string{"198.51.100.7"}) {
		t.Fatalf("file = %v, want the new address", got)
	}
}

// The row of a name went while its file stayed on disk with generation 9 (a
// configuration still includes it). A reload signalled before the name came
// back lands after its new row exists: it read the old file, so it must not
// record the new row's generations as applied, now or at the next
// revocation.
func TestDNSAnOldFileNeverMarksANewRowApplied(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	hooks := r.svc.ReloadHooks()
	r.store.setRefs(dnsRef(dnsTestListA, name))
	r.store.put(dnsOKRow(name, 9, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	delete(r.store.rows, name) // the row goes; its file stays
	r.store.mu.Unlock()
	inFlight := hooks.Before() // reads generation 9: 203.0.113.10

	// Written by a path that does not know generation 9 (a save's first
	// publish, a restore): generation 1.
	fresh := r.clock.Now()
	row := dnsOKRow(name, 1, "198.51.100.7")
	row.AppliedGeneration = 0
	row.V4.AnswerAt, row.LastCheckedAt, row.LastChangedAt = &fresh, &fresh, &fresh
	r.store.put(row)
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	st, _ := r.store.row(name)
	if st.Generation <= 9 {
		t.Fatalf("new row at generation %d, want it raised above the old file's 9", st.Generation)
	}
	hooks.After(inFlight, nginx.ReloadAccepted, nil)
	r.settle()
	st, _ = r.store.row(name)
	if st.AppliedGeneration >= st.Generation {
		t.Fatalf("new row: generation %d, applied %d; a reload of the old file applied none of it", st.Generation, st.AppliedGeneration)
	}
	if !r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatal("nginx read the old file with 203.0.113.10: it may still allow it")
	}

	// The next revocation, written again by a path that does not know the
	// old generations, and a reload signalled before it that lands after it.
	older := hooks.Before()
	st.Published, st.Generation = nil, 2
	since := r.clock.Now()
	st.RevokePendingSince = &since
	r.store.put(st)
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	hooks.After(older, nginx.ReloadAccepted, nil)
	r.settle()
	st, _ = r.store.row(name)
	if st.AppliedGeneration > st.Generation {
		t.Fatalf("applied generation %d above generation %d", st.AppliedGeneration, st.Generation)
	}
	if st.RevokePendingSince == nil {
		t.Fatal("the revocation is recorded as applied by a reload that read the file before it")
	}
	if !r.svc.dnsAllows(a, "198.51.100.7") {
		t.Fatal("that reload read 198.51.100.7: nginx may still allow it")
	}
}

// A name whose row is gone while this process still holds its file gets a
// new row above that file's generation when a pass creates it.
func TestDNSARowCreatedAgainStartsAboveItsOldFile(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	r.store.setRefs(dnsRef(dnsTestListA, name))
	r.store.put(dnsOKRow(name, 9, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	delete(r.store.rows, name)
	r.store.mu.Unlock()
	hooks := r.svc.ReloadHooks()
	inFlight := hooks.Before() // reads generation 9: 203.0.113.10

	if err := r.svc.ReconcileFiles(ctx, false); err != nil { // a restore's pass
		t.Fatal(err)
	}
	st, ok := r.store.row(name)
	if !ok || st.Status != model.DNSStatusPending || st.Generation != 10 {
		t.Fatalf("new row = %+v (exists %v), want pending at generation 10", st, ok)
	}
	if got, _ := r.nginx.file(a, name); len(got) != 0 {
		t.Fatalf("file = %v, want it empty until the name answers", got)
	}
	hooks.After(inFlight, nginx.ReloadAccepted, nil)
	r.settle()
	if st, _ := r.store.row(name); st.AppliedGeneration >= st.Generation {
		t.Fatalf("generation %d, applied %d; a reload of the old file applied none of the new row", st.Generation, st.AppliedGeneration)
	}
	if !r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatal("nginx read the old file with 203.0.113.10: it may still allow it")
	}
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()
	if st, _ := r.store.row(name); st.AppliedGeneration != 10 || r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatalf("after a reload of the new file: applied %d, want 10 and 203.0.113.10 no longer allowed", st.AppliedGeneration)
	}
}

// Every transaction of the service keeps rows above the generations the
// process holds for their names: a row read below them is raised (and
// written so), and a row the transaction creates is written above them.
// Rows at or above them, and names nothing is held for, keep their
// generation.
func TestDNSTransactionsKeepRowsAboveHeldGenerations(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	a := dnsACL(dnsTestListA)
	r.svc.disk[dnsSegKey(a, "partner.example.com")] = dnsDiskEntry{Scope: a, Name: "partner.example.com", Gen: 9}
	r.svc.disk[dnsSegKey(a, "shop.example.com")] = dnsDiskEntry{Scope: a, Name: "shop.example.com", Gen: 4}
	r.svc.nginxView["office.example.com"] = dnsViewEntry{Gen: 7}
	r.store.put(model.DNSEntryState{Hostname: "partner.example.com", Status: model.DNSStatusOK, Generation: 2, AppliedGeneration: 2})
	r.store.put(model.DNSEntryState{Hostname: "shop.example.com", Status: model.DNSStatusOK, Generation: 4, AppliedGeneration: 4})
	r.store.put(model.DNSEntryState{Hostname: "other.example.com", Status: model.DNSStatusOK, Generation: 1, AppliedGeneration: 1})

	err := r.svc.RunExclusive(func() error {
		return r.svc.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			cur, err := tx.GetStates(ctx, nil)
			if err != nil {
				return err
			}
			if g := cur["partner.example.com"].Generation; g != 10 {
				t.Errorf("partner read at generation %d, want 10", g)
			}
			for _, n := range []string{"office.example.com", "new.example.com"} {
				if err := tx.UpsertState(ctx, dnsNewState(n, dnsTestStart, dnsSwitch{known: true, enabled: true})); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int64{"partner.example.com": 10, "shop.example.com": 4, "other.example.com": 1,
		"office.example.com": 8, "new.example.com": 0} {
		if st, _ := r.store.row(name); st.Generation != want {
			t.Errorf("%s: generation %d, want %d", name, st.Generation, want)
		}
	}
	if st, _ := r.store.row("partner.example.com"); st.AppliedGeneration != 2 {
		t.Errorf("partner: applied %d, want 2: a raise applies nothing", st.AppliedGeneration)
	}
}

// dnsSlowReadStore holds one read of every row: it reads the rows when
// called and answers only once released, as a slow database round trip does.
type dnsSlowReadStore struct {
	*dnsTestStore
	mu      sync.Mutex
	hold    bool
	read    chan struct{} // closed when the held read has read the rows
	release chan struct{}
	other   chan struct{} // a value for every other read of every row
}

func (s *dnsSlowReadStore) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	rows, err := s.dnsTestStore.GetStates(ctx, names)
	if names != nil {
		return rows, err
	}
	s.mu.Lock()
	hold := s.hold
	s.hold = false
	s.mu.Unlock()
	if hold {
		close(s.read)
		<-s.release
	} else {
		s.other <- struct{}{}
	}
	return rows, err
}

// Alert evaluations overlap: a reload hook's goroutine, the apply loop, a
// check. A slow read made before a revocation was written must never land
// after a read that sees it: the urgent revoke alert would close while the
// revocation is blocked.
func TestDNSApplyAlertsNeverApplyAStaleRead(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const name = "partner.example.com"
	since := dnsTestStart
	revoking := dnsOKRow(name, 2)
	revoking.AppliedGeneration = 1
	revoking.RevokePendingSince = &since
	r.store.put(revoking)
	blocked := nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_shop_example_com.conf"}
	r.svc.evaluateApplyAlerts(ctx, &blocked) // revoke failing

	slow := &dnsSlowReadStore{dnsTestStore: r.store, hold: true, read: make(chan struct{}),
		release: make(chan struct{}), other: make(chan struct{}, 4)}
	r.svc.states = slow

	// A reload took generation 2; its hook evaluates, and the database is slow.
	if err := r.store.MarkApplied(ctx, map[string]int64{name: 2}); err != nil {
		t.Fatal(err)
	}
	hookDone := make(chan struct{})
	go func() {
		defer close(hookDone)
		r.svc.evaluateApplyAlerts(ctx, nil)
	}()
	<-slow.read // it read the rows: no revocation waits

	// The next check revokes again, and the apply is blocked again.
	again := dnsOKRow(name, 3)
	again.AppliedGeneration = 2
	later := dnsTestStart.Add(time.Minute)
	again.RevokePendingSince = &later
	r.store.put(again)
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		r.svc.evaluateApplyAlerts(ctx, &blocked)
	}()
	select {
	case <-slow.other: // it read without waiting for the hook's evaluation
		<-applyDone
	case <-time.After(100 * time.Millisecond): // it waits for the hook's evaluation
	}
	close(slow.release)
	<-hookDone
	<-applyDone

	var last *dnsApplyAlert
	ev := r.events.snapshot()
	for i := range ev.alerts {
		if ev.alerts[i].Subject == "revoke" {
			last = &ev.alerts[i]
		}
	}
	if last == nil || !last.Failing {
		t.Fatalf("revoke alerts = %+v, want the last one failing: a revocation waits and its apply is blocked", ev.alerts)
	}
}
