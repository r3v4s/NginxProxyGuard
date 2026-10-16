package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// dnsTick runs one check and waits for the work the hooks handed off.
func (r *dnsTestRig) tick(t *testing.T) time.Duration {
	t.Helper()
	d := r.svc.Tick(context.Background())
	r.settle()
	return d
}

// dnsPartnerRig is a rig with partner.example.com in list A, published and
// applied, and its file written.
func dnsPartnerRig(t *testing.T, addrs ...string) *dnsTestRig {
	t.Helper()
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, addrs...))
	r.lookup.set("partner.example.com", addrs...)
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.svc.lastGC = r.clock.Now() // the GC has its own test
	return r
}

func (r *dnsTestRig) partnerFile(t *testing.T) []string {
	t.Helper()
	got, ok := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com")
	if !ok {
		t.Fatal("the partner file does not exist")
	}
	return got
}

func TestDNSTickPublishesAPendingNameAtItsFirstAnswer(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.lookup.set("partner.example.com", "203.0.113.10")

	r.tick(t)

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("file = %v, want the first answer published at once", got)
	}
	st, _ := r.store.row("partner.example.com")
	if st.Status != model.DNSStatusOK || st.CanonicalName != "partner.example.com" || st.AppliedGeneration != st.Generation {
		t.Fatalf("row = %+v, want ok, the CNAME target pinned and the generation applied", st)
	}
	if r.nginx.applyCount() != 1 {
		t.Fatalf("applies = %d, want 1", r.nginx.applyCount())
	}
}

func TestDNSTickKeepsAFamilyThroughATimeoutAndStoresCodesOnly(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10", "2001:db8::10")
	r.lookup.mu.Lock()
	r.lookup.err6["partner.example.com"] = &net.DNSError{Err: "i/o timeout", Name: "partner.example.com.", Server: "192.0.2.53:53", IsTimeout: true}
	r.lookup.mu.Unlock()

	r.tick(t)

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10", "2001:db8::10"}) {
		t.Fatalf("file = %v, want both addresses kept: a timeout is not a change", got)
	}
	if r.nginx.applyCount() != 0 {
		t.Fatalf("applies = %d, want none: nothing changed", r.nginx.applyCount())
	}
	st, _ := r.store.row("partner.example.com")
	if st.Status != model.DNSStatusStale || st.V6.Code != "timeout" {
		t.Fatalf("row status %q, v6 code %q; want stale and the code timeout", st.Status, st.V6.Code)
	}
	for _, code := range []string{st.V4.Code, st.V6.Code} {
		if strings.Contains(code, ":") || strings.Contains(code, "192.0.2.53") {
			t.Fatalf("stored code %q carries the resolver address", code)
		}
	}
}

func TestDNSTickReplacementRevokesAtOnceAndAddsAfterTheGap(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.lookup.set("partner.example.com", "203.0.113.20")

	r.tick(t)
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("after the first answer the file = %v, want the old address out at once", got)
	}
	if r.nginx.applyCount() != 1 {
		t.Fatalf("applies = %d, want the revocation applied in the same check", r.nginx.applyCount())
	}

	r.clock.Advance(time.Minute)
	r.tick(t)
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("one minute after the revocation the file = %v, want the new address held for the gap", got)
	}

	r.clock.Advance(5 * time.Minute)
	r.tick(t)
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.20"}) {
		t.Fatalf("after the gap the file = %v, want the new address", got)
	}
	st, _ := r.store.row("partner.example.com")
	if len(st.ChangeTimes) != 1 {
		t.Fatalf("change_times = %v, want the replacement counted once", st.ChangeTimes)
	}
}

func TestDNSTickNeverMarksUnusedANameASaveJustAdded(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	// The check reads no reference, then a save commits one before the
	// check's transaction.
	r.store.beforeTx = func(f *dnsTestStore) {
		f.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	}

	r.tick(t)

	st, _ := r.store.row("partner.example.com")
	if st.UnusedSince != nil || !dnsEqual(st.Published, []string{"203.0.113.10"}) {
		t.Fatalf("row = %+v, want it still used and published", st)
	}
}

func TestDNSTickDoesNotReloadWhatASaveReloadApplied(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	row, _ := r.store.row("partner.example.com")
	row.Generation, row.AppliedGeneration = 2, 1
	r.store.put(row)
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // the save's own regeneration reload
	r.settle()

	r.tick(t)

	if r.nginx.applyCount() != 0 {
		t.Fatalf("applies = %d, want none: the save's reload already applied generation 2", r.nginx.applyCount())
	}
}

// A file the check repairs (here one that lost its addresses with its
// volume) is applied in that check, also inside the reload gap. The
// gap keeps a name's owner from deciding how often nginx reloads; a
// repair is not theirs to cause, and the generation counts as
// applied already, so nothing would apply a repair held back.
func TestDNSTickAppliesARepairedFileAtOnce(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.svc.lastReload = r.clock.Now() // a DNS reload just now: the gap has not passed
	r.nginx.putFile(dnsACL(dnsTestListA), "partner.example.com", 1)

	r.tick(t)

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("file = %v, want the published address written back", got)
	}
	if r.nginx.applyCount() != 1 {
		t.Fatalf("applies = %d, want the repair applied in the same check", r.nginx.applyCount())
	}
}

// List A drops a name list B keeps, and a check sees it before the save's
// SyncScope does (SyncScope failed, or the check's transaction came first).
// Emptying A's file is a revocation like any other: it gets a generation of
// its own and waits as a revocation, so a blocked apply raises the revoke
// alert and keeps being retried, and only a reload that read the emptied
// file ends it. SyncScope then finds nothing left to do.
func TestDNSTickTracksAScopeDropAsARevocation(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	r.store.setRefs(dnsRef(dnsTestListA, name), dnsRef(dnsTestListB, name))
	r.store.put(dnsOKRow(name, 1, "203.0.113.10"))
	r.lookup.set(name, "203.0.113.10")
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "blocked", BlockingFile: "proxy_host_shop_example_com.conf"}}
	r.store.setRefs(dnsRef(dnsTestListB, name)) // list A committed without the name

	r.tick(t)
	if err := r.svc.SyncScope(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.nginx.file(a, name); len(got) != 0 {
		t.Fatalf("list A file = %v, want it emptied", got)
	}
	if st, _ := r.store.row(name); st.Generation != 2 || st.AppliedGeneration != 1 || st.RevokePendingSince == nil {
		t.Fatalf("row = %+v, want generation 2 waiting as a revocation, and nothing more from the save", st)
	}
	if !dnsAlerted(r, "revoke", true) {
		t.Fatalf("alerts = %+v, want revoke failing: a revocation's apply is blocked", r.events.snapshot().alerts)
	}

	for i := 0; i < 4; i++ {
		r.clock.Advance(3 * time.Minute)
		r.tick(t)
	}
	if r.nginx.applyCount() != 4 {
		t.Fatalf("applies = %d, want the blocked revocation retried after 1, 2 and 4 minutes", r.nginx.applyCount())
	}
	if ev := r.events.snapshot(); strings.Join(ev.failing, ",") != "true:blocked" {
		t.Fatalf("apply loop transitions = %v, want it failing and never recovered while blocked", ev.failing)
	}
	if st, _ := r.store.row(name); st.RevokePendingSince == nil || !r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatalf("row %+v; want the revocation still waiting: no reload read the emptied file", st)
	}

	// nginx -t passes again: the next retry's reload reads the emptied file.
	r.nginx.mu.Lock()
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "accepted"}}
	r.nginx.mu.Unlock()
	r.clock.Advance(10 * time.Minute)
	r.tick(t)
	if st, _ := r.store.row(name); st.RevokePendingSince != nil || st.AppliedGeneration != 2 || r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatalf("row %+v; want the revocation applied by the reload that read the emptied file", st)
	}
	if !dnsAlerted(r, "revoke", false) {
		t.Fatalf("alerts = %+v, want revoke recovered", r.events.snapshot().alerts)
	}
}

// The same drop while the post-hoc check of an older reload is open. That
// reload read A's file before it was emptied, so the emptied file is
// signalled at once, and nginx taking the older reload does not count as
// taking the revocation.
func TestDNSTickSignalsAScopeDropAnOlderReloadDidNotRead(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	r.store.setRefs(dnsRef(dnsTestListA, name), dnsRef(dnsTestListB, name), dnsRef(dnsTestListA, "shop.example.com"))
	r.store.put(dnsOKRow(name, 1, "203.0.113.10"))
	r.store.put(dnsOKRow("shop.example.com", 1, "203.0.113.20"))
	r.lookup.set(name, "203.0.113.10")
	r.lookup.set("shop.example.com", "127.0.0.1") // shop's revocation is signalled first
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	older, newer := &nginx.ReloadSnapshot{}, &nginx.ReloadSnapshot{}
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "unconfirmed", Snapshot: older}, {Outcome: "unconfirmed", Snapshot: newer}}
	r.nginx.takenSnaps = map[*nginx.ReloadSnapshot]bool{older: false, newer: false}
	r.tick(t) // the older reload: it reads A's file with 203.0.113.10

	r.store.setRefs(dnsRef(dnsTestListB, name), dnsRef(dnsTestListA, "shop.example.com")) // list A drops partner
	r.clock.Advance(time.Minute)
	r.tick(t)
	if r.nginx.applyCount() != 2 {
		t.Fatalf("applies = %d, want the emptied file signalled at once: the open check's reload read it full", r.nginx.applyCount())
	}

	r.nginx.mu.Lock()
	r.nginx.takenSnaps[older] = true // nginx is seen taking the older reload only
	r.nginx.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.tick(t)
	if st, _ := r.store.row(name); st.RevokePendingSince == nil || !r.svc.dnsAllows(a, "203.0.113.10") {
		t.Fatalf("row %+v; want the revocation still waiting: the reload nginx took read A's file before it was emptied", st)
	}

	r.nginx.mu.Lock()
	r.nginx.takenSnaps[newer] = true
	r.nginx.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.tick(t)
	st, _ := r.store.row(name)
	if st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation || r.svc.dnsAllows(a, "203.0.113.10") || r.nginx.applyCount() != 2 {
		t.Fatalf("row %+v after %d applies; want the revocation applied by the newer reload and no further signal", st, r.nginx.applyCount())
	}
}

// dnsHangingLookuper never answers: every lookup waits until its context
// ends, as when the resolver drops the queries.
type dnsHangingLookuper struct{}

func (dnsHangingLookuper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (dnsHangingLookuper) LookupCNAME(ctx context.Context, host string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// dnsCtxStore begins a transaction only while its context lives, as
// database/sql's BeginTx does.
type dnsCtxStore struct{ *dnsTestStore }

func (s dnsCtxStore) WithTx(ctx context.Context, fn func(tx repository.DNSEntryTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.dnsTestStore.WithTx(ctx, fn)
}

// A DNS outage where every lookup runs into its timeout must not stop the
// checks: when the names do not fit the check's time, the lookups stop
// early, the transaction still commits, and names past their grace
// close. Here a check has 2 s and every name would take 3 s.
func TestDNSTickCommitsWhenTheLookupsRunOutOfTime(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	var refs []model.DNSReference
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("n%02d.example.com", i)
		refs = append(refs, dnsRef(dnsTestListA, name))
		r.store.put(dnsOKRow(name, 1, "203.0.113.10"))
	}
	r.store.setRefs(refs...)
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.svc.lookuper = dnsHangingLookuper{}
	r.svc.states = dnsCtxStore{r.store}
	r.clock.Advance(25 * time.Hour) // past every name's 24-hour grace

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.svc.Tick(ctx)
	r.settle()

	for _, ref := range refs {
		st, _ := r.store.row(ref.Name)
		if st.Status != model.DNSStatusExpired || len(st.Published) != 0 {
			t.Fatalf("%s: status %q, published %v; want expired and empty although DNS never answered", ref.Name, st.Status, st.Published)
		}
		if got, _ := r.nginx.file(ref.Scope, ref.Name); len(got) != 0 {
			t.Fatalf("%s: file = %v, want it emptied", ref.Name, got)
		}
	}
}

func TestDNSApplyFailureKeepsTheFilesAndBacksOff(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.settings.set(`{"check_interval_seconds":300}`, nil)
	r.lookup.set("partner.example.com", "127.0.0.1") // parked on loopback: refused, revoked at once
	blocked := nginx.DNSApplyResult{Outcome: "blocked", Detail: `host not found in upstream "app.example.com"`, BlockingFile: "proxy_host_shop_example_com.conf"}
	r.nginx.results = []nginx.DNSApplyResult{blocked, blocked, {Outcome: "accepted"}}

	if d := r.tick(t); d != time.Minute {
		t.Fatalf("delay after the first failure = %v, want the 1 minute retry", d)
	}
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("file = %v, want it left empty after the failed apply", got)
	}
	if !dnsAlerted(r, "revoke", true) {
		t.Fatalf("alerts = %+v, want revoke failing at the first failure", r.events.snapshot().alerts)
	}

	r.clock.Advance(30 * time.Second)
	r.tick(t)
	if r.nginx.applyCount() != 1 {
		t.Fatalf("applies = %d, want no retry before it is due", r.nginx.applyCount())
	}

	r.clock.Advance(31 * time.Second)
	if d := r.tick(t); d != 2*time.Minute {
		t.Fatalf("delay after the second failure = %v, want 2 minutes", d)
	}
	r.clock.Advance(2 * time.Minute)
	r.tick(t)
	if r.nginx.applyCount() != 3 {
		t.Fatalf("applies = %d, want 3", r.nginx.applyCount())
	}
	st, _ := r.store.row("partner.example.com")
	if st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation {
		t.Fatalf("row = %+v, want the revocation applied", st)
	}
	if len(st.ChangeTimes) != 1 {
		t.Fatalf("change_times = %v, want only the revocation: failed applies use no budget", st.ChangeTimes)
	}
	if !dnsAlerted(r, "revoke", false) {
		t.Fatalf("alerts = %+v, want revoke recovered", r.events.snapshot().alerts)
	}
	if ev := r.events.snapshot(); strings.Join(ev.failing, ",") != "true:blocked,false:accepted" {
		t.Fatalf("apply loop transitions = %v, want one failing and one recovered", ev.failing)
	}
}

// nginx not running is no emergency: no nginx holds an
// old allow, and it reads the files when it starts. It is retried, counts as
// a failing apply loop from 15 minutes on, and never raises the revoke alert.
func TestDNSNginxNotUpIsNoFailureForFifteenMinutes(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.lookup.set("partner.example.com", "127.0.0.1")
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "not_up"}}

	start := r.clock.Now()
	failingAt := time.Duration(-1)
	for i := 0; i < 40 && failingAt < 0; i++ {
		r.tick(t)
		if len(r.events.snapshot().failing) > 0 {
			failingAt = r.clock.Now().Sub(start)
		}
		r.clock.Advance(time.Minute)
	}
	if failingAt < 15*time.Minute || failingAt > 25*time.Minute {
		t.Fatalf("the apply loop failed after %v of not_up, want it at the first retry from 15 minutes on", failingAt)
	}
	if ev := r.events.snapshot(); len(ev.failing) != 1 || dnsAlerted(r, "revoke", true) {
		t.Fatalf("apply loop transitions %v, alerts %+v; want one failing transition and no revoke alert", ev.failing, ev.alerts)
	}
}

// A cold boot: compose starts the API before nginx, so the
// first apply finds nginx not up, which is no emergency. Once nginx
// is up, the boot's own reload of what it could not test then
// (applyWhenNginxUp) passes the hooks: the waiting change counts as applied,
// nothing is signalled again and the retry ends without a failing apply
// loop or a revoke alert.
func TestDNSColdBootAppliesOnceNginxIsUp(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.settings.set(`{"check_interval_seconds":300}`, nil)
	r.lookup.set("partner.example.com", "127.0.0.1") // a change waits for nginx: here a revocation
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "not_up"}}

	if d := r.tick(t); d != time.Minute {
		t.Fatalf("delay while nginx is not up = %v, want the 1 minute retry", d)
	}
	if st, _ := r.store.row("partner.example.com"); st.RevokePendingSince == nil || st.AppliedGeneration == st.Generation {
		t.Fatalf("row = %+v, want the change waiting for nginx", st)
	}

	// nginx is up: the boot reloads it once, through the hooks.
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()

	r.clock.Advance(time.Minute)
	if d := r.tick(t); d != 5*time.Minute {
		t.Fatalf("delay once nginx took the files = %v, want the 5 minute interval: no retry is left", d)
	}
	st, _ := r.store.row("partner.example.com")
	if st.AppliedGeneration != st.Generation || st.RevokePendingSince != nil || r.nginx.applyCount() != 1 {
		t.Fatalf("row %+v after %d apply(ies); want the change applied by the boot's reload and no second signal", st, r.nginx.applyCount())
	}
	if ev := r.events.snapshot(); len(ev.failing) != 0 || dnsAlerted(r, "revoke", true) {
		t.Fatalf("apply loop transitions %v, alerts %+v; want no failing apply loop and no revoke alert", ev.failing, ev.alerts)
	}
}

// dnsAlerted reports whether subject was recorded with failing.
func dnsAlerted(r *dnsTestRig, subject string, failing bool) bool {
	for _, a := range r.events.snapshot().alerts {
		if a.Subject == subject && a.Failing == failing {
			return true
		}
	}
	return false
}

func TestDNSUnconfirmedReloadIsCheckedBeforeSignallingAgain(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.lookup.set("partner.example.com", "127.0.0.1")
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "unconfirmed", Snapshot: &nginx.ReloadSnapshot{}}}

	r.tick(t)
	r.clock.Advance(time.Minute)
	r.tick(t)
	if r.nginx.applyCount() != 1 || r.nginx.takenCall != 1 {
		t.Fatalf("applies %d, post-hoc checks %d; want one apply and one check, no second signal", r.nginx.applyCount(), r.nginx.takenCall)
	}

	r.clock.Advance(10 * time.Minute)
	r.tick(t)
	if r.nginx.applyCount() != 2 {
		t.Fatalf("applies = %d, want a new signal after 10 minutes without a new nginx child", r.nginx.applyCount())
	}

	r.nginx.mu.Lock()
	r.nginx.taken = true
	r.nginx.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.tick(t)
	st, _ := r.store.row("partner.example.com")
	if st.RevokePendingSince != nil {
		t.Fatalf("row = %+v, want the revocation applied once the check sees nginx took the reload", st)
	}
}

// A failed apply is retried, and the retry's reload comes back unconfirmed
// with nginx never seen taking it. The checks that look for nginx taking it,
// and the one that gives up after 10 minutes and signals again, come every
// 15 seconds, never at once. A retry that falls due while no such check is
// open runs on time.
func TestDNSUnconfirmedRetryNeverSpinsTheChecks(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.settings.set(`{"check_interval_seconds":300}`, nil)
	r.lookup.set("partner.example.com", "127.0.0.1") // refused: a revocation waits
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "blocked"}, {Outcome: "unconfirmed", Snapshot: &nginx.ReloadSnapshot{}}}

	if d := r.tick(t); d != time.Minute {
		t.Fatalf("delay after the failed apply = %v, want the 1 minute retry", d)
	}
	r.clock.Advance(time.Minute)
	d := r.tick(t)
	if r.nginx.applyCount() != 2 {
		t.Fatalf("applies = %d, want the retry run when it fell due", r.nginx.applyCount())
	}
	checks, shortest := 0, d
	for start := r.clock.Now(); r.clock.Now().Sub(start) < 15*time.Minute; checks++ {
		shortest = min(shortest, d)
		r.clock.Advance(d)
		d = r.tick(t)
	}
	if shortest < 15*time.Second || checks > 60 {
		t.Fatalf("%d checks in 15 minutes, the shortest wait %v; want none sooner than 15 s", checks, shortest)
	}
	if r.nginx.applyCount() != 3 {
		t.Fatalf("applies = %d, want one more signal once the check gave up after 10 minutes", r.nginx.applyCount())
	}
}

// As a property: whatever DNS answers and however nginx fails,
// after a check whose writes went through every file holds exactly what the
// database wants, and a failed apply never puts anything back.
// An open post-hoc check holds back additions, not a revocation
// it does not cover: that is signalled at once, with a new snapshot. The
// older check stays open, and taking the newer reload closes both.
func TestDNSOpenPostHocCheckHoldsBackOnlyAdditions(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10", "203.0.113.11")
	older, newer := &nginx.ReloadSnapshot{}, &nginx.ReloadSnapshot{}
	r.nginx.results = []nginx.DNSApplyResult{
		{Outcome: "unconfirmed", Snapshot: older},
		{Outcome: "unconfirmed", Snapshot: newer},
	}
	open := func() int {
		r.svc.diskMu.Lock()
		defer r.svc.diskMu.Unlock()
		return len(r.svc.postHocs)
	}

	// 203.0.113.11 is revoked; nginx is not seen taking the reload.
	r.lookup.set("partner.example.com", "203.0.113.10")
	r.tick(t)
	if r.nginx.applyCount() != 1 || open() != 1 {
		t.Fatalf("applies %d, open checks %d; want 1 and 1", r.nginx.applyCount(), open())
	}

	// 203.0.113.12 is added (seen twice, after the reload gap): written, not
	// signalled while the check is open.
	r.lookup.set("partner.example.com", "203.0.113.10", "203.0.113.12")
	r.clock.Advance(time.Minute)
	r.tick(t)
	r.clock.Advance(5 * time.Minute)
	r.tick(t)
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10", "203.0.113.12"}) || r.nginx.applyCount() != 1 {
		t.Fatalf("file %v after %d applies; want the addition written and not signalled", got, r.nginx.applyCount())
	}

	// 203.0.113.10 is revoked: the open check does not cover it, so it is
	// signalled now, and the older check stays open.
	r.lookup.set("partner.example.com", "203.0.113.12")
	r.clock.Advance(time.Minute)
	r.tick(t)
	if r.nginx.applyCount() != 2 || open() != 2 {
		t.Fatalf("applies %d, open checks %d; want the revocation signalled at once and both checks open", r.nginx.applyCount(), open())
	}

	// nginx is seen taking the newer reload: it read the older one's files too.
	r.nginx.mu.Lock()
	r.nginx.takenSnaps = map[*nginx.ReloadSnapshot]bool{older: false, newer: true}
	r.nginx.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.tick(t)
	st, _ := r.store.row("partner.example.com")
	if open() != 0 || st.AppliedGeneration != st.Generation || st.RevokePendingSince != nil || r.nginx.applyCount() != 2 {
		t.Fatalf("row %+v, open checks %d, applies %d; want everything applied by the newer reload and no new signal", st, open(), r.nginx.applyCount())
	}
	for _, a := range []string{"203.0.113.10", "203.0.113.11"} {
		if r.svc.dnsAllows(dnsACL(dnsTestListA), a) {
			t.Fatalf("%s is still counted as allowed after nginx took the newer reload", a)
		}
	}
}

func TestDNSFilesNeverHoldMoreThanTheDatabaseWants(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"),
		dnsRef(dnsTestListA, "shop.example.com"))
	rng := rand.New(rand.NewSource(320))
	answers := [][]string{{"203.0.113.10"}, {"203.0.113.11"}, {"203.0.113.10", "203.0.113.11"}, {"127.0.0.1"}, {"2001:db8::10"}, nil}
	results := []string{"accepted", "blocked", "rejected", "failed", "not_up", "signalled"}
	for i := 0; i < 300; i++ {
		for _, name := range []string{"partner.example.com", "shop.example.com"} {
			switch k := rng.Intn(len(answers) + 1); k {
			case len(answers):
				r.lookup.fail(name, &net.DNSError{Err: "server misbehaving", Name: name + ".", IsTemporary: true})
			default:
				r.lookup.set(name, answers[k]...)
			}
		}
		r.nginx.mu.Lock()
		r.nginx.results = []nginx.DNSApplyResult{{Outcome: results[rng.Intn(len(results))]}}
		writeFails := rng.Intn(10) == 0
		if writeFails {
			r.nginx.writeErr = errors.New("no space left on device")
		} else {
			r.nginx.writeErr = nil
		}
		r.nginx.mu.Unlock()
		if rng.Intn(20) == 0 {
			r.store.setRefs(dnsRef(dnsTestListB, "partner.example.com"))
		} else if rng.Intn(20) == 0 {
			r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"),
				dnsRef(dnsTestListA, "shop.example.com"))
		}

		r.svc.Tick(context.Background())
		r.settle()
		r.clock.Advance(time.Duration(30+rng.Intn(600)) * time.Second)
		if writeFails {
			continue
		}
		refs, _ := r.store.ListReferences(context.Background())
		referenced := make(map[string]bool)
		for _, ref := range refs {
			referenced[dnsSegKey(ref.Scope, ref.Name)] = true
		}
		for _, list := range []string{dnsTestListA, dnsTestListB} {
			for _, name := range []string{"partner.example.com", "shop.example.com"} {
				got, ok := r.nginx.file(dnsACL(list), name)
				if !ok {
					continue
				}
				row, has := r.store.row(name)
				var want []string
				if referenced[dnsSegKey(dnsACL(list), name)] {
					want = dnsDesired(row, has)
				}
				if !dnsEqual(got, want) {
					t.Fatalf("step %d: file (%s, %s) = %v, want %v (row %+v)", i, list[:4], name, got, want, row)
				}
			}
		}
	}
}

func TestDNSTickDelay(t *testing.T) {
	r := newDNSTestRig(t)
	r.settings.set(`{"check_interval_seconds":300}`, nil)
	st := r.svc.Settings(context.Background())
	if d := r.svc.nextDelay(st); d != 300*time.Second {
		t.Fatalf("delay = %v, want the configured 300s", d)
	}
	r.svc.envInterval = 5 * time.Second
	if d := r.svc.nextDelay(st); d != 5*time.Second {
		t.Fatalf("delay = %v, want NPG_DNS_ENTRIES_INTERVAL", d)
	}
	r.svc.envInterval = 0
	r.svc.applyView.retryAt = r.clock.Now().Add(20 * time.Second)
	if d := r.svc.nextDelay(st); d != 20*time.Second {
		t.Fatalf("delay = %v, want the retry that is due sooner", d)
	}
	r.svc.applyView.retryAt = r.clock.Now().Add(-time.Minute)
	if d := r.svc.nextDelay(st); d != 300*time.Second {
		t.Fatalf("delay = %v, want the interval: a retry time that has passed shortens nothing", d)
	}
	r.svc.applyView.retryAt = r.clock.Now().Add(100 * time.Millisecond)
	if d := r.svc.nextDelay(st); d != time.Second {
		t.Fatalf("delay = %v, want at least a second", d)
	}
	r.svc.applyView.retryAt = time.Time{}
	r.svc.postHocs = []*dnsPostHoc{{since: r.clock.Now()}}
	if d := r.svc.nextDelay(st); d != 15*time.Second {
		t.Fatalf("delay = %v, want 15 s while a post-hoc check is open", d)
	}
	r.svc.envInterval = 5 * time.Second
	if d := r.svc.nextDelay(st); d != 5*time.Second {
		t.Fatalf("delay = %v, want the interval when it is shorter than 15 s", d)
	}
}
