package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

func TestDNSEntrySettingsKeepTheLastGoodValueOnAReadError(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()

	r.settings.set(``, errors.New("db down"))
	st, known := r.svc.currentSettings(ctx)
	if known || st.Enabled {
		t.Fatalf("first read failed: got enabled=%v known=%v, want the feature off and unknown", st.Enabled, known)
	}

	r.settings.set(`{"enabled":false,"check_interval_seconds":90}`, nil)
	if st := r.svc.Settings(ctx); st.Enabled || st.CheckIntervalSeconds != 90 {
		t.Fatalf("stored value: got %+v", st)
	}
	r.settings.set(``, errors.New("db down"))
	st, known = r.svc.currentSettings(ctx)
	if !known || st.Enabled || st.CheckIntervalSeconds != 90 {
		t.Fatalf("read error after a good read: got %+v known=%v, want the last stored value (never the defaults)", st, known)
	}
}

func TestDNSEntrySettingsEnvSwitchWins(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.envDisabled = true
	r.settings.set(`{"enabled":true}`, nil)
	st, known := r.svc.currentSettings(context.Background())
	if st.Enabled || !known {
		t.Fatalf("NPG_DNS_ENTRIES_DISABLED: got enabled=%v known=%v, want off and known", st.Enabled, known)
	}
	r.settings.set(``, errors.New("db down"))
	if st, known := r.svc.currentSettings(context.Background()); st.Enabled || !known {
		t.Fatal("the env switch must hold even when the settings cannot be read")
	}
}

func TestDNSReconcileFilesWritesEveryReferencedSegment(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"),
		dnsRef(dnsTestListA, "new.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 3, "203.0.113.10"))

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, list := range []string{dnsTestListA, dnsTestListB} {
		got, ok := r.nginx.file(dnsACL(list), "partner.example.com")
		if !ok || !dnsEqual(got, []string{"203.0.113.10"}) {
			t.Errorf("list %s: partner file = %v (exists %v), want the published address", list, got, ok)
		}
	}
	got, ok := r.nginx.file(dnsACL(dnsTestListA), "new.example.com")
	if !ok || len(got) != 0 {
		t.Errorf("new name: file = %v (exists %v), want an empty file before any answer", got, ok)
	}
	row, ok := r.store.row("new.example.com")
	if !ok || row.Status != model.DNSStatusPending || len(row.Published) != 0 {
		t.Errorf("new name: row = %+v (exists %v), want pending with nothing published", row, ok)
	}
	if r.nginx.applyCount() != 0 {
		t.Error("ReconcileFiles must not ask nginx anything")
	}
}

func TestDNSReconcileFilesClosesNamesUncheckedPastTheGrace(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	row := dnsOKRow("partner.example.com", 3, "203.0.113.10")
	old := dnsTestStart.Add(-30 * time.Hour) // the API was down longer than the 24 h grace
	row.V4.AnswerAt = &old
	r.store.put(row)
	r.nginx.putFile(dnsACL(dnsTestListA), "partner.example.com", 3, "203.0.113.10")

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got, _ := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com")
	if len(got) != 0 {
		t.Fatalf("file = %v, want it emptied at boot", got)
	}
	st, _ := r.store.row("partner.example.com")
	if len(st.Published) != 0 || st.EmptyCause != model.DNSEmptyLapse || st.RevokePendingSince == nil || st.Generation != 4 {
		t.Fatalf("row = %+v, want published empty, empty_cause lapse, a revocation waiting, generation 4", st)
	}
	if !r.svc.dnsAllows(dnsACL(dnsTestListA), "203.0.113.10") {
		t.Fatal("until a reload is taken, nginx may still allow the old address: it must stay in pendingRevoke")
	}
}

func TestDNSReconcileFilesEmptiesFilesNothingReferences(t *testing.T) {
	r := newDNSTestRig(t)
	r.nginx.putFile(dnsACL(dnsTestListB), "gone.example.com", 7, "198.51.100.7")

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got, ok := r.nginx.file(dnsACL(dnsTestListB), "gone.example.com")
	if !ok || len(got) != 0 {
		t.Fatalf("unreferenced file = %v (exists %v), want it kept but empty", got, ok)
	}
	if !r.svc.dnsAllows(dnsACL(dnsTestListB), "198.51.100.7") {
		t.Fatal("the emptied address must be remembered as possibly still allowed")
	}
}

func TestDNSReconcileFilesCreatesMissingFilesConfigsReference(t *testing.T) {
	r := newDNSTestRig(t)
	r.nginx.diskRefs = map[string]bool{"00112233445566ff.allow": true}

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(r.nginx.ensured) != 0 {
		t.Fatalf("without scanDisk nothing is created, got %v", r.nginx.ensured)
	}
	if err := r.svc.ReconcileFiles(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(r.nginx.ensured) != 1 || r.nginx.ensured[0] != "00112233445566ff.allow" {
		t.Fatalf("ensured = %v, want the referenced file a restored configuration names", r.nginx.ensured)
	}
}

func TestDNSReconcileFilesHonoursTheSwitch(t *testing.T) {
	r := newDNSTestRig(t)
	r.settings.set(`{"enabled":false}`, nil)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 3, "203.0.113.10"))

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	st, _ := r.store.row("partner.example.com")
	if !st.Disabled || len(st.Published) != 0 || st.EmptyCause != model.DNSEmptyDisabled || !dnsEqual(st.LastApplied, []string{"203.0.113.10"}) {
		t.Fatalf("row = %+v, want disabled, nothing published, empty_cause disabled, last_applied kept", st)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com"); len(got) != 0 {
		t.Fatalf("file = %v, want empty while the feature is off", got)
	}
}

func TestDNSReconcileFilesChangesNoSwitchWhenTheSettingsAreUnknown(t *testing.T) {
	r := newDNSTestRig(t)
	r.settings.set(``, errors.New("db down"))
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 3, "203.0.113.10"))

	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	st, _ := r.store.row("partner.example.com")
	if st.Disabled || len(st.Published) != 1 {
		t.Fatalf("row = %+v: an unreadable setting must not switch names off", st)
	}
}

// The common hook: any reload that read the files marks
// their generation applied, so the next tick does not reload again.
func TestDNSAcceptedReloadMarksTheFilesApplied(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	row := dnsOKRow("partner.example.com", 4, "203.0.113.11")
	row.AppliedGeneration = 3 // 203.0.113.10 was replaced and nginx has not reloaded
	now := dnsTestStart
	row.RevokePendingSince = &now
	r.store.put(row)
	r.nginx.putFile(dnsACL(dnsTestListA), "partner.example.com", 3, "203.0.113.10")
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // e.g. the reload of a save
	r.settle()

	st, _ := r.store.row("partner.example.com")
	if st.AppliedGeneration != 4 || st.RevokePendingSince != nil {
		t.Fatalf("row = applied %d, revoke pending %v; want generation 4 applied and no revocation waiting", st.AppliedGeneration, st.RevokePendingSince)
	}
	if r.svc.dnsAllows(dnsACL(dnsTestListA), "203.0.113.10") {
		t.Fatal("the revoked address must leave pendingRevoke once nginx took the file without it")
	}
	ev := r.events.snapshot()
	if len(ev.applies) != 1 || ev.applies[0].before != nil || !dnsEqual(ev.applies[0].after, []string{"203.0.113.11"}) || ev.applies[0].gen != 4 {
		t.Fatalf("applied events = %+v, want one: unknown before, 203.0.113.11 after, generation 4", ev.applies)
	}
}

func TestDNSReloadsNginxDidNotTakeChangeNothing(t *testing.T) {
	for _, outcome := range []nginx.ReloadOutcome{nginx.ReloadRejected, nginx.ReloadSuperseded} {
		r := newDNSTestRig(t)
		r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
		row := dnsOKRow("partner.example.com", 2, "203.0.113.10")
		row.AppliedGeneration = 1
		r.store.put(row)
		if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		hooks := r.svc.ReloadHooks()
		hooks.After(hooks.Before(), outcome, nil)
		r.settle()
		if st, _ := r.store.row("partner.example.com"); st.AppliedGeneration != 1 || len(r.store.marked) != 0 {
			t.Fatalf("%s: applied = %d, marks = %v; want nothing recorded", outcome, st.AppliedGeneration, r.store.marked)
		}
	}
}

func TestDNSUnconfirmedReloadWaitsForThePostHocCheck(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	row := dnsOKRow("partner.example.com", 2, "203.0.113.10")
	row.AppliedGeneration = 1
	r.store.put(row)
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	hooks := r.svc.ReloadHooks()

	hooks.After(hooks.Before(), nginx.ReloadUnconfirmed, &nginx.ReloadSnapshot{})
	r.settle()
	if len(r.store.marked) != 0 || len(r.svc.postHocs) != 1 {
		t.Fatalf("unconfirmed with a snapshot: marks %v, open checks %d; want nothing marked and the check kept", r.store.marked, len(r.svc.postHocs))
	}

	hooks.After(hooks.Before(), nginx.ReloadUnconfirmed, nil) // no snapshot to check against: counts as taken
	r.settle()
	if st, _ := r.store.row("partner.example.com"); st.AppliedGeneration != 2 {
		t.Fatalf("unconfirmed without a snapshot: applied = %d, want 2 (counted as taken)", st.AppliedGeneration)
	}
	if len(r.svc.postHocs) != 0 {
		t.Fatal("a later taken reload covers the older unconfirmed one")
	}

	// Two unconfirmed reloads: both stay open, oldest first.
	older, newer := hooks.Before(), hooks.Before()
	hooks.After(older, nginx.ReloadUnconfirmed, &nginx.ReloadSnapshot{})
	hooks.After(newer, nginx.ReloadNotChecked, &nginx.ReloadSnapshot{})
	if len(r.svc.postHocs) != 2 || r.svc.postHocs[0].token != older || r.svc.postHocs[1].token != newer {
		t.Fatalf("open checks = %d, want both, the older first", len(r.svc.postHocs))
	}
	// A reload older than one nginx took is not kept open.
	late, taken := hooks.Before(), hooks.Before()
	hooks.After(taken, nginx.ReloadAccepted, nil)
	hooks.After(late, nginx.ReloadUnconfirmed, &nginx.ReloadSnapshot{})
	r.settle()
	if len(r.svc.postHocs) != 0 {
		t.Fatalf("open checks = %d after a newer reload was taken, want none", len(r.svc.postHocs))
	}
}

func TestDNSReloadTokenNeverOverClaimsAPartlyWrittenName(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.disk[dnsSegKey(dnsACL(dnsTestListA), "partner.example.com")] = dnsDiskEntry{Scope: dnsACL(dnsTestListA), Name: "partner.example.com", Gen: 5}
	r.svc.disk[dnsSegKey(dnsACL(dnsTestListB), "partner.example.com")] = dnsDiskEntry{Scope: dnsACL(dnsTestListB), Name: "partner.example.com", Gen: 4}
	tok := r.svc.beforeReload().(*dnsReloadToken)
	if tok.gens["partner.example.com"] != 4 {
		t.Fatalf("token generation = %d, want 4: the list B file still holds generation 4", tok.gens["partner.example.com"])
	}
}

func TestDNSAfterHooksOutOfOrderNeverMoveBack(t *testing.T) {
	r := newDNSTestRig(t)
	scope := dnsACL(dnsTestListA)
	r.svc.disk[dnsSegKey(scope, "partner.example.com")] = dnsDiskEntry{Scope: scope, Name: "partner.example.com", Gen: 1, Addrs: []string{"203.0.113.10"}}
	older := r.svc.beforeReload()
	r.svc.disk[dnsSegKey(scope, "partner.example.com")] = dnsDiskEntry{Scope: scope, Name: "partner.example.com", Gen: 2, Addrs: []string{"203.0.113.11"}}
	newer := r.svc.beforeReload()

	r.svc.afterReload(newer, nginx.ReloadAccepted, nil)
	r.svc.afterReload(older, nginx.ReloadAccepted, nil)
	r.settle()

	if v := r.svc.nginxView["partner.example.com"]; v.Gen != 2 || !dnsEqual(v.Addrs, []string{"203.0.113.11"}) {
		t.Fatalf("nginxView = %+v, want generation 2 with 203.0.113.11", v)
	}
	if ev := r.events.snapshot(); len(ev.applies) != 1 {
		t.Fatalf("applied events = %+v, want only the newer reload's", ev.applies)
	}
}

func TestDNSApplyAlerts(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	since := dnsTestStart
	revoking := dnsOKRow("partner.example.com", 2)
	revoking.AppliedGeneration = 1
	revoking.RevokePendingSince = &since
	r.store.put(revoking)

	r.svc.evaluateApplyAlerts(ctx, nil)
	if ev := r.events.snapshot(); len(ev.alerts) != 1 || ev.alerts[0].Subject != "apply" {
		t.Fatalf("no failure yet: alerts = %+v, want only the apply subject's first look", ev.alerts)
	}

	blocked := nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_shop_example_com.conf"}
	r.svc.evaluateApplyAlerts(ctx, &blocked)
	r.svc.evaluateApplyAlerts(ctx, &blocked)
	ev := r.events.snapshot()
	if len(ev.alerts) != 2 || ev.alerts[1].Subject != "revoke" || !ev.alerts[1].Failing ||
		ev.alerts[1].File != "proxy_host_shop_example_com.conf" || !dnsEqual(ev.alerts[1].Names, []string{"partner.example.com"}) {
		t.Fatalf("alerts = %+v, want revoke failing once, on the first failure, naming the blocking file", ev.alerts)
	}

	adding := dnsOKRow("shop.example.com", 5, "198.51.100.7")
	adding.AppliedGeneration = 4
	changed := dnsTestStart.Add(-16 * time.Minute)
	adding.LastChangedAt = &changed
	r.store.put(adding)
	r.store.MarkApplied(ctx, map[string]int64{"partner.example.com": 2})
	r.svc.evaluateApplyAlerts(ctx, nil)
	ev = r.events.snapshot()
	if len(ev.alerts) != 4 {
		t.Fatalf("alerts = %+v, want revoke recovered and apply failing", ev.alerts)
	}
	if a := ev.alerts[2]; a.Subject != "revoke" || a.Failing || a.Quiet {
		t.Errorf("third alert = %+v, want revoke recovered (not quiet: this process saw it fail)", a)
	}
	if a := ev.alerts[3]; a.Subject != "apply" || !a.Failing || !dnsEqual(a.Names, []string{"shop.example.com"}) {
		t.Errorf("fourth alert = %+v, want apply failing for shop.example.com", a)
	}
}

func TestDNSReviewAlertOncePerProcessAndRetriedCloses(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	review := model.DNSEntryState{Hostname: "partner.example.com", Status: model.DNSStatusNeedsReview, ReviewReason: model.DNSReviewCNAMEChanged}
	rows := map[string]model.DNSEntryState{"partner.example.com": review}
	scopes := map[string]int{"partner.example.com": 1}

	r.svc.announceReviews(ctx, rows, scopes)
	r.svc.announceReviews(ctx, rows, scopes)
	if ev := r.events.snapshot(); len(ev.reviews) != 1 {
		t.Fatalf("review alerts = %v, want one per process", ev.reviews)
	}

	r.events.closeErr = errors.New("db down")
	r.svc.closeReview(ctx, "partner.example.com", true)
	r.events.closeErr = nil
	review.Status = model.DNSStatusOK
	r.svc.announceReviews(ctx, map[string]model.DNSEntryState{"partner.example.com": review}, scopes)
	if ev := r.events.snapshot(); len(ev.closed) != 1 || ev.closed[0] != "partner.example.com confirmed" {
		t.Fatalf("closes = %v, want the failed close retried once", ev.closed)
	}
}

func TestDNSGarbageCollection(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	eightDays := dnsTestStart.Add(-8 * 24 * time.Hour)
	fiveDays := dnsTestStart.Add(-5 * 24 * time.Hour)
	old := model.DNSEntryState{Hostname: "old.example.com", Status: model.DNSStatusNeedsReview, ReviewReason: model.DNSReviewReappeared, UnusedSince: &eightDays}
	recent := model.DNSEntryState{Hostname: "recent.example.com", Status: model.DNSStatusOK, UnusedSince: &fiveDays}
	r.store.put(old)
	r.store.put(recent)
	r.nginx.putFile(dnsACL(dnsTestListA), "old.example.com", 3)
	if err := r.svc.ReconcileFiles(ctx, false); err != nil { // records the file in the disk table
		t.Fatal(err)
	}
	r.clock.Advance(25 * time.Hour)

	r.svc.collectGarbage(ctx)

	if _, ok := r.store.row("old.example.com"); ok {
		t.Error("a row unused for more than 7 days must be deleted")
	}
	if _, ok := r.store.row("recent.example.com"); !ok {
		t.Error("a row unused for less than 7 days keeps its review and pin")
	}
	if ev := r.events.snapshot(); len(ev.closed) != 1 || ev.closed[0] != "old.example.com quiet" {
		t.Errorf("closes = %v, want the deleted name's review closed quietly first", ev.closed)
	}
	if _, ok := r.nginx.file(dnsACL(dnsTestListA), "old.example.com"); ok {
		t.Error("an unreferenced file empty for more than a day must be removed")
	}
	if len(r.svc.disk) != 0 {
		t.Errorf("disk table = %v, want the removed file forgotten", r.svc.disk)
	}
}

// A name unused for more than 7 days whose revocation nginx never took (every
// reload refused) keeps its row: deleting it would end the revoke alert as
// recovered while nginx still allows the addresses. A row with a generation
// nginx has not taken stays too. The transaction checks again what the read
// before it saw: a revocation recorded in between keeps the row.
func TestDNSGarbageCollectionKeepsWhatNginxMayStillAllow(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	eightDays := dnsTestStart.Add(-8 * 24 * time.Hour)
	revoking := dnsOKRow("gone.example.com", 6)
	revoking.AppliedGeneration, revoking.UnusedSince, revoking.RevokePendingSince = 5, &eightDays, &eightDays
	unapplied := dnsOKRow("waiting.example.com", 4)
	unapplied.AppliedGeneration, unapplied.UnusedSince = 3, &eightDays
	late := dnsOKRow("late.example.com", 2)
	late.UnusedSince = &eightDays
	for _, st := range []model.DNSEntryState{revoking, unapplied, late} {
		r.store.put(st)
	}
	// The revoke alert is failing: an apply failed while the revocation waits.
	r.svc.evaluateApplyAlerts(ctx, &nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_x.conf"})
	// late's revocation is recorded after the cleanup read the rows.
	r.store.beforeTx = func(f *dnsTestStore) {
		f.mu.Lock()
		defer f.mu.Unlock()
		st := f.rows["late.example.com"]
		st.Generation, st.RevokePendingSince = 3, &eightDays
		f.rows["late.example.com"] = st
	}

	r.svc.collectGarbage(ctx)
	r.store.beforeTx = nil
	r.svc.evaluateApplyAlerts(ctx, nil)

	for _, name := range []string{"gone.example.com", "waiting.example.com", "late.example.com"} {
		if _, ok := r.store.row(name); !ok {
			t.Errorf("%s: row deleted while nginx may still allow its addresses", name)
		}
	}
	if dnsAlerted(r, "revoke", false) {
		t.Errorf("alerts = %+v, want the revoke alert still failing: no reload took the revocation", r.events.snapshot().alerts)
	}
}

// A name leaves its only list while nginx refuses every reload for more than
// a day (nginx -t passes, so no host config includes its emptied file any
// more). The cleanup keeps that file: a reload carries a name to nginx only
// through a file this process holds. Once nginx takes a reload again, the
// revocation clears, the revoke alert recovers, and the row and the file go
// as usual.
func TestDNSGarbageCollectionKeepsTheFileOfARevocationNginxHasNotTaken(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	ctx := context.Background()
	const name = "partner.example.com"
	a := dnsACL(dnsTestListA)
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "rejected", Detail: "bind() to 0.0.0.0:443 failed (98: Address in use)"}}
	r.store.setRefs() // list A saved without the name: nothing uses it now
	if err := r.svc.SyncScope(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	r.tick(t) // the removal is applied: refused
	if !dnsAlerted(r, "revoke", true) {
		t.Fatalf("alerts = %+v, want revoke failing", r.events.snapshot().alerts)
	}

	r.clock.Advance(25 * time.Hour)
	r.svc.collectGarbage(ctx)
	if _, ok := r.nginx.file(a, name); !ok {
		t.Fatal("the emptied file was removed while its revocation waits for nginx")
	}

	r.nginx.mu.Lock()
	r.nginx.results = []nginx.DNSApplyResult{{Outcome: "accepted"}}
	r.nginx.mu.Unlock()
	r.clock.Advance(time.Minute)
	r.tick(t) // the retry: nginx takes it
	if st, _ := r.store.row(name); st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation {
		t.Fatalf("row %+v; want the revocation taken by the reload", st)
	}
	if !dnsAlerted(r, "revoke", false) {
		t.Fatalf("alerts = %+v, want revoke recovered", r.events.snapshot().alerts)
	}

	r.clock.Advance(8 * 24 * time.Hour)
	r.svc.collectGarbage(ctx)
	if _, ok := r.store.row(name); ok {
		t.Error("the row of a name unused for more than 7 days and in nginx must be deleted")
	}
	if _, ok := r.nginx.file(a, name); ok {
		t.Error("its empty file must then be removed too")
	}
}

// The same holds for a row whose generation no reload took: its empty file is
// kept while nothing references it.
func TestDNSGarbageCollectionKeepsTheFileOfAnUntakenGeneration(t *testing.T) {
	r := newDNSTestRig(t)
	eightDays := dnsTestStart.Add(-8 * 24 * time.Hour)
	st := dnsOKRow("waiting.example.com", 4)
	st.AppliedGeneration, st.UnusedSince = 3, &eightDays
	r.store.put(st)
	r.nginx.putFile(dnsACL(dnsTestListB), "waiting.example.com", 4)
	r.clock.Advance(25 * time.Hour)

	r.svc.collectGarbage(context.Background())

	if _, ok := r.nginx.file(dnsACL(dnsTestListB), "waiting.example.com"); !ok {
		t.Error("the file of a generation nginx has not taken was removed")
	}
}
