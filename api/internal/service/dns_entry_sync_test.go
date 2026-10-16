package service

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

func TestDNSSyncScopePublishesANewNameAtOnce(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "slow.example.com"))
	r.lookup.set("partner.example.com", "203.0.113.10")
	r.lookup.fail("slow.example.com", &net.DNSError{Err: "i/o timeout", Name: "slow.example.com.", IsTimeout: true})

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), []string{"partner.example.com", "Slow.Example.com."}); err != nil {
		t.Fatal(err)
	}

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("file = %v, want the new name's first answer at once", got)
	}
	st, _ := r.store.row("partner.example.com")
	if st.Status != model.DNSStatusOK || len(st.ChangeTimes) != 0 || st.CanonicalName != "partner.example.com" {
		t.Fatalf("row = %+v, want ok, outside the change budget, CNAME target pinned", st)
	}
	slow, ok := r.store.row("slow.example.com")
	if !ok || slow.Status != model.DNSStatusPending {
		t.Fatalf("slow name row = %+v (exists %v), want pending for the scheduler", slow, ok)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "slow.example.com"); len(got) != 0 {
		t.Fatalf("slow name file = %v, want empty", got)
	}
	if r.nginx.applyCount() != 0 {
		t.Fatal("SyncScope must leave the reload to the caller's regeneration")
	}
}

func TestDNSSyncScopeGivesAReaddedNameItsStateBack(t *testing.T) {
	r := newDNSTestRig(t)
	twoDays := dnsTestStart.Add(-48 * time.Hour)
	back := dnsOKRow("partner.example.com", 3)
	back.Published, back.LastApplied = nil, []string{"203.0.113.10"}
	back.EmptyCause, back.UnusedSince = model.DNSEmptyUnused, &twoDays
	r.store.put(back)
	watched := model.DNSEntryState{Hostname: "watch.example.com", Status: model.DNSStatusNeedsReview,
		ReviewReason: model.DNSReviewCNAMEChanged, CanonicalName: "a.ddns.example.com", LastApplied: []string{"198.51.100.7"},
		Generation: 5, AppliedGeneration: 5, UnusedSince: &twoDays}
	r.store.put(watched)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "watch.example.com"))
	r.lookup.set("partner.example.com", "203.0.113.11")
	r.lookup.set("watch.example.com", "198.51.100.8")

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), []string{"partner.example.com", "watch.example.com"}); err != nil {
		t.Fatal(err)
	}

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.11"}) {
		t.Fatalf("re-added name file = %v, want the current answer published at once (an operator action)", got)
	}
	w, _ := r.store.row("watch.example.com")
	if w.Status != model.DNSStatusNeedsReview || w.UnusedSince != nil || w.CanonicalName != "a.ddns.example.com" {
		t.Fatalf("row = %+v, want review and pin kept, used again", w)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "watch.example.com"); len(got) != 0 {
		t.Fatalf("name in review: file = %v, want empty", got)
	}
	if ev := r.events.snapshot(); len(ev.reviews) != 1 || ev.reviews[0] != "watch.example.com" {
		t.Fatalf("review alerts = %v, want the re-added name in review announced", ev.reviews)
	}
}

// A list saved again with the same domains, by an unrelated edit or by an
// older client that sends the rules back without kind, changes no
// name's state: nothing is looked up, no generation moves, a review stays,
// the files stay as they are and nothing waits for nginx.
func TestDNSSyncScopeLeavesUnchangedNamesAlone(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "watch.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 3, "203.0.113.10"))
	watch := dnsOKRow("watch.example.com", 5)
	watch.Status, watch.ReviewReason = model.DNSStatusNeedsReview, model.DNSReviewReappeared
	watch.LastApplied, watch.Candidate = []string{"198.51.100.7"}, []string{"198.51.100.8"}
	r.store.put(watch)
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// DNS moved meanwhile: a check acts on that, a save does not.
	r.lookup.set("partner.example.com", "203.0.113.20")
	r.lookup.set("watch.example.com", "198.51.100.7")
	before := make(map[string]model.DNSEntryState)
	for _, n := range []string{"partner.example.com", "watch.example.com"} {
		before[n], _ = r.store.row(n)
	}
	r.lookup.mu.Lock()
	lookups := r.lookup.lookups
	r.lookup.mu.Unlock()

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), []string{"partner.example.com", "watch.example.com"}); err != nil {
		t.Fatal(err)
	}

	for n, prev := range before {
		if st, _ := r.store.row(n); !reflect.DeepEqual(st, prev) {
			t.Errorf("%s: row after the save %+v, want it unchanged %+v", n, st, prev)
		}
	}
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Errorf("partner file = %v, want the published address kept", got)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "watch.example.com"); len(got) != 0 {
		t.Errorf("name in review: file = %v, want empty", got)
	}
	r.lookup.mu.Lock()
	lookups = r.lookup.lookups - lookups
	r.lookup.mu.Unlock()
	if lookups != 0 || r.nginx.applyCount() != 0 {
		t.Errorf("%d lookup(s) and %d apply(ies), want none: no name is new", lookups, r.nginx.applyCount())
	}
}

// (scope, name) files: a name left in list B keeps its file
// there when list A drops it, and A's file stays empty even when the
// caller's regeneration reload never comes.
func TestDNSSyncScopeEmptiesOnlyTheScopeThatDroppedTheName(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	r.lookup.set("partner.example.com", "203.0.113.10")
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.store.setRefs(dnsRef(dnsTestListB, "partner.example.com")) // list A saved without the name

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), nil); err != nil {
		t.Fatal(err)
	}

	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com"); len(got) != 0 {
		t.Fatalf("list A file = %v, want empty at once", got)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListB), "partner.example.com"); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("list B file = %v, want it untouched", got)
	}
	st, _ := r.store.row("partner.example.com")
	if st.Generation != 2 || st.RevokePendingSince == nil || st.UnusedSince != nil {
		t.Fatalf("row = %+v, want a new generation with a revocation waiting, still used", st)
	}

	// The caller's regeneration failed: the next check applies it.
	r.tick(t)
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com"); len(got) != 0 {
		t.Fatalf("list A file after the check = %v, want still empty", got)
	}
	if st, _ := r.store.row("partner.example.com"); st.RevokePendingSince != nil {
		t.Fatalf("row = %+v, want the revocation applied by the check", st)
	}
}

func TestDNSSyncScopeAddingAPublishedNameToAListNeedsAReload(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListB, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"))

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), []string{"partner.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("list A file = %v, want the published address", got)
	}
	st, _ := r.store.row("partner.example.com")
	if st.Generation != 2 || st.AppliedGeneration != 1 {
		t.Fatalf("generation %d, applied %d; want a new generation nginx has not read yet", st.Generation, st.AppliedGeneration)
	}
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // the list save's regeneration reload
	r.settle()
	if st, _ := r.store.row("partner.example.com"); st.AppliedGeneration != 2 {
		t.Fatalf("applied = %d after the save's reload, want 2", st.AppliedGeneration)
	}
}

func TestDNSSyncScopeMarksANameNothingUsesUnused(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.store.setRefs() // the list was deleted

	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), nil); err != nil {
		t.Fatal(err)
	}
	st, _ := r.store.row("partner.example.com")
	if st.UnusedSince == nil || len(st.Published) != 0 || st.RevokePendingSince == nil {
		t.Fatalf("row = %+v, want unused, nothing published, the revocation waiting", st)
	}
	if got, _ := r.nginx.file(dnsACL(dnsTestListA), "partner.example.com"); len(got) != 0 {
		t.Fatalf("file = %v, want empty", got)
	}
}

func TestDNSValidateScopeNamesRefusesOnlyGrowthAboveALimit(t *testing.T) {
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "a1.example.com"), dnsRef(dnsTestListA, "a2.example.com"), dnsRef(dnsTestListB, "b1.example.com"))
	ctx := context.Background()
	a, b := dnsACL(dnsTestListA), dnsACL(dnsTestListB)
	cases := []struct {
		settings, scope string
		names           []string
		field           string
	}{
		{`{"max_per_list":2}`, a, []string{"a1.example.com", "a2.example.com", "a3.example.com"}, "items"},
		{`{"max_per_list":1}`, a, []string{"a1.example.com", "a2.example.com"}, ""}, // over a lowered limit, not growing
		{`{"max_per_list":1}`, a, []string{"a1.example.com"}, ""},
		{`{"max_total":3}`, b, []string{"b1.example.com", "b2.example.com"}, "dns_entry_settings.max_total"},
		{`{"max_total":3}`, b, []string{"b2.example.com"}, ""}, // a swap keeps the total
	}
	for i, c := range cases {
		r.settings.set(c.settings, nil)
		err := r.svc.ValidateScopeNames(ctx, c.scope, c.names)
		var limit *DNSLimitError
		switch {
		case c.field == "" && err != nil:
			t.Errorf("case %d: err = %v, want none", i, err)
		case c.field != "" && (!errors.As(err, &limit) || limit.Field != c.field):
			t.Errorf("case %d: err = %v, want a limit error on %s", i, err, c.field)
		}
	}
	r.settings.set(`{"max_per_list":2}`, nil)
	err := r.svc.ValidateScopeNames(ctx, a, []string{"a1.example.com", "a2.example.com", "a3.example.com"})
	if err == nil || err.Error() != "items: at most 2 domains (got 3)" {
		t.Fatalf("message = %v", err)
	}
}

// The feature switch: off empties every file at once; on
// again keeps a name in review closed, brings an unchanged address back the
// normal way (two answers and the gap), sends a changed one to review and
// publishes a pending name's first answer.
func TestDNSSettingsChangedSwitchesEveryName(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	for _, n := range []string{"same.example.com", "moved.example.com", "review.example.com", "new.example.com"} {
		r.store.setRefs(append(r.mustRefs(), dnsRef(dnsTestListA, n))...)
	}
	r.store.put(dnsOKRow("same.example.com", 1, "203.0.113.10"))
	r.store.put(dnsOKRow("moved.example.com", 1, "203.0.113.20"))
	review := dnsOKRow("review.example.com", 2)
	review.Status, review.ReviewReason, review.LastApplied = model.DNSStatusNeedsReview, model.DNSReviewCNAMEChanged, []string{"203.0.113.30"}
	r.store.put(review)
	r.store.put(model.DNSEntryState{Hostname: "new.example.com", Status: model.DNSStatusPending})
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	on := model.DefaultDNSEntrySettings()
	off := on
	off.Enabled = false

	r.settings.set(`{"enabled":false}`, nil)
	r.svc.SettingsChanged(ctx, on, off)
	select {
	case <-r.svc.Wake():
	default:
		t.Fatal("switching off must wake the scheduler to apply at once")
	}
	for _, n := range []string{"same.example.com", "moved.example.com"} {
		if got, _ := r.nginx.file(dnsACL(dnsTestListA), n); len(got) != 0 {
			t.Fatalf("%s file = %v, want empty while off", n, got)
		}
	}
	r.tick(t) // applies the emptied files

	r.lookup.set("same.example.com", "203.0.113.10")
	r.lookup.set("moved.example.com", "203.0.113.21")
	r.lookup.set("review.example.com", "203.0.113.30")
	r.lookup.set("new.example.com", "203.0.113.40")
	r.settings.set(`{"enabled":true}`, nil)
	r.svc.SettingsChanged(ctx, off, on)
	r.clock.Advance(time.Minute)
	r.tick(t)

	file := func(n string) []string { got, _ := r.nginx.file(dnsACL(dnsTestListA), n); return got }
	if got := file("new.example.com"); !dnsEqual(got, []string{"203.0.113.40"}) {
		t.Errorf("pending name: file = %v, want its first answer published", got)
	}
	if got := file("same.example.com"); len(got) != 0 {
		t.Errorf("unchanged name: file = %v, want it to wait for a second answer and the gap", got)
	}
	if st, _ := r.store.row("moved.example.com"); st.Status != model.DNSStatusNeedsReview || st.ReviewReason != model.DNSReviewReappeared {
		t.Errorf("changed name: row = %+v, want review (reappeared)", st)
	}
	if st, _ := r.store.row("review.example.com"); st.Status != model.DNSStatusNeedsReview || len(file("review.example.com")) != 0 {
		t.Errorf("name in review: row = %+v, want it to stay closed", st)
	}

	r.clock.Advance(6 * time.Minute)
	r.tick(t)
	if got := file("same.example.com"); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Errorf("unchanged name after the gap: file = %v, want it back", got)
	}
}

func (r *dnsTestRig) mustRefs() []model.DNSReference {
	refs, _ := r.store.ListReferences(context.Background())
	return refs
}
