package dnsentry

import (
	"reflect"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// The backup record merge: it never publishes, a review in
// either survives, and the database's own pin and last addresses win.
func TestMergeRestoredIntoNoRow(t *testing.T) {
	plain, ok := MergeRestored(nil, model.DNSEntryStateExport{Hostname: "Partner.Example.COM."}, docsAsPublic(), at(0))
	if !ok || plain.Hostname != host || plain.Status != model.DNSStatusPending || plain.EmptyCause != "" ||
		len(plain.Published) != 0 || plain.Generation != 0 {
		t.Fatalf("plain record: %+v %v", plain, ok)
	}

	review, ok := MergeRestored(nil, model.DNSEntryStateExport{
		Hostname: host, NeedsReview: true, ReviewReason: "cname_changed", CanonicalName: "Edge.DDNS.Example.NET.",
		LastApplied: []string{"203.0.113.11", "::ffff:203.0.113.10", "10.0.0.5", "not-an-address", "203.0.113.11"},
	}, docsAsPublic(), at(0))
	if !ok || review.Status != model.DNSStatusNeedsReview || review.ReviewReason != model.DNSReviewCNAMEChanged ||
		review.CanonicalName != "edge.ddns.example.net" || review.EmptyCause != model.DNSEmptyRestored || len(review.Published) != 0 ||
		!reflect.DeepEqual(review.LastApplied, []string{"203.0.113.10", "203.0.113.11"}) {
		t.Fatalf("record in review: %+v; want closed for review, pin normalized, only allowed addresses kept", review)
	}

	// The production policy refuses documentation addresses, so nothing of
	// this last_applied is kept.
	if def, _ := MergeRestored(nil, model.DNSEntryStateExport{Hostname: host, LastApplied: []string{"203.0.113.10"}}, nil, at(0)); len(def.LastApplied) != 0 || def.EmptyCause != "" {
		t.Fatalf("default policy: %+v", def)
	}

	for _, rec := range []model.DNSEntryStateExport{
		{Hostname: host, NeedsReview: true, ReviewReason: "policy_changed"}, // a reason this version does not know
		{Hostname: host, NeedsReview: true},
		{Hostname: host, ReviewReason: "unstable"}, // a reason without the flag
	} {
		if st, _ := MergeRestored(nil, rec, docsAsPublic(), at(0)); st.Status != model.DNSStatusPending || st.ReviewReason != "" {
			t.Errorf("record %+v: status %q reason %q; want not in review", rec, st.Status, st.ReviewReason)
		}
	}

	for _, pin := range []string{"_edge.example.net", "edge example.net", ""} {
		if st, _ := MergeRestored(nil, model.DNSEntryStateExport{Hostname: host, CanonicalName: pin}, docsAsPublic(), at(0)); st.CanonicalName != "" {
			t.Errorf("pin %q kept as %q", pin, st.CanonicalName)
		}
	}

	for _, name := range []string{"", "203.0.113.10", "partner", "bad name.example.com", "nas.local"} {
		if _, ok := MergeRestored(nil, model.DNSEntryStateExport{Hostname: name}, docsAsPublic(), at(0)); ok {
			t.Errorf("hostname %q accepted", name)
		}
	}
}

func TestMergeRestoredIntoARow(t *testing.T) {
	merge := func(existing model.DNSEntryState, rec model.DNSEntryStateExport) model.DNSEntryState {
		t.Helper()
		before := copyRow(existing)
		rec.Hostname = host
		st, ok := MergeRestored(&existing, rec, docsAsPublic(), at(0))
		if !ok {
			t.Fatalf("record %+v refused", rec)
		}
		if !reflect.DeepEqual(existing, before) {
			t.Fatalf("the merge changed the row it was given")
		}
		return st
	}

	// A published row the backup marks for review is closed (revoked).
	live := published("203.0.113.10")
	closed := merge(live, model.DNSEntryStateExport{NeedsReview: true, ReviewReason: "reappeared", LastApplied: []string{"203.0.113.20"}})
	if closed.Status != model.DNSStatusNeedsReview || closed.ReviewReason != model.DNSReviewReappeared || len(closed.Published) != 0 ||
		closed.Generation != live.Generation+1 || closed.RevokePendingSince == nil || !closed.RevokePendingSince.Equal(t0) ||
		!sameList(closed.LastApplied, "203.0.113.10") {
		t.Fatalf("live row, record in review: %+v; want closed, revoked, the row's last addresses kept", closed)
	}

	// A record not in review changes nothing on a published row.
	if kept := merge(live, model.DNSEntryStateExport{CanonicalName: "other.example.net", LastApplied: []string{"203.0.113.20"}}); !reflect.DeepEqual(kept, live) {
		t.Fatalf("live row, plain record: %+v; want unchanged", kept)
	}

	// A row already in review keeps its reason.
	inReview, _ := EnterReview(live, model.DNSReviewCNAMEChanged, at(-time.Hour))
	if st := merge(inReview, model.DNSEntryStateExport{NeedsReview: true, ReviewReason: "unstable"}); st.ReviewReason != model.DNSReviewCNAMEChanged {
		t.Fatalf("row in review: reason %q", st.ReviewReason)
	}

	// The row's pin and last addresses win; the record's fill what is empty,
	// and an empty row then meets the escape rule ("restored").
	bare := pending()
	filled := merge(bare, model.DNSEntryStateExport{CanonicalName: "edge.example.net", LastApplied: []string{"203.0.113.20"}})
	if filled.CanonicalName != "edge.example.net" || !sameList(filled.LastApplied, "203.0.113.20") || filled.EmptyCause != model.DNSEmptyRestored ||
		filled.Status != model.DNSStatusPending || len(filled.Published) != 0 {
		t.Fatalf("empty row: %+v; want the record's pin and last addresses, cause restored, nothing published", filled)
	}
	other := v4Only("203.0.113.30")
	other.Canonical = "edge.example.net"
	if next, _ := decide(t, filled, other, input(at(time.Hour), nil)); next.ReviewReason != model.DNSReviewReappeared {
		t.Fatalf("a filled row answering a new address: %+v; want review", next)
	}
}

// A backup taken before the name went under review does not let it back in
// (a review in either survives): restoring it keeps the review,
// the pin and the row's last addresses, publishes nothing, and no later
// answer, not even the old address, reopens the name. Only a confirmation
// does.
func TestMergeRestoredKeepsAReviewTheBackupPredates(t *testing.T) {
	const old = "203.0.113.10"
	pinned := published(old)
	pinned.CanonicalName = "a.ddns.example.com"
	moved := v4Only("203.0.113.20")
	moved.Canonical = "b.ddns.example.com"
	review, _ := decide(t, pinned, moved, input(at(0), nil))
	if review.Status != model.DNSStatusNeedsReview || review.ReviewReason != model.DNSReviewCNAMEChanged {
		t.Fatalf("setup: %+v", review)
	}

	rec := model.DNSEntryStateExport{Hostname: host, CanonicalName: "a.ddns.example.com", LastApplied: []string{old}}
	merged, ok := MergeRestored(&review, rec, docsAsPublic(), at(time.Hour))
	if !ok {
		t.Fatal("record refused")
	}
	if merged.Status != model.DNSStatusNeedsReview || merged.ReviewReason != model.DNSReviewCNAMEChanged ||
		len(merged.Published) != 0 || merged.Generation != review.Generation || merged.CanonicalName != "a.ddns.example.com" {
		t.Fatalf("row in review, record from before the review: %+v; want still in review, nothing published", merged)
	}

	back := v4Only(old)
	back.Canonical = "a.ddns.example.com"
	for i, o := range []Observation{moved, back} {
		if next, _ := decide(t, merged, o, input(at(2*time.Hour), nil)); next.Status != model.DNSStatusNeedsReview || len(next.Published) != 0 {
			t.Fatalf("answer %d after the restore: %+v; want still closed until confirmed", i, next)
		}
	}
}

// The restored lists use the name, so a row that publishes
// nothing and has a last_applied comes back as a restored name whatever
// emptied it: used again (a check never takes it back as an operator's
// re-add) and through the empty-state escape rule. A row that never
// published has nothing to compare with and stays as it was.
func TestMergeRestoredReopensThroughTheEscapeRule(t *testing.T) {
	const old, other = "203.0.113.10", "203.0.113.20"
	unused, _ := MarkUnused(published(old), at(-time.Hour))
	off, _ := Disable(published(old), at(-time.Hour))
	lapsed, _ := Decide(published(old), seen(refusedObs("loopback"), notFoundObs()), input(at(-time.Hour), nil))
	replacing, _ := Decide(published(old), v4Only("203.0.113.30"), input(at(-time.Hour), nil))
	neverPublished, _ := MarkUnused(pending(), at(-time.Hour))
	cases := []struct {
		name     string
		row      model.DNSEntryState
		rec      model.DNSEntryStateExport
		restored bool
	}{
		{"unused", unused, model.DNSEntryStateExport{}, true},
		{"switched off", off, model.DNSEntryStateExport{}, true},
		{"lapsed", lapsed, model.DNSEntryStateExport{}, true},
		{"replacement in progress", replacing, model.DNSEntryStateExport{}, true},
		{"unused, last addresses from the record", neverPublished, model.DNSEntryStateExport{LastApplied: []string{old}}, true},
		{"never published", neverPublished, model.DNSEntryStateExport{}, false},
	}
	for _, tc := range cases {
		tc.rec.Hostname = host
		merged, ok := MergeRestored(&tc.row, tc.rec, docsAsPublic(), at(0))
		if !ok {
			t.Fatalf("%s: record refused", tc.name)
		}
		if !tc.restored {
			if !reflect.DeepEqual(merged, tc.row) {
				t.Errorf("%s: %+v; want the row unchanged", tc.name, merged)
			}
			continue
		}
		if merged.UnusedSince != nil || merged.EmptyCause != model.DNSEmptyRestored || merged.ReplaceOpen ||
			len(merged.Published) != 0 || merged.Disabled != tc.row.Disabled || !sameList(merged.LastApplied, old) {
			t.Errorf("%s: %+v; want used, restored, nothing published, the switch flag kept", tc.name, merged)
			continue
		}
		on := Enable(merged)
		if moved, _ := decide(t, on, v4Only(other), input(at(time.Hour), nil)); moved.Status != model.DNSStatusNeedsReview || moved.ReviewReason != model.DNSReviewReappeared {
			t.Errorf("%s: a new address after the restore: %+v; want review (reappeared)", tc.name, moved)
		}
		if back, _ := decide(t, on, v4Only(old), input(at(time.Hour), nil)); back.Status == model.DNSStatusNeedsReview || back.CandidateSeen != 1 {
			t.Errorf("%s: the old address after the restore: %+v; want the normal path (seen once)", tc.name, back)
		}
	}
}
