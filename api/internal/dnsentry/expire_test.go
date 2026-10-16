package dnsentry

import (
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// At boot a name whose answers are older than the grace loses what it
// published, as the checks the API missed would have taken it.
func TestExpireStale(t *testing.T) {
	const grace = 24 * time.Hour
	expire := func(t *testing.T, prev model.DNSEntryState, now time.Time) (model.DNSEntryState, Effects) {
		t.Helper()
		return run(t, prev, now, func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return ExpireStale(p, now, grace) })
	}

	within, eff := expire(t, published("203.0.113.10", "2001:db8::10"), at(23*time.Hour))
	if !sameList(within.Published, "203.0.113.10", "2001:db8::10") || within.Generation != 3 || len(eff.Revoked) != 0 {
		t.Fatalf("within the grace: %+v; want unchanged", within)
	}

	// IPv6 answered recently; IPv4 last answered 30 hours ago.
	prev := published("203.0.113.10", "2001:db8::10")
	fresh := at(29 * time.Hour)
	prev.V6.AnswerAt = &fresh
	half, eff := expire(t, prev, at(30*time.Hour))
	if !sameList(half.Published, "2001:db8::10") || !sameList(eff.Revoked, "203.0.113.10") || eff.Recorded ||
		half.V4.State != "transient" || half.V6.State != "ok" || half.Status != model.DNSStatusOK || half.EmptyCause != "" {
		t.Fatalf("one family past the grace: %+v", half)
	}

	// A family that was failing keeps its code.
	stale := published("203.0.113.10")
	stale.Status, stale.V4.State, stale.V4.Code = model.DNSStatusStale, "transient", "timeout"
	all, _ := expire(t, stale, at(30*time.Hour))
	if len(all.Published) != 0 || all.EmptyCause != model.DNSEmptyLapse || all.Status != model.DNSStatusExpired || all.V4.Code != "timeout" {
		t.Fatalf("everything past the grace: %+v; want emptied, lapse, expired, code kept", all)
	}
	// The next answer meets the empty-state escape rule.
	if next, _ := decide(t, all, v4Only("203.0.113.20"), input(at(31*time.Hour), nil)); next.ReviewReason != model.DNSReviewReappeared {
		t.Fatalf("a new address after the boot expiry: %+v; want review", next)
	}
	if next, _ := decide(t, all, v4Only("203.0.113.10"), input(at(31*time.Hour), nil)); next.Status == model.DNSStatusNeedsReview {
		t.Fatalf("the old address after the boot expiry went under review: %+v", next)
	}

	// No definitive answer ever: nothing to keep it by.
	never := published("203.0.113.10")
	never.V4.AnswerAt = nil
	if gone, _ := expire(t, never, at(0)); len(gone.Published) != 0 {
		t.Fatalf("published without an answer time: %+v", gone)
	}

	// Nothing published: nothing to do.
	if same, _ := expire(t, pending(), at(100*time.Hour)); same.Status != model.DNSStatusPending || same.Generation != 0 {
		t.Fatalf("pending name: %+v", same)
	}
}
