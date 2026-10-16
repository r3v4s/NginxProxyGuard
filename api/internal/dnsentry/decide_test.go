package dnsentry

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

const host = "partner.example.com"

var t0 = time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)

func at(d time.Duration) time.Time { return t0.Add(d) }

func okObs(ss ...string) FamilyObs     { return FamilyObs{Outcome: "ok", Addrs: ss} }
func notFoundObs() FamilyObs           { return FamilyObs{Outcome: "notfound", Code: "not_found"} }
func failingObs(code string) FamilyObs { return FamilyObs{Outcome: "transient", Code: code} }
func refusedObs(code string) FamilyObs { return FamilyObs{Outcome: "rejected", Code: code} }

// seen is an answer whose two CNAME lookups agreed on the name itself.
func seen(v4, v6 FamilyObs) Observation {
	return Observation{V4: v4, V6: v6, CNAMEOK: true, Canonical: host}
}

// v4Only is seen with addresses for IPv4 and none for IPv6.
func v4Only(ss ...string) Observation { return seen(okObs(ss...), notFoundObs()) }

// undecided is o with the CNAME check undecided.
func undecided(o Observation) Observation {
	o.CNAMEOK, o.Canonical = false, ""
	return o
}

func input(now time.Time, lastReload *time.Time) Input {
	return Input{Now: now, Settings: model.DefaultDNSEntrySettings(), LastDNSReloadAt: lastReload}
}

// published is an ok row that publishes addrs (nginx has them: applied),
// pinned to the name itself, last answered a minute before t0. A family it
// has no address of has answered "not found" for a long time.
func published(ss ...string) model.DNSEntryState {
	answered := at(-time.Minute)
	addrs := sortUnique(ss)
	st := model.DNSEntryState{
		Hostname: host, Status: model.DNSStatusOK,
		Published: addrs, LastApplied: addrs, Candidate: addrs,
		Generation: 3, AppliedGeneration: 3,
		CanonicalName: host, CanonicalSeen: host,
		LastCheckedAt: &answered,
	}
	st.V4 = familyState(familyOf(addrs, true), answered)
	st.V6 = familyState(familyOf(addrs, false), answered)
	return st
}

func familyState(addrs []string, answered time.Time) model.DNSFamilyState {
	if len(addrs) == 0 {
		return model.DNSFamilyState{State: "notfound", Code: "not_found", AnswerAt: &answered, NotFound: 9}
	}
	return model.DNSFamilyState{State: "ok", Observed: addrs, AnswerAt: &answered}
}

func pending() model.DNSEntryState {
	return model.DNSEntryState{Hostname: host, Status: model.DNSStatusPending}
}

// run calls one transition and checks what every transition keeps
// (every entry point of the state machine): the row it was given is left as
// it was; Published is sorted and unique; Generation moves by one, with
// LastChangedAt, exactly when Published changes as a set; a removal sets
// RevokePendingSince when unset and an earlier one stays; a non-empty
// Published is LastApplied; Effects name what left and what came and the two
// statuses; Recorded is true exactly when the call appended now to
// ChangeTimes.
func run(t *testing.T, prev model.DNSEntryState, now time.Time, fn func(model.DNSEntryState) (model.DNSEntryState, Effects)) (model.DNSEntryState, Effects) {
	t.Helper()
	before := copyRow(prev)
	next, eff := fn(prev)
	if !reflect.DeepEqual(prev, before) {
		t.Fatalf("the transition changed the row it was given:\n got %+v\nwant %+v", prev, before)
	}
	if !sort.StringsAreSorted(next.Published) || len(sortUnique(next.Published)) != len(next.Published) {
		t.Errorf("Published %v is not sorted and unique", next.Published)
	}
	removed, added := setMinus(prev.Published, next.Published), setMinus(next.Published, prev.Published)
	if len(removed)+len(added) > 0 {
		if next.Generation != prev.Generation+1 || next.LastChangedAt == nil || !next.LastChangedAt.Equal(now) {
			t.Errorf("Published %v -> %v: generation %d -> %d, last changed %v; want +1 at %v",
				prev.Published, next.Published, prev.Generation, next.Generation, next.LastChangedAt, now)
		}
	} else if next.Generation != prev.Generation || !reflect.DeepEqual(next.LastChangedAt, prev.LastChangedAt) {
		t.Errorf("Published unchanged, yet generation %d -> %d and last changed %v -> %v",
			prev.Generation, next.Generation, prev.LastChangedAt, next.LastChangedAt)
	}
	wantRevoke := prev.RevokePendingSince
	if len(removed) > 0 && wantRevoke == nil {
		wantRevoke = &now
	}
	if !reflect.DeepEqual(next.RevokePendingSince, wantRevoke) {
		t.Errorf("RevokePendingSince = %v, want %v (removed %v)", next.RevokePendingSince, wantRevoke, removed)
	}
	if len(next.Published) > 0 && !reflect.DeepEqual(next.LastApplied, next.Published) {
		t.Errorf("LastApplied = %v, want the published %v", next.LastApplied, next.Published)
	}
	if !reflect.DeepEqual(setOf(eff.Revoked), setOf(removed)) || !reflect.DeepEqual(setOf(eff.Added), setOf(added)) {
		t.Errorf("Effects revoked %v added %v, want %v and %v", eff.Revoked, eff.Added, removed, added)
	}
	if eff.FromStatus != prev.Status || eff.ToStatus != next.Status {
		t.Errorf("Effects statuses %q -> %q, want %q -> %q", eff.FromStatus, eff.ToStatus, prev.Status, next.Status)
	}
	appended := len(next.ChangeTimes) > 0 && next.ChangeTimes[len(next.ChangeTimes)-1].Equal(now) && !hasTime(prev.ChangeTimes, now)
	if eff.Recorded != appended {
		t.Errorf("Effects.Recorded = %v, but ChangeTimes %v -> %v", eff.Recorded, prev.ChangeTimes, next.ChangeTimes)
	}
	return next, eff
}

func decide(t *testing.T, prev model.DNSEntryState, obs Observation, in Input) (model.DNSEntryState, Effects) {
	t.Helper()
	return run(t, prev, in.Now, func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return Decide(p, obs, in) })
}

func copyRow(s model.DNSEntryState) model.DNSEntryState {
	strs := func(v []string) []string {
		if v == nil {
			return nil
		}
		return append([]string{}, v...)
	}
	tm := func(v *time.Time) *time.Time {
		if v == nil {
			return nil
		}
		c := *v
		return &c
	}
	fam := func(f model.DNSFamilyState) model.DNSFamilyState {
		f.Observed, f.AnswerAt = strs(f.Observed), tm(f.AnswerAt)
		return f
	}
	c := s
	c.UnusedSince, c.RevokePendingSince = tm(s.UnusedSince), tm(s.RevokePendingSince)
	c.LastCheckedAt, c.LastChangedAt = tm(s.LastCheckedAt), tm(s.LastChangedAt)
	c.Published, c.LastApplied, c.Candidate, c.Warnings = strs(s.Published), strs(s.LastApplied), strs(s.Candidate), strs(s.Warnings)
	c.V4, c.V6 = fam(s.V4), fam(s.V6)
	if s.ChangeTimes != nil {
		c.ChangeTimes = append([]time.Time{}, s.ChangeTimes...)
	}
	return c
}

func setOf(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func setMinus(a, b []string) []string {
	drop := setOf(b)
	var out []string
	for _, s := range a {
		if !drop[s] {
			out = append(out, s)
		}
	}
	return out
}

func hasTime(ts []time.Time, want time.Time) bool {
	for _, t := range ts {
		if t.Equal(want) {
			return true
		}
	}
	return false
}

func sameList(got []string, want ...string) bool {
	return reflect.DeepEqual(setOf(got), setOf(want)) && len(got) == len(want)
}

// A family that fails for a moment keeps what it published: no change, no
// count against the budget.
func TestDecideKeepsAFamilyThroughATransientError(t *testing.T) {
	for _, code := range []string{"timeout", "refused", "servfail", "network"} {
		prev := published("203.0.113.10", "2001:db8::10")
		next, eff := decide(t, prev, seen(okObs("203.0.113.10"), failingObs(code)), input(at(0), nil))
		if !sameList(next.Published, "203.0.113.10", "2001:db8::10") || eff.Recorded || next.Status != model.DNSStatusStale {
			t.Errorf("%s: published %v, recorded %v, status %q; want both kept, nothing recorded, stale", code, next.Published, eff.Recorded, next.Status)
		}
		if next.V6.State != "transient" || next.V6.Code != code || !next.V6.AnswerAt.Equal(at(-time.Minute)) || !sameList(next.V6.Observed, "2001:db8::10") {
			t.Errorf("%s: v6 = %+v, want transient with the code, the last answer time and observation kept", code, next.V6)
		}
	}
}

func TestDecideIgnoresAnswerOrder(t *testing.T) {
	prev := published("203.0.113.10", "203.0.113.11")
	next, eff := decide(t, prev, v4Only("203.0.113.11", "203.0.113.10"), input(at(0), nil))
	if next.Generation != prev.Generation || eff.Recorded || next.Status != model.DNSStatusOK {
		t.Fatalf("order-only change: generation %d, recorded %v, status %q", next.Generation, eff.Recorded, next.Status)
	}
}

// One "not found" keeps the family; the second (not_found_checks 2)
// empties it.
func TestDecideDebouncesNotFound(t *testing.T) {
	prev := published("203.0.113.10")
	first, _ := decide(t, prev, seen(notFoundObs(), notFoundObs()), input(at(0), nil))
	if !sameList(first.Published, "203.0.113.10") || first.V4.NotFound != 1 || first.V4.State != "notfound" {
		t.Fatalf("first not found: published %v, v4 %+v; want kept with the count at 1", first.Published, first.V4)
	}
	second, eff := decide(t, first, seen(notFoundObs(), notFoundObs()), input(at(time.Minute), nil))
	if len(second.Published) != 0 || second.EmptyCause != model.DNSEmptyLapse || second.Status != model.DNSStatusNotFound || !eff.Recorded {
		t.Fatalf("second not found: %+v; want emptied, lapse, not_found, recorded", second)
	}
	// The count stops at notFoundCap: the column is a smallint.
	capped := second
	capped.V4.NotFound, capped.V6.NotFound = notFoundCap, notFoundCap
	if next, _ := decide(t, capped, seen(notFoundObs(), notFoundObs()), input(at(2*time.Minute), nil)); next.V4.NotFound != notFoundCap || next.V6.NotFound != notFoundCap {
		t.Fatalf("not found at the cap: %d/%d, want both %d", next.V4.NotFound, next.V6.NotFound, notFoundCap)
	}
}

// A failing family keeps its addresses for the grace (24 h) after its last
// definitive answer, then loses them.
func TestDecideEmptiesAFamilyAfterTheGrace(t *testing.T) {
	prev := published("203.0.113.10")
	stale, _ := decide(t, prev, seen(failingObs("timeout"), notFoundObs()), input(at(23*time.Hour), nil))
	if !sameList(stale.Published, "203.0.113.10") || stale.Status != model.DNSStatusStale {
		t.Fatalf("within the grace: published %v status %q", stale.Published, stale.Status)
	}
	gone, eff := decide(t, stale, seen(failingObs("timeout"), notFoundObs()), input(at(25*time.Hour), nil))
	if len(gone.Published) != 0 || gone.Status != model.DNSStatusExpired || gone.EmptyCause != model.DNSEmptyLapse || !eff.Recorded {
		t.Fatalf("past the grace: %+v; want emptied, expired, lapse", gone)
	}
}

func TestDecideEmptiesARejectedFamilyAtOnce(t *testing.T) {
	next, _ := decide(t, published("203.0.113.10"), seen(refusedObs("loopback"), notFoundObs()), input(at(0), nil))
	if len(next.Published) != 0 || next.Status != model.DNSStatusRejected || next.EmptyCause != model.DNSEmptyLapse ||
		next.V4.State != "rejected" || next.V4.Code != "loopback" || next.V4.Observed != nil {
		t.Fatalf("rejected: %+v", next)
	}
}

// A → B: A leaves at the first check, B comes after a second observation and
// the reload gap, and the whole replacement counts once.
func TestDecideReplacementRevokesAtOnceAndCountsOnce(t *testing.T) {
	prev := published("203.0.113.10")
	tick1, eff := decide(t, prev, v4Only("203.0.113.20"), input(at(0), nil))
	if len(tick1.Published) != 0 || tick1.EmptyCause != model.DNSEmptyReplace || !tick1.ReplaceOpen || !eff.Recorded ||
		tick1.CandidateSeen != 1 || tick1.Status != model.DNSStatusOK {
		t.Fatalf("tick 1: %+v; want A revoked, replace, open, recorded, B seen once, still ok", tick1)
	}
	reload := at(5 * time.Second) // the reload that took the revocation
	tick2, eff := decide(t, tick1, v4Only("203.0.113.20"), input(at(time.Minute), &reload))
	if len(tick2.Published) != 0 || tick2.CandidateSeen != 2 || eff.Recorded {
		t.Fatalf("tick 2: %+v; want B seen twice but waiting for the gap", tick2)
	}
	tick3, eff := decide(t, tick2, v4Only("203.0.113.20"), input(reload.Add(5*time.Minute), &reload))
	if !sameList(tick3.Published, "203.0.113.20") || eff.Recorded || tick3.ReplaceOpen || tick3.EmptyCause != "" {
		t.Fatalf("tick 3: %+v; want B published, not recorded again, replacement closed", tick3)
	}
	if len(tick3.ChangeTimes) != 1 || !tick3.ChangeTimes[0].Equal(t0) {
		t.Fatalf("change times = %v, want the one replacement", tick3.ChangeTimes)
	}
}

// A check on which a family fails within the grace, or answers "not found"
// fewer times than not_found_checks, does not end a replacement in progress:
// that family's part of the answer is only what it already publishes, which
// hides the address the replacement waits for. The replacement stays open and
// counts once, the name shows as ok or stale (never not_found, never review),
// and the new address still needs two sightings after that check, and the
// reload gap.
func TestDecideKeepsAReplacementOpenThroughAFailedCheck(t *testing.T) {
	const a, b, x = "203.0.113.10", "203.0.113.20", "203.0.113.11"
	cases := []struct {
		name       string
		from, to   []string    // published before, and the new answer
		kept       []string    // what stays published while the replacement waits
		cause      string      // EmptyCause while the replacement waits
		failed     Observation // the check between the first sighting and the next
		failStatus string
	}{
		{"a timeout", []string{a}, []string{b}, nil, model.DNSEmptyReplace,
			seen(failingObs("timeout"), notFoundObs()), model.DNSStatusStale},
		{"one not found", []string{a}, []string{b}, nil, model.DNSEmptyReplace,
			seen(notFoundObs(), notFoundObs()), model.DNSStatusOK},
		{"part of the addresses and a timeout", []string{a, x}, []string{a, b}, []string{a}, "",
			seen(failingObs("timeout"), notFoundObs()), model.DNSStatusStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inProgress := func(check string, s model.DNSEntryState, eff Effects) {
				t.Helper()
				switch s.Status {
				case model.DNSStatusNotFound, model.DNSStatusExpired, model.DNSStatusRejected, model.DNSStatusNeedsReview:
					t.Fatalf("%s: status %q; want the replacement shown in progress: %+v", check, s.Status, s)
				}
				if eff.EnteredReview != "" {
					t.Fatalf("%s: entered review %q", check, eff.EnteredReview)
				}
			}
			first, eff := decide(t, published(tc.from...), v4Only(tc.to...), input(at(0), nil))
			inProgress("first sighting", first, eff)
			if !first.ReplaceOpen || !eff.Recorded || !sameList(first.Published, tc.kept...) {
				t.Fatalf("first sighting: %+v; want the replacement open and recorded", first)
			}
			reload := at(5 * time.Second) // the reload that took the revocation
			failed, eff := decide(t, first, tc.failed, input(at(time.Minute), &reload))
			inProgress("failed check", failed, eff)
			if failed.Status != tc.failStatus || !failed.ReplaceOpen || failed.EmptyCause != tc.cause ||
				!sameList(failed.Published, tc.kept...) || eff.Recorded || failed.CandidateSeen != 0 {
				t.Fatalf("failed check: %+v; want %s, the replacement still open (empty cause %q), %v kept, nothing recorded, no sighting",
					failed, tc.failStatus, tc.cause, tc.kept)
			}
			// The gap has passed by the next sighting, which counts as the first.
			next, eff := decide(t, failed, v4Only(tc.to...), input(reload.Add(5*time.Minute), &reload))
			inProgress("next sighting", next, eff)
			if !sameList(next.Published, tc.kept...) || next.CandidateSeen != 1 {
				t.Fatalf("next sighting: %+v; want seen once, still waiting", next)
			}
			done, eff := decide(t, next, v4Only(tc.to...), input(reload.Add(6*time.Minute), &reload))
			inProgress("second sighting", done, eff)
			if !sameList(done.Published, tc.to...) || done.ReplaceOpen || done.EmptyCause != "" || eff.Recorded || done.Status != model.DNSStatusOK {
				t.Fatalf("second sighting: %+v; want the new addresses published, the replacement closed, not recorded again", done)
			}
			if len(done.ChangeTimes) != 1 || !done.ChangeTimes[0].Equal(t0) {
				t.Fatalf("change times = %v, want the one replacement", done.ChangeTimes)
			}
		})
	}
}

// A family that really ends does end a replacement in progress: "not found"
// as often as not_found_checks, or failing past the grace. The name is then
// empty because of its answers ("lapse"), so an address it never published
// needs review.
func TestDecideReplacementLapsesWhenAFamilyEnds(t *testing.T) {
	const a, b, c = "203.0.113.10", "203.0.113.20", "203.0.113.30"
	cases := []struct {
		name   string
		end    func(t *testing.T, s model.DNSEntryState) model.DNSEntryState
		status string
	}{
		{"not found at the threshold", func(t *testing.T, s model.DNSEntryState) model.DNSEntryState {
			// The first "not found" is debounced; the second reaches
			// not_found_checks (2).
			for i := 1; i <= 2; i++ {
				s, _ = decide(t, s, seen(notFoundObs(), notFoundObs()), input(at(time.Duration(i)*time.Minute), nil))
			}
			return s
		}, model.DNSStatusNotFound},
		{"past the grace", func(t *testing.T, s model.DNSEntryState) model.DNSEntryState {
			s, _ = decide(t, s, seen(failingObs("timeout"), notFoundObs()), input(at(25*time.Hour), nil))
			return s
		}, model.DNSStatusExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replacing, _ := decide(t, published(a), v4Only(b), input(at(0), nil))
			ended := tc.end(t, replacing)
			if len(ended.Published) != 0 || ended.EmptyCause != model.DNSEmptyLapse || ended.ReplaceOpen || ended.Status != tc.status {
				t.Fatalf("ended: %+v; want nothing published, lapse, the replacement closed, %s", ended, tc.status)
			}
			next, eff := decide(t, ended, v4Only(c), input(at(26*time.Hour), nil))
			if next.Status != model.DNSStatusNeedsReview || next.ReviewReason != model.DNSReviewReappeared || eff.EnteredReview != model.DNSReviewReappeared {
				t.Fatalf("a new address afterwards: %+v; want review (reappeared)", next)
			}
		})
	}
}

// Outside a replacement a failing family changes nothing: a name that lapsed
// keeps its status and stays empty; it is not shown as stale.
func TestDecideKeepsALapsedNameThroughAFailedCheck(t *testing.T) {
	lapsed := published("203.0.113.10")
	for i := 0; i < 2; i++ {
		lapsed, _ = decide(t, lapsed, seen(notFoundObs(), notFoundObs()), input(at(time.Duration(i)*time.Minute), nil))
	}
	if lapsed.Status != model.DNSStatusNotFound || lapsed.EmptyCause != model.DNSEmptyLapse {
		t.Fatalf("setup: %+v", lapsed)
	}
	next, _ := decide(t, lapsed, seen(failingObs("timeout"), notFoundObs()), input(at(2*time.Minute), nil))
	if next.Status != model.DNSStatusNotFound || next.EmptyCause != model.DNSEmptyLapse || next.ReplaceOpen || len(next.Published) != 0 {
		t.Fatalf("a lapsed name and a timeout: %+v; want still not_found and lapse", next)
	}
}

// An added address needs the same candidate twice; after a restart the first
// apply needs no gap.
func TestDecideAdditionNeedsTwoObservations(t *testing.T) {
	prev := published("203.0.113.10")
	once, _ := decide(t, prev, v4Only("203.0.113.10", "203.0.113.11"), input(at(0), nil))
	if !sameList(once.Published, "203.0.113.10") || once.CandidateSeen != 1 {
		t.Fatalf("first sight: %+v", once)
	}
	twice, eff := decide(t, once, v4Only("203.0.113.10", "203.0.113.11"), input(at(time.Minute), nil))
	if !sameList(twice.Published, "203.0.113.10", "203.0.113.11") || !eff.Recorded || len(twice.ChangeTimes) != 1 {
		t.Fatalf("second sight: %+v; want both published and one change recorded", twice)
	}
}

// The empty-state escape rule: a name that had addresses and
// went empty because of the answers, the switch or a restore comes back on
// the normal path only to addresses it published before; anything else
// needs review. A replacement in progress is not covered.
func TestDecideEmptyStateEscapeRule(t *testing.T) {
	const old, other = "203.0.113.10", "203.0.113.20"
	cases := []struct {
		name  string
		empty func(t *testing.T) model.DNSEntryState
		rule  bool
	}{
		{"not found", func(t *testing.T) model.DNSEntryState {
			n, _ := decide(t, published(old), seen(notFoundObs(), notFoundObs()), input(at(0), nil))
			n, _ = decide(t, n, seen(notFoundObs(), notFoundObs()), input(at(time.Minute), nil))
			return n
		}, true},
		{"parked on 127.0.0.1", func(t *testing.T) model.DNSEntryState {
			n, _ := decide(t, published(old), seen(refusedObs("loopback"), notFoundObs()), input(at(0), nil))
			return n
		}, true},
		{"past the grace", func(t *testing.T) model.DNSEntryState {
			n, _ := decide(t, published(old), seen(failingObs("servfail"), notFoundObs()), input(at(25*time.Hour), nil))
			return n
		}, true},
		{"switched off and on", func(t *testing.T) model.DNSEntryState {
			n, _ := run(t, published(old), at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return Disable(p, at(0)) })
			return Enable(n)
		}, true},
		{"restored", func(t *testing.T) model.DNSEntryState {
			n, ok := MergeRestored(nil, model.DNSEntryStateExport{Hostname: host, LastApplied: []string{old}}, docsAsPublic(), at(0))
			if !ok {
				t.Fatal("restore record refused")
			}
			return n
		}, true},
		{"replacement in progress", func(t *testing.T) model.DNSEntryState {
			n, _ := decide(t, published(old), v4Only("203.0.113.30"), input(at(0), nil))
			return n
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			empty := tc.empty(t)
			if len(empty.Published) != 0 {
				t.Fatalf("setup published %v", empty.Published)
			}
			now := at(26 * time.Hour)
			back, _ := decide(t, empty, v4Only(old), input(now, nil))
			if back.Status == model.DNSStatusNeedsReview || back.CandidateSeen != 1 {
				t.Fatalf("same address: %+v; want the normal path (seen once, no review)", back)
			}
			again, _ := decide(t, back, v4Only(old), input(now.Add(time.Minute), nil))
			if !sameList(again.Published, old) || again.CanonicalName != host {
				t.Fatalf("same address seen twice: published %v, pin %q; want published and pinned", again.Published, again.CanonicalName)
			}
			moved, eff := decide(t, empty, v4Only(other), input(now, nil))
			if !tc.rule {
				if moved.Status == model.DNSStatusNeedsReview {
					t.Fatalf("a replacement in progress went under review: %+v", moved)
				}
				return
			}
			if moved.Status != model.DNSStatusNeedsReview || moved.ReviewReason != model.DNSReviewReappeared ||
				eff.EnteredReview != model.DNSReviewReappeared || len(moved.Published) != 0 || !sameList(moved.Candidate, other) {
				t.Fatalf("other address: %+v; want needs_review (reappeared) showing the new address", moved)
			}
		})
	}
}

// A new name publishes its first answer at once, outside the budget, and pins
// its CNAME target.
func TestDecidePendingPublishesItsFirstAnswer(t *testing.T) {
	justReloaded := at(-time.Second)
	obs := v4Only("203.0.113.10")
	obs.Canonical = "edge.ddns.example.net"
	next, eff := decide(t, pending(), obs, input(at(0), &justReloaded))
	if !sameList(next.Published, "203.0.113.10") || next.Status != model.DNSStatusOK || next.CanonicalName != "edge.ddns.example.net" || eff.Recorded {
		t.Fatalf("first answer: %+v", next)
	}
}

func TestDecidePendingWaitsForADeterminateCNAME(t *testing.T) {
	next, _ := decide(t, pending(), undecided(v4Only("203.0.113.10")), input(at(0), nil))
	if len(next.Published) != 0 || next.Status != model.DNSStatusPending || next.CanonicalName != "" || !sameList(next.Candidate, "203.0.113.10") {
		t.Fatalf("undecided CNAME: %+v; want still pending, showing the address", next)
	}
	nothing, _ := decide(t, pending(), seen(notFoundObs(), notFoundObs()), input(at(0), nil))
	if nothing.Status != model.DNSStatusPending || len(nothing.Published) != 0 {
		t.Fatalf("no address: %+v; want still pending", nothing)
	}
}

// While the two CNAME lookups disagree or one fails, additions wait and the
// answer is not counted; revocations go on.
func TestDecideHoldsAdditionsWhileTheCNAMEIsUndecided(t *testing.T) {
	oneFailed, _ := Observe(Answer{
		V4:         FamilyAnswer{Outcome: "ok", Addrs: addrs("203.0.113.20")},
		V6:         FamilyAnswer{Outcome: "notfound", Code: "not_found"},
		CNAMEAfter: host,
	}, docsAsPublic(), 4)
	for name, obs := range map[string]Observation{
		"answers disagree":  undecided(v4Only("203.0.113.20")),
		"one lookup failed": oneFailed,
	} {
		held, eff := decide(t, published("203.0.113.10"), obs, input(at(0), nil))
		if len(held.Published) != 0 || !eff.Recorded || held.CandidateSeen != 0 || !sameList(held.Candidate, "203.0.113.20") {
			t.Errorf("%s: %+v; want the old address revoked and the new one held, not counted", name, held)
		}
	}

	// The answer after the undecided one is the first that counts.
	held, _ := decide(t, published("203.0.113.10"), undecided(v4Only("203.0.113.20")), input(at(0), nil))
	first, _ := decide(t, held, v4Only("203.0.113.20"), input(at(time.Minute), nil))
	if len(first.Published) != 0 || first.CandidateSeen != 1 {
		t.Fatalf("after the undecided check: %+v; want seen once", first)
	}

	// A different candidate under an undecided CNAME starts over: it never
	// borrows the count of the one before.
	seenOnce, _ := decide(t, published("203.0.113.10"), v4Only("203.0.113.10", "203.0.113.11"), input(at(0), nil))
	switched, _ := decide(t, seenOnce, undecided(v4Only("203.0.113.10", "203.0.113.12")), input(at(time.Minute), nil))
	if switched.CandidateSeen != 0 {
		t.Fatalf("new candidate while undecided kept count %d", switched.CandidateSeen)
	}
	after, _ := decide(t, switched, v4Only("203.0.113.10", "203.0.113.12"), input(at(2*time.Minute), nil))
	if !sameList(after.Published, "203.0.113.10") || after.CandidateSeen != 1 {
		t.Fatalf("one determinate sight published %v (seen %d); want still waiting", after.Published, after.CandidateSeen)
	}
}

// Resolvers mix the case of a name (0x20) and answer "name.": not a change of
// the pinned target.
func TestDecideCNAMECaseAndDotAreNotAChange(t *testing.T) {
	obs, _ := Observe(Answer{
		V4:          FamilyAnswer{Outcome: "ok", Addrs: addrs("203.0.113.10")},
		V6:          FamilyAnswer{Outcome: "notfound", Code: "not_found"},
		CNAMEBefore: "PARTNER.Example.com.",
		CNAMEAfter:  "partner.example.COM",
	}, docsAsPublic(), 4)
	next, eff := decide(t, published("203.0.113.10"), obs, input(at(0), nil))
	if next.Status != model.DNSStatusOK || eff.EnteredReview != "" || next.Generation != 3 {
		t.Fatalf("case and dot: %+v", next)
	}
}

func TestDecideMovedCNAMEPutsTheNameUnderReview(t *testing.T) {
	prev := published("203.0.113.10")
	prev.ChangeTimes = []time.Time{at(-time.Hour)}
	obs := v4Only("203.0.113.10")
	obs.Canonical = "parking.example.net"
	next, eff := decide(t, prev, obs, input(at(0), nil))
	if next.Status != model.DNSStatusNeedsReview || next.ReviewReason != model.DNSReviewCNAMEChanged ||
		eff.EnteredReview != model.DNSReviewCNAMEChanged || len(next.Published) != 0 || eff.Recorded ||
		next.CanonicalName != host || next.CanonicalSeen != "parking.example.net" {
		t.Fatalf("moved CNAME: %+v; want closed for review, pin kept, the review not counted as a change", next)
	}
}

// More applied changes in 24 hours than max_changes_per_day (6) close the name
// (review reason "unstable"); older ones do not count.
func TestDecideTooManyChangesPutTheNameUnderReview(t *testing.T) {
	recent := func(n int) []time.Time {
		ts := []time.Time{at(-25 * time.Hour)}
		for i := 1; i <= n; i++ {
			ts = append(ts, at(-time.Duration(i)*time.Hour))
		}
		return ts
	}
	prev := published("203.0.113.10")
	prev.ChangeTimes = recent(6)
	next, eff := decide(t, prev, seen(refusedObs("private"), notFoundObs()), input(at(0), nil))
	if next.Status != model.DNSStatusNeedsReview || next.ReviewReason != model.DNSReviewUnstable || eff.EnteredReview != model.DNSReviewUnstable ||
		len(next.Published) != 0 || len(next.ChangeTimes) != 7 {
		t.Fatalf("7th change: %+v; want unstable with the 7 recent change times", next)
	}
	prev.ChangeTimes = recent(5)
	if next, _ := decide(t, prev, seen(refusedObs("private"), notFoundObs()), input(at(0), nil)); next.Status == model.DNSStatusNeedsReview {
		t.Fatalf("6th change went under review: %+v", next)
	}
}

// A name in review stays closed whatever it answers, also across the feature
// switch; its pin stays.
func TestDecideKeepsAReviewClosed(t *testing.T) {
	review := published("203.0.113.10")
	review.CanonicalName = "a.ddns.example.net"
	obs := v4Only("203.0.113.20")
	obs.Canonical = "b.ddns.example.net"
	review, _ = decide(t, review, obs, input(at(0), nil))
	if review.Status != model.DNSStatusNeedsReview {
		t.Fatalf("setup: %+v", review)
	}
	off, _ := run(t, review, at(time.Hour), func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return Disable(p, at(time.Hour)) })
	on := Enable(off)
	for i, o := range []Observation{obs, v4Only("203.0.113.10")} {
		next, _ := decide(t, on, o, input(at(2*time.Hour), nil))
		if next.Status != model.DNSStatusNeedsReview || len(next.Published) != 0 || next.CanonicalName != "a.ddns.example.net" {
			t.Fatalf("answer %d after off and on: %+v; want still closed with the old pin", i, next)
		}
	}
}

// Decide never publishes for a switched-off or unused name.
func TestDecideNeverPublishesASwitchedOffOrUnusedName(t *testing.T) {
	off, _ := Disable(pending(), at(0))
	unused, _ := MarkUnused(published("203.0.113.10"), at(0))
	for name, row := range map[string]model.DNSEntryState{"off": off, "unused": unused} {
		next, _ := decide(t, row, v4Only("203.0.113.10"), input(at(time.Hour), nil))
		if len(next.Published) != 0 {
			t.Errorf("%s: published %v", name, next.Published)
		}
	}
}

func TestDisableAndMarkUnused(t *testing.T) {
	prev := published("203.0.113.10")
	off, eff := run(t, prev, at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return Disable(p, at(0)) })
	if !off.Disabled || len(off.Published) != 0 || off.EmptyCause != model.DNSEmptyDisabled || off.Status != model.DNSStatusOK ||
		off.CanonicalName != host || !sameList(off.LastApplied, "203.0.113.10") || eff.Recorded {
		t.Fatalf("Disable: %+v", off)
	}
	on := Enable(off)
	flagOnly := on
	flagOnly.Disabled = true
	if on.Disabled || !reflect.DeepEqual(flagOnly, off) {
		t.Fatalf("Enable changed more than the flag: %+v", on)
	}
	if never, _ := Disable(pending(), at(0)); never.EmptyCause != "" {
		t.Fatalf("a name that never published got empty cause %q", never.EmptyCause)
	}

	unused, eff := run(t, prev, at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return MarkUnused(p, at(0)) })
	if unused.UnusedSince == nil || !unused.UnusedSince.Equal(t0) || len(unused.Published) != 0 || unused.EmptyCause != model.DNSEmptyUnused ||
		unused.Status != model.DNSStatusOK || !sameList(unused.LastApplied, "203.0.113.10") || eff.Recorded {
		t.Fatalf("MarkUnused: %+v", unused)
	}
	if later, _ := MarkUnused(unused, at(time.Hour)); !later.UnusedSince.Equal(t0) {
		t.Fatalf("a second MarkUnused moved UnusedSince to %v", later.UnusedSince)
	}
}

// An operator who adds a name back within seven days gets it at once
// (an operator action); a review and the pin stay.
func TestReactivate(t *testing.T) {
	react := func(t *testing.T, prev model.DNSEntryState, obs *Observation) model.DNSEntryState {
		t.Helper()
		next, _ := run(t, prev, at(time.Hour), func(p model.DNSEntryState) (model.DNSEntryState, Effects) {
			return Reactivate(p, obs, at(time.Hour))
		})
		if next.UnusedSince != nil {
			t.Fatalf("still unused: %+v", next)
		}
		return next
	}
	unused, _ := MarkUnused(published("203.0.113.10"), at(0))

	moved := v4Only("203.0.113.20")
	if next := react(t, unused, &moved); !sameList(next.Published, "203.0.113.20") || next.EmptyCause != "" || len(next.ChangeTimes) != 0 {
		t.Fatalf("re-added with an answer: %+v; want the new address at once, not recorded, no escape rule", next)
	}
	cname := v4Only("203.0.113.10")
	cname.Canonical = "parking.example.net"
	if next := react(t, unused, &cname); next.Status != model.DNSStatusNeedsReview || next.ReviewReason != model.DNSReviewCNAMEChanged {
		t.Fatalf("re-added with a moved CNAME: %+v", next)
	}
	later := react(t, unused, nil)
	if len(later.Published) != 0 || later.EmptyCause != model.DNSEmptyUnused {
		t.Fatalf("re-added without an answer: %+v; want nothing published, empty cause unused", later)
	}
	if next, _ := decide(t, later, v4Only("203.0.113.20"), input(at(2*time.Hour), nil)); next.Status == model.DNSStatusNeedsReview || next.CandidateSeen != 1 {
		t.Fatalf("next check after a re-add without an answer: %+v; want the normal path", next)
	}

	review, _ := EnterReview(published("203.0.113.10"), model.DNSReviewReappeared, at(0))
	review, _ = MarkUnused(review, at(0))
	if next := react(t, review, &moved); next.Status != model.DNSStatusNeedsReview || len(next.Published) != 0 ||
		next.CanonicalName != host || !sameList(next.Candidate, "203.0.113.20") {
		t.Fatalf("re-added in review: %+v; want still closed, pin kept, the answer shown", next)
	}

	offUnused, _ := Disable(unused, at(0))
	if next := react(t, offUnused, &moved); len(next.Published) != 0 {
		t.Fatalf("re-added while switched off published %v", next.Published)
	}
}

func TestFirstPublish(t *testing.T) {
	first := func(prev model.DNSEntryState, obs Observation) model.DNSEntryState {
		next, _ := run(t, prev, at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) { return FirstPublish(p, obs, at(0)) })
		return next
	}
	if next := first(pending(), v4Only("203.0.113.10")); !sameList(next.Published, "203.0.113.10") || next.CanonicalName != host || next.Status != model.DNSStatusOK {
		t.Fatalf("pending: %+v", next)
	}
	if next := first(pending(), undecided(v4Only("203.0.113.10"))); len(next.Published) != 0 || next.Status != model.DNSStatusPending {
		t.Fatalf("undecided CNAME: %+v", next)
	}
	off, _ := Disable(pending(), at(0))
	restored, _ := MergeRestored(nil, model.DNSEntryStateExport{Hostname: host, LastApplied: []string{"203.0.113.10"}}, docsAsPublic(), at(0))
	for name, row := range map[string]model.DNSEntryState{"ok": published("203.0.113.10"), "off": off, "restored": restored} {
		if next := first(row, v4Only("203.0.113.20")); !reflect.DeepEqual(next.Published, row.Published) || next.Generation != row.Generation {
			t.Errorf("%s: FirstPublish changed %v to %v", name, row.Published, next.Published)
		}
	}
}

func TestConfirm(t *testing.T) {
	review, _ := EnterReview(published("203.0.113.10"), model.DNSReviewCNAMEChanged, at(-time.Hour))
	review.CanonicalName = "a.ddns.example.net"
	review.ChangeTimes = []time.Time{at(-2 * time.Hour), at(-time.Hour)}
	review.V6.NotFound = 3
	obs := v4Only("203.0.113.20")
	obs.Canonical = "b.ddns.example.net"

	refused := []struct {
		name string
		prev model.DNSEntryState
		obs  Observation
		exp  []string
		want error
	}{
		{"not in review", published("203.0.113.10"), obs, []string{"203.0.113.20"}, ErrNotInReview},
		{"a family failed", review, seen(okObs("203.0.113.20"), failingObs("timeout")), []string{"203.0.113.20"}, ErrLookupUnavailable},
		{"CNAME undecided", review, undecided(obs), []string{"203.0.113.20"}, ErrLookupUnavailable},
		{"nothing usable", review, seen(refusedObs("private"), notFoundObs()), nil, ErrLookupUnavailable},
	}
	for _, tc := range refused {
		next, eff, err := Confirm(tc.prev, tc.obs, tc.exp, "", at(0))
		if !errors.Is(err, tc.want) || !reflect.DeepEqual(next, tc.prev) || eff.Recorded || len(eff.Added) != 0 {
			t.Errorf("%s: err %v, row changed %v; want %v and nothing changed", tc.name, err, !reflect.DeepEqual(next, tc.prev), tc.want)
		}
	}

	for name, exp := range map[string]struct {
		addrs     []string
		canonical string
	}{
		"other addresses": {[]string{"203.0.113.10"}, "b.ddns.example.net"},
		"other target":    {[]string{"203.0.113.20"}, "c.ddns.example.net"},
		// The operator never saw a target: the 409 shows the one the server sees.
		"target left out": {[]string{"203.0.113.20"}, ""},
	} {
		_, _, err := Confirm(review, obs, exp.addrs, exp.canonical, at(0))
		var changed *ObservationChangedError
		if !errors.As(err, &changed) || !errors.Is(err, ErrObservationChanged) ||
			!sameList(changed.Observed, "203.0.113.20") || changed.Canonical != "b.ddns.example.net" {
			t.Errorf("%s: err %v; want ObservationChangedError carrying what the server sees", name, err)
		}
	}

	var err error
	next, eff := run(t, review, at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) {
		var n model.DNSEntryState
		var e Effects
		n, e, err = Confirm(p, obs, []string{"::ffff:203.0.113.20"}, "B.DDNS.example.net.", at(0))
		return n, e
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sameList(next.Published, "203.0.113.20") || next.Status != model.DNSStatusOK || next.ReviewReason != "" ||
		len(next.ChangeTimes) != 0 || next.V4.NotFound != 0 || next.V6.NotFound != 0 || next.CanonicalName != "b.ddns.example.net" ||
		next.EmptyCause != "" || next.ReplaceOpen || next.CandidateSeen != 0 || eff.Recorded {
		t.Fatalf("confirmed: %+v; want the observation published, the review and counters reset, the pin moved", next)
	}
}

func TestEnterReview(t *testing.T) {
	next, eff := run(t, published("203.0.113.10"), at(0), func(p model.DNSEntryState) (model.DNSEntryState, Effects) {
		return EnterReview(p, model.DNSReviewReappeared, at(0))
	})
	if next.Status != model.DNSStatusNeedsReview || next.ReviewReason != model.DNSReviewReappeared || eff.EnteredReview != model.DNSReviewReappeared ||
		len(next.Published) != 0 || eff.Recorded || next.CanonicalName != host {
		t.Fatalf("EnterReview: %+v", next)
	}
	again, eff := run(t, next, at(time.Hour), func(p model.DNSEntryState) (model.DNSEntryState, Effects) {
		return EnterReview(p, model.DNSReviewUnstable, at(time.Hour))
	})
	if again.ReviewReason != model.DNSReviewReappeared || eff.EnteredReview != "" {
		t.Fatalf("a second review entry: %+v %+v; want the first reason kept and no new entry", again, eff)
	}
}
