package dnsentry

import (
	"errors"
	"net/netip"
	"sort"
	"time"

	"nginx-proxy-guard/internal/model"
)

// The state machine of one name: its checks, the daily change budget,
// review and confirmation, the feature switch. Every function here is
// pure: no I/O, no clock, no locks. The caller resolves, holds the locks,
// stores the row and writes the files.
//
// What every function keeps:
//   - a change of Published (as a set) moves Generation by exactly one and sets
//     LastChangedAt;
//   - an address leaving Published sets RevokePendingSince when it is unset
//     (cleared only when an accepted reload read the files, MarkApplied);
//   - a non-empty Published is also LastApplied, the last published set the
//     empty-state escape rule compares new answers with;
//   - prev is never modified: fields are replaced, never written into.

// Input is what Decide needs besides the row and the answer.
type Input struct {
	Now             time.Time
	Settings        model.DNSEntrySettings // normalized again inside
	LastDNSReloadAt *time.Time             // in memory; nil after a restart (no gap before the first apply)
}

// Effects is what one call did, for events, alerts and audits.
type Effects struct {
	Revoked       []string // addresses that left Published in this call
	Added         []string // addresses that entered Published in this call
	EnteredReview string   // the review reason when the name entered needs_review in this call, else ""
	Recorded      bool     // a change_times entry was appended
	FromStatus    string
	ToStatus      string
}

var (
	// ErrNotInReview: Confirm was asked for a name that does not wait for review.
	ErrNotInReview = errors.New("the domain does not wait for review")
	// ErrLookupUnavailable: Confirm could not get a determinate answer (a family
	// failed, the CNAME check was undecided, or nothing usable came back), so
	// nothing was published.
	ErrLookupUnavailable = errors.New("the domain could not be resolved just now")
	// ErrObservationChanged is what errors.Is matches for an
	// *ObservationChangedError.
	ErrObservationChanged = errors.New("the domain answers differently from what was confirmed")
)

// ObservationChangedError: the server's own answer is not what the operator
// confirmed. It carries the new answer, so the UI can show it.
type ObservationChangedError struct {
	Observed  []string
	Canonical string
}

func (e *ObservationChangedError) Error() string { return ErrObservationChanged.Error() }

// Is makes errors.Is(err, ErrObservationChanged) match.
func (e *ObservationChangedError) Is(target error) bool { return target == ErrObservationChanged }

// Decide is one check of a name that is used and switched on: the answer
// updates the families, then the name's status and
// what it publishes. Revocations are immediate; an addition needs the same
// candidate twice in a row with a determinate CNAME and the reload gap. A
// check on which a family fails within the grace or answers a debounced "not
// found" does not end a replacement in progress. A
// name in review only records what it sees. Decide never publishes for a
// name that is switched off or unused.
func Decide(prev model.DNSEntryState, obs Observation, in Input) (model.DNSEntryState, Effects) {
	st := in.Settings.Normalize()
	c := begin(prev, in.Now)
	n := &c.next
	candidate := c.observe(obs, prev.Published, st)

	switch {
	case prev.Status == model.DNSStatusNeedsReview || prev.Disabled || prev.UnusedSince != nil:
		n.Published = nil
		n.Candidate, n.CandidateSeen = candidate, 0
		return c.finish()
	case prev.Status == model.DNSStatusPending && len(prev.LastApplied) == 0:
		c.firstPublish(candidate, obs)
		return c.finish()
	}

	// The pinned CNAME target moved: closed until an operator looks.
	if obs.CNAMEOK && n.CanonicalName != "" && obs.Canonical != n.CanonicalName {
		c.enterReview(model.DNSReviewCNAMEChanged, candidate)
		return c.finish()
	}

	// Revocations: at once, also while the CNAME check is undecided.
	published := intersect(prev.Published, candidate)
	if len(minus(prev.Published, candidate)) > 0 {
		c.record()
		if len(minus(candidate, published)) > 0 {
			n.ReplaceOpen = true
		}
		if len(published) == 0 {
			n.EmptyCause = model.DNSEmptyLapse
			if len(candidate) > 0 {
				n.EmptyCause = model.DNSEmptyReplace
			}
		}
	}
	// A replacement left with nothing to add lapses, unless the check held: a
	// held family's part of the candidate is only what it publishes, so the
	// address the replacement waits for may still come.
	if len(published) == 0 && len(candidate) == 0 && n.EmptyCause == model.DNSEmptyReplace && !c.held {
		n.EmptyCause = model.DNSEmptyLapse
	}

	// Additions.
	adds := minus(candidate, published)
	switch {
	case len(adds) == 0:
		n.Candidate, n.CandidateSeen = candidate, 0
	case len(published) == 0 && len(prev.LastApplied) > 0 && escapesEmptyState(n.EmptyCause) && !subset(candidate, prev.LastApplied):
		// Back from empty with an address it never published.
		c.enterReview(model.DNSReviewReappeared, candidate)
		return c.finish()
	case !obs.CNAMEOK:
		// Held: this answer does not count as an observation.
		if !sameSet(prev.Candidate, candidate) {
			n.CandidateSeen = 0
		}
		n.Candidate = candidate
	default:
		n.CandidateSeen = 1
		if sameSet(prev.Candidate, candidate) {
			n.CandidateSeen = prev.CandidateSeen + 1
		}
		n.Candidate = candidate
		if n.CandidateSeen >= 2 && gapElapsed(in.LastDNSReloadAt, in.Now, st.MinReloadGap()) {
			published = candidate
			if !n.ReplaceOpen {
				c.record()
			}
			n.EmptyCause = ""
			if n.CanonicalName == "" {
				n.CanonicalName = obs.Canonical
			}
		}
	}
	n.Published = published
	// A replacement ends once its whole candidate is published; a held check
	// with nothing to add leaves it open, so it still counts once.
	if sameSet(published, candidate) && !(c.held && len(adds) == 0) {
		n.ReplaceOpen = false
	}

	// More applied changes in 24 hours than allowed: closed (unstable).
	n.ChangeTimes = within24h(n.ChangeTimes, in.Now)
	if len(n.ChangeTimes) > st.MaxChangesPerDay {
		c.enterReview(model.DNSReviewUnstable, candidate)
		return c.finish()
	}

	n.Status = statusOf(*n, candidate, st.NotFoundChecks, st.StaleGrace(), in.Now)
	return c.finish()
}

// FirstPublish is a pending name's first answer on the operator's save
// path: published at once when it has addresses and a determinate
// CNAME, which is pinned. Outside the budget, not recorded. Any other row is
// returned unchanged.
func FirstPublish(prev model.DNSEntryState, obs Observation, now time.Time) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	if prev.Status != model.DNSStatusPending || len(prev.LastApplied) > 0 || prev.Disabled || prev.UnusedSince != nil {
		return c.finish()
	}
	c.firstPublish(c.observe(obs, nil, model.DefaultDNSEntrySettings()), obs)
	return c.finish()
}

// Disable switches a name off: everything published is revoked
// at once, outside the budget. Status, review, pin and LastApplied stay, so
// switching the feature back on trusts nothing new by itself.
func Disable(prev model.DNSEntryState, now time.Time) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	c.next.Disabled = true
	if len(prev.Published) > 0 || len(prev.LastApplied) > 0 {
		c.next.EmptyCause = model.DNSEmptyDisabled
	}
	c.next.Published = nil
	return c.finish()
}

// Enable switches a name back on and changes nothing else: the
// next Decide publishes a pending name's first answer, keeps a review closed,
// and takes any other name through the empty-state escape rule
// (EmptyCause "disabled").
func Enable(prev model.DNSEntryState) model.DNSEntryState {
	prev.Disabled = false
	return prev
}

// MarkUnused closes a name nothing references any more. Status,
// review, pin and LastApplied stay for seven days, in case it comes back.
func MarkUnused(prev model.DNSEntryState, now time.Time) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	if c.next.UnusedSince == nil {
		c.next.UnusedSince = timePtr(now)
	}
	if len(prev.Published) > 0 {
		c.next.EmptyCause = model.DNSEmptyUnused
	}
	c.next.Published = nil
	return c.finish()
}

// Reactivate takes back an unused name an operator added again, or one a
// check sees used again. A review stays closed and the
// pin stays. With an answer: a moved CNAME target puts the name under review;
// otherwise what it observes is published at once (an operator action, not
// recorded, no escape rule), pinning the CNAME target when none is pinned.
// Without a usable answer nothing is published and EmptyCause is "unused":
// the next Decide adds through the normal path. Never publishes
// while the name is switched off.
func Reactivate(prev model.DNSEntryState, obs *Observation, now time.Time) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	n := &c.next
	n.UnusedSince = nil
	var candidate []string
	if obs != nil {
		candidate = c.observe(*obs, nil, model.DefaultDNSEntrySettings())
		n.Candidate, n.CandidateSeen = candidate, 0
	}
	n.Published = nil
	if prev.Status == model.DNSStatusNeedsReview {
		return c.finish()
	}
	if obs != nil && obs.CNAMEOK && n.CanonicalName != "" && obs.Canonical != n.CanonicalName {
		c.enterReview(model.DNSReviewCNAMEChanged, candidate)
		return c.finish()
	}
	if obs != nil && obs.CNAMEOK && len(candidate) > 0 && !prev.Disabled {
		n.Published = candidate
		n.EmptyCause, n.ReplaceOpen = "", false
		if n.CanonicalName == "" {
			n.CanonicalName = obs.Canonical
		}
	} else {
		n.EmptyCause = model.DNSEmptyUnused
	}
	if obs != nil {
		def := model.DefaultDNSEntrySettings() // the next check recomputes with the configured limits
		n.Status = statusOf(*n, candidate, def.NotFoundChecks, def.StaleGrace(), now)
	}
	return c.finish()
}

// Confirm is an operator's "allow again" for a name in review.
// It publishes only the server's own answer, and only when that is what the
// operator saw: expected (as a set, compared unmapped) and expectedCanonical,
// the CNAME target (a name without a CNAME is its own target), so a target
// the operator was not shown is never pinned. Errors change nothing:
// ErrNotInReview, ErrLookupUnavailable (a transient family, an undecided
// CNAME, or no usable address), *ObservationChangedError. On success the
// review, the change counters and the not-found counters reset and the pin
// moves to the observed target.
func Confirm(prev model.DNSEntryState, obs Observation, expected []string, expectedCanonical string, now time.Time) (model.DNSEntryState, Effects, error) {
	unchanged := Effects{FromStatus: prev.Status, ToStatus: prev.Status}
	if prev.Status != model.DNSStatusNeedsReview {
		return prev, unchanged, ErrNotInReview
	}
	if !determinate(obs.V4) || !determinate(obs.V6) || !obs.CNAMEOK {
		return prev, unchanged, ErrLookupUnavailable
	}
	c := begin(prev, now)
	observed := c.observe(obs, nil, model.DefaultDNSEntrySettings())
	if len(observed) == 0 {
		return prev, unchanged, ErrLookupUnavailable
	}
	expectedCanonical = NormalizeCanonical(expectedCanonical)
	if !sameSet(observed, canonicalAddrs(expected)) || obs.Canonical != expectedCanonical {
		return prev, unchanged, &ObservationChangedError{Observed: observed, Canonical: obs.Canonical}
	}
	n := &c.next
	n.Published = observed
	n.Status, n.ReviewReason = model.DNSStatusOK, ""
	n.ChangeTimes = nil
	n.V4.NotFound, n.V6.NotFound = 0, 0
	n.CanonicalName = obs.Canonical
	n.EmptyCause, n.ReplaceOpen = "", false
	n.Candidate, n.CandidateSeen = observed, 0
	next, eff := c.finish()
	return next, eff, nil
}

// EnterReview closes a name until an operator confirms it:
// everything published is revoked, the status becomes needs_review with
// reason. EmptyCause stays, and nothing is recorded. A name
// already in review keeps its reason. The backup import uses it to close a
// restored name the backup marks for review.
func EnterReview(prev model.DNSEntryState, reason string, now time.Time) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	if prev.Status == model.DNSStatusNeedsReview {
		c.next.Published = nil
		return c.finish()
	}
	c.enterReview(reason, prev.Candidate)
	return c.finish()
}

// transition is one call's work: the row being built from prev and what the
// call did besides. next starts as a copy of prev that shares its slices and
// times, so every change replaces a field and never writes into one: the
// caller's row stays as it was (the tests check it).
type transition struct {
	prev     model.DNSEntryState
	next     model.DNSEntryState
	now      time.Time
	recorded bool
	entered  string
	held     bool // a family kept its published part: debounced not found, or failing within the grace
}

func begin(prev model.DNSEntryState, now time.Time) *transition {
	return &transition{prev: prev, next: prev, now: now}
}

// observe takes an answer into the row (first part of Decide): the time of the
// check, the canonical name both lookups agreed on, each family's state, and
// the candidate, which is what the policy says should be published. pub is
// what is published now; a debounced not-found family and a failing family
// within the grace keep their part of it, and the check then held (c.held):
// that family's part of the candidate is only what it publishes, whatever it
// would answer.
func (c *transition) observe(obs Observation, pub []string, st model.DNSEntrySettings) []string {
	c.next.LastCheckedAt = timePtr(c.now)
	c.next.CanonicalSeen = obs.Canonical
	v4 := c.family(&c.next.V4, obs.V4, familyOf(pub, true), st)
	v6 := c.family(&c.next.V6, obs.V6, familyOf(pub, false), st)
	return sortUnique(append(v4, v6...))
}

func (c *transition) family(f *model.DNSFamilyState, o FamilyObs, pub []string, st model.DNSEntrySettings) []string {
	switch o.Outcome {
	case outcomeOK:
		f.State, f.Code, f.Observed = outcomeOK, "", sortUnique(o.Addrs)
		f.AnswerAt, f.NotFound = timePtr(c.now), 0
		return sortUnique(o.Addrs)
	case outcomeRejected:
		f.State, f.Code, f.Observed = outcomeRejected, o.Code, nil
		f.AnswerAt, f.NotFound = timePtr(c.now), 0
		return nil
	case outcomeNotFound:
		f.State, f.Code, f.Observed = outcomeNotFound, codeNotFound, nil
		f.AnswerAt = timePtr(c.now)
		f.NotFound = min(f.NotFound+1, notFoundCap)
		if f.NotFound >= st.NotFoundChecks {
			return nil
		}
		c.held = true
		return pub
	default: // transient: neither a change nor an answer
		f.State, f.Code = outcomeTransient, o.Code
		if expired(*f, c.now, st.StaleGrace()) {
			return nil
		}
		c.held = true
		return pub
	}
}

// firstPublish is part of Decide: a pending name that never published takes
// its first answer at once (the result of an operator's action, not
// recorded), with a determinate CNAME, which is pinned. Otherwise it stays
// pending.
func (c *transition) firstPublish(candidate []string, obs Observation) {
	n := &c.next
	n.Candidate, n.CandidateSeen = candidate, 0
	if len(candidate) == 0 || !obs.CNAMEOK {
		return
	}
	n.Published = candidate
	n.CanonicalName = obs.Canonical
	n.Status = model.DNSStatusOK
	n.EmptyCause, n.ReplaceOpen = "", false
}

// enterReview revokes everything published and closes the name.
func (c *transition) enterReview(reason string, candidate []string) {
	n := &c.next
	n.Published = nil
	n.Status, n.ReviewReason = model.DNSStatusNeedsReview, reason
	n.Candidate, n.CandidateSeen = candidate, 0
	n.ReplaceOpen = false
	c.entered = reason
}

// record appends this check to ChangeTimes, once per call.
func (c *transition) record() {
	if c.recorded {
		return
	}
	c.recorded = true
	c.next.ChangeTimes = append(append([]time.Time(nil), c.next.ChangeTimes...), c.now)
}

// finish does the bookkeeping every change of Published needs, once per call,
// and reports what the call did.
func (c *transition) finish() (model.DNSEntryState, Effects) {
	n := c.next
	n.Published = sortUnique(n.Published)
	revoked := minus(c.prev.Published, n.Published)
	added := minus(n.Published, c.prev.Published)
	if len(revoked) > 0 || len(added) > 0 {
		n.Generation = c.prev.Generation + 1
		n.LastChangedAt = timePtr(c.now)
	}
	if len(revoked) > 0 && n.RevokePendingSince == nil {
		n.RevokePendingSince = timePtr(c.now)
	}
	if len(n.Published) > 0 {
		n.LastApplied = append([]string(nil), n.Published...)
	}
	return n, Effects{
		Revoked:       revoked,
		Added:         added,
		EnteredReview: c.entered,
		Recorded:      c.recorded,
		FromStatus:    c.prev.Status,
		ToStatus:      n.Status,
	}
}

// statusOf is a name's status at the end of a check: a
// pending name stays pending until it publishes and a review stays a review;
// otherwise not_found when both families are not found at the limit; with
// nothing published and nothing to publish (candidate empty) rejected, then
// expired, then not_found, by the families; else stale while a family fails
// within the grace; else ok. A name that publishes nothing only because its
// next addresses wait for the budget (every address change of a DDNS name: A
// revoked, B waiting) is ok or stale: its answers are fine, and its other
// family may well be "notfound" for good. So is one whose replacement a held
// check kept open (EmptyCause still "replace" with nothing to add).
func statusOf(n model.DNSEntryState, candidate []string, notFoundChecks int, grace time.Duration, now time.Time) string {
	if n.Status == model.DNSStatusNeedsReview || (n.Status == model.DNSStatusPending && len(n.Published) == 0) {
		return n.Status
	}
	fams := []model.DNSFamilyState{n.V4, n.V6}
	notFoundAtLimit := func(f model.DNSFamilyState) bool {
		return f.State == outcomeNotFound && f.NotFound >= notFoundChecks
	}
	if notFoundAtLimit(n.V4) && notFoundAtLimit(n.V6) {
		return model.DNSStatusNotFound
	}
	either := func(match func(model.DNSFamilyState) bool) bool {
		return match(fams[0]) || match(fams[1])
	}
	if len(n.Published) == 0 && len(candidate) == 0 && n.EmptyCause != model.DNSEmptyReplace {
		switch {
		case either(func(f model.DNSFamilyState) bool { return f.State == outcomeRejected }):
			return model.DNSStatusRejected
		case either(func(f model.DNSFamilyState) bool { return f.State == outcomeTransient && expired(f, now, grace) }):
			return model.DNSStatusExpired
		case either(func(f model.DNSFamilyState) bool { return f.State == outcomeNotFound }):
			return model.DNSStatusNotFound
		}
	}
	if either(func(f model.DNSFamilyState) bool { return f.State == outcomeTransient && !expired(f, now, grace) }) {
		return model.DNSStatusStale
	}
	return model.DNSStatusOK
}

// notFoundCap is where a family's count of not-found answers stops. Only
// counts up to not_found_checks (at most 10) decide anything, and the column
// is a smallint: a name that stays not found would pass 32767 after about 23
// days of 60-second checks, and its row could no longer be written.
const notFoundCap = 10000

// expired: a family's last definitive answer is older than the grace, or
// there never was one.
func expired(f model.DNSFamilyState, now time.Time, grace time.Duration) bool {
	return f.AnswerAt == nil || now.Sub(*f.AnswerAt) > grace
}

// determinate: the family answered (ok, not found or refused), not failed.
func determinate(o FamilyObs) bool {
	return o.Outcome == outcomeOK || o.Outcome == outcomeNotFound || o.Outcome == outcomeRejected
}

// escapesEmptyState: the empty causes the empty-state escape rule applies to.
// replace (an address change in progress) and unused (an operator re-added
// the name) are not among them.
func escapesEmptyState(cause string) bool {
	return cause == model.DNSEmptyLapse || cause == model.DNSEmptyDisabled || cause == model.DNSEmptyRestored
}

func gapElapsed(last *time.Time, now time.Time, gap time.Duration) bool {
	return last == nil || now.Sub(*last) >= gap
}

// within24h keeps the change times of the last 24 hours.
func within24h(times []time.Time, now time.Time) []time.Time {
	var out []time.Time
	for _, t := range times {
		if now.Sub(t) < 24*time.Hour {
			out = append(out, t)
		}
	}
	return out
}

// familyOf returns the addresses of one family (IPv4 when ipv4) in addrs.
// A value that is not an address belongs to neither, so a check revokes it.
func familyOf(addrs []string, ipv4 bool) []string {
	var out []string
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil && a.Unmap().Is4() == ipv4 {
			out = append(out, s)
		}
	}
	return out
}

// canonicalAddrs writes addresses as Observe does (unmapped, String());
// a value that is not an address stays as it is, so it never matches.
func canonicalAddrs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil {
			s = a.Unmap().String()
		}
		out = append(out, s)
	}
	return sortUnique(out)
}

func timePtr(t time.Time) *time.Time { return &t }

// sortUnique returns the values sorted, each once; nil when there are none.
func sortUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	j := 0
	for i, v := range out {
		if i == 0 || v != out[j-1] {
			out[j] = v
			j++
		}
	}
	return out[:j]
}

// minus returns the values of a that are not in b, sorted.
func minus(a, b []string) []string {
	drop := make(map[string]bool, len(b))
	for _, v := range b {
		drop[v] = true
	}
	var out []string
	for _, v := range a {
		if !drop[v] {
			out = append(out, v)
		}
	}
	return sortUnique(out)
}

// intersect returns the values in both a and b, sorted.
func intersect(a, b []string) []string {
	return minus(a, minus(a, b))
}

func subset(a, b []string) bool { return len(minus(a, b)) == 0 }

func sameSet(a, b []string) bool { return subset(a, b) && subset(b, a) }
