package dnsentry

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// restoredCanonical is the only shape a restored CNAME pin may have: a
// CNAME target need not pass the name rules, only fit the
// column and the files.
var restoredCanonical = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// MergeRestored merges one backup record into the name's row.
// existing is the row the database has, nil when there is none. It never
// publishes: a restored name starts closed and comes back only on its own
// answers, through the empty-state escape rule.
//
// The record is checked first: a hostname that fails the name rules makes it
// unusable (ok=false); a record in review whose reason is not cname_changed,
// reappeared or unstable (a newer version's reason, a hand-edited file, none
// at all) is in review as reappeared, so it still waits for a confirmation;
// a pin that does not fit ^[a-z0-9.-]{1,253}$ after NormalizeCanonical is
// dropped; last_applied keeps only addresses that parse and that p allows,
// unmapped, sorted, unique.
//
//   - No row: needs_review with the record's reason when it is in review,
//     else pending; nothing published; pin and last_applied from the record,
//     EmptyCause "restored" when last_applied is not empty.
//   - A row: in review when either is (a row the record puts in review is
//     closed through EnterReview: its addresses are revoked); the row's pin
//     wins, else the record's; the row's last_applied wins, else the record's.
//     A row that then publishes nothing and has a last_applied becomes a
//     restored name the restored lists use: EmptyCause
//     "restored", UnusedSince and ReplaceOpen cleared, so its next answers
//     meet the escape rule whatever emptied it before.
func MergeRestored(existing *model.DNSEntryState, rec model.DNSEntryStateExport, p *model.AddressPolicy, now time.Time) (model.DNSEntryState, bool) {
	name := model.NormalizeDNSName(rec.Hostname)
	if model.ValidateDNSName(name) != nil {
		return model.DNSEntryState{}, false
	}
	review := ""
	if rec.NeedsReview {
		review = rec.ReviewReason
		if !isReviewReason(review) {
			// An unknown or missing reason still waits for a confirmation.
			review = model.DNSReviewReappeared
		}
	}
	canonical := NormalizeCanonical(rec.CanonicalName)
	if !restoredCanonical.MatchString(canonical) {
		canonical = ""
	}
	lastApplied := restoredAddrs(rec.LastApplied, p)

	if existing == nil {
		st := model.DNSEntryState{
			Hostname:      name,
			Status:        model.DNSStatusPending,
			LastApplied:   lastApplied,
			CanonicalName: canonical,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if review != "" {
			st.Status, st.ReviewReason = model.DNSStatusNeedsReview, review
		}
		if len(lastApplied) > 0 {
			st.EmptyCause = model.DNSEmptyRestored
		}
		return st, true
	}

	next := *existing
	if review != "" && next.Status != model.DNSStatusNeedsReview {
		next, _ = EnterReview(next, review, now)
	}
	if next.CanonicalName == "" {
		next.CanonicalName = canonical
	}
	if len(next.LastApplied) == 0 && len(lastApplied) > 0 {
		next.LastApplied = lastApplied
	}
	// Whatever emptied the row (unused, switched off, lapsed, a
	// replacement in progress), the restored lists use the name now. Left
	// unused, the next check would take it back like an operator's re-add
	// (Reactivate), which skips the escape rule; "restored" keeps it.
	if len(next.Published) == 0 && len(next.LastApplied) > 0 {
		next.EmptyCause = model.DNSEmptyRestored
		next.UnusedSince = nil
		next.ReplaceOpen = false
	}
	return next, true
}

func isReviewReason(reason string) bool {
	switch reason {
	case model.DNSReviewCNAMEChanged, model.DNSReviewReappeared, model.DNSReviewUnstable:
		return true
	}
	return false
}

// restoredAddrs keeps the addresses of a backup's last_applied that parse and
// that p allows, written as the files write them.
func restoredAddrs(in []string, p *model.AddressPolicy) []string {
	var out []string
	for _, s := range in {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		a = a.Unmap()
		if p.Classify(a) != "" {
			continue
		}
		out = append(out, a.String())
	}
	return sortUnique(out)
}
