package dnsentry

import (
	"time"

	"nginx-proxy-guard/internal/model"
)

// ExpireStale applies the grace at boot: while the API was down
// nothing was checked, so a family whose last definitive answer is older
// than grace (or that never had one) loses the addresses it publishes, as a
// check would have taken them away. The family becomes "transient" (its code
// stays), the removal is a revocation, and a name left with nothing is
// "lapse": its next answer goes through the empty-state escape rule. Not
// recorded in ChangeTimes. A name with nothing past the grace comes back
// unchanged.
func ExpireStale(prev model.DNSEntryState, now time.Time, grace time.Duration) (model.DNSEntryState, Effects) {
	c := begin(prev, now)
	n := &c.next
	keep := prev.Published
	for _, fam := range []struct {
		state *model.DNSFamilyState
		ipv4  bool
	}{{&n.V4, true}, {&n.V6, false}} {
		pub := familyOf(prev.Published, fam.ipv4)
		if len(pub) == 0 || !expired(*fam.state, now, grace) {
			continue
		}
		keep = minus(keep, pub)
		fam.state.State = outcomeTransient
	}
	if sameSet(keep, prev.Published) {
		return c.finish() // nothing past the grace: unchanged
	}
	n.Published = keep
	if len(keep) == 0 {
		n.EmptyCause, n.ReplaceOpen = model.DNSEmptyLapse, false
	}
	n.Status = statusOf(*n, keep, model.DefaultDNSEntrySettings().NotFoundChecks, grace, now)
	return c.finish()
}
