// Package dnsentry resolves the domain names of domain entries (#320) and
// decides, as pure functions, which addresses a name may publish. It imports
// only model and the standard library, so the DNS entry service and the backup
// import can both use it. Nothing here keeps an error's text: a lookup error
// carries the resolver's address, so only classification codes leave this
// package.
package dnsentry

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Outcomes of one address family. They are also the values of
// DNSFamilyState.State (the v4_state and v6_state columns).
const (
	outcomeOK        = "ok"        // the name has addresses of this family
	outcomeNotFound  = "notfound"  // definitely none: NXDOMAIN, NODATA, a hosts-file name without one
	outcomeTransient = "transient" // no definitive answer
	outcomeRejected  = "rejected"  // an answer the address policy refused (Observe only)
)

// Classification codes. They are what is stored and shown in
// place of an error.
const (
	codeTimeout  = "timeout"
	codeServfail = "servfail"
	codeRefused  = "refused"
	codeNetwork  = "network"
	codeNotFound = "not_found"
	codeTooMany  = "too_many"
	codeReserved = "reserved"
)

// The texts Go's resolver puts in the errors ClassifyLookupError tells apart.
// They are compared, never stored.
const (
	errTextNoSuitableAddress = "no suitable address found" // *net.AddrError: a hosts-file name without this family
	errTextServerMisbehaving = "server misbehaving"        // *net.DNSError: SERVFAIL (temporary), REFUSED and other rcodes
)

// defaultPerLookup bounds one lookup when the caller passes no timeout.
const defaultPerLookup = 5 * time.Second

// Lookuper is the part of *net.Resolver a check uses. Tests use a fake.
type Lookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// SystemLookuper returns the resolver checks use: Go's own resolver, which
// reads /etc/hosts before the nameservers of /etc/resolv.conf (the E2E and
// real-environment stacks put names there with extra_hosts). StrictErrors
// turns a failed query into an error instead of a partial answer.
func SystemLookuper() Lookuper {
	return &net.Resolver{PreferGo: true, StrictErrors: true}
}

// FamilyAnswer is one address family's lookup result. Outcome is "ok" (Addrs
// holds at least one address), "notfound" or "transient" (Code says why).
// Addrs are unmapped (a hosts-file IPv4 address comes back as ::ffff:a.b.c.d),
// sorted and unique.
type FamilyAnswer struct {
	Outcome string
	Code    string
	Addrs   []netip.Addr
}

// Answer is one resolution of one name. CNAMEBefore and CNAMEAfter are the
// canonical names the lookups before and after the address lookups returned,
// normalized (NormalizeCanonical); "" when that lookup failed.
type Answer struct {
	V4, V6                  FamilyAnswer
	CNAMEBefore, CNAMEAfter string
}

// Resolve looks name up the way every check does: LookupCNAME,
// then the IPv4 and IPv6 lookups at the same time, then LookupCNAME again.
// Every lookup has its own perLookup timeout under ctx, so a slow family does
// not eat the other's time, and asks for the absolute name (name + "."), so
// resolv.conf's search list is never tried. It always returns an Answer: a
// lookup cut off by ctx is a transient timeout, which never counts as a
// change.
func Resolve(ctx context.Context, l Lookuper, name string, perLookup time.Duration) Answer {
	if perLookup <= 0 {
		perLookup = defaultPerLookup
	}
	host := strings.TrimSuffix(name, ".") + "."
	var a Answer
	a.CNAMEBefore = lookupCanonical(ctx, l, host, perLookup)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a.V4 = lookupFamily(ctx, l, "ip4", host, perLookup)
	}()
	go func() {
		defer wg.Done()
		a.V6 = lookupFamily(ctx, l, "ip6", host, perLookup)
	}()
	wg.Wait()
	a.CNAMEAfter = lookupCanonical(ctx, l, host, perLookup)
	return a
}

func lookupCanonical(ctx context.Context, l Lookuper, host string, perLookup time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, perLookup)
	defer cancel()
	cname, err := l.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	return NormalizeCanonical(cname)
}

func lookupFamily(ctx context.Context, l Lookuper, network, host string, perLookup time.Duration) FamilyAnswer {
	ctx, cancel := context.WithTimeout(ctx, perLookup)
	defer cancel()
	addrs, err := l.LookupNetIP(ctx, network, host)
	if err != nil {
		outcome, code := ClassifyLookupError(err)
		return FamilyAnswer{Outcome: outcome, Code: code}
	}
	out := unmapSorted(addrs)
	if len(out) == 0 {
		return FamilyAnswer{Outcome: outcomeNotFound, Code: codeNotFound}
	}
	return FamilyAnswer{Outcome: outcomeOK, Addrs: out}
}

// unmapSorted returns addrs unmapped, sorted and without duplicates (an
// address and its ::ffff: form are one address).
func unmapSorted(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// ClassifyLookupError turns a lookup error into an outcome and a code. The
// rows, in this order, are what Go's resolver (go1.27, PreferGo, StrictErrors)
// was measured to return against /etc/hosts and a DNS server:
//
//	a. *net.AddrError "no suitable address found" — a hosts-file name without
//	   this family: "notfound", "not_found" (like DNS NODATA)
//	b. *net.DNSError with IsNotFound — NXDOMAIN or NODATA: "notfound", "not_found"
//	c. IsTimeout, context.DeadlineExceeded, or context.Canceled (the lookup was
//	   cut off): "transient", "timeout"
//	d. "server misbehaving" with IsTemporary — SERVFAIL: "transient", "servfail"
//	e. "server misbehaving" otherwise — REFUSED, FORMERR, NOTIMP and every
//	   other rcode: "transient", "refused"
//	f. IsTemporary — no route, socket errors: "transient", "network"
//	g. anything else (lame referral, an unreadable reply): "transient", "servfail"
//
// A nil error is "ok", "". Only these constants come back; err.Error() is
// never used (it holds the resolver's address).
func ClassifyLookupError(err error) (outcome, code string) {
	if err == nil {
		return outcomeOK, ""
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && addrErr.Err == errTextNoSuitableAddress {
		return outcomeNotFound, codeNotFound
	}
	var dnsErr *net.DNSError
	isDNS := errors.As(err, &dnsErr)
	var netErr net.Error
	switch {
	case isDNS && dnsErr.IsNotFound:
		return outcomeNotFound, codeNotFound
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.As(err, &netErr) && netErr.Timeout():
		return outcomeTransient, codeTimeout
	case isDNS && dnsErr.Err == errTextServerMisbehaving && dnsErr.IsTemporary:
		return outcomeTransient, codeServfail
	case isDNS && dnsErr.Err == errTextServerMisbehaving:
		return outcomeTransient, codeRefused
	case isDNS && dnsErr.IsTemporary:
		return outcomeTransient, codeNetwork
	}
	return outcomeTransient, codeServfail
}

// NormalizeCanonical returns a canonical name as it is compared and pinned:
// ASCII letters in lower case, one trailing dot removed. Resolvers that mix
// the case of a query (0x20) and the absolute form "name." are not changes.
// Only ASCII letters are lowered, like model.NormalizeDNSName.
func NormalizeCanonical(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return strings.TrimSuffix(string(b), ".")
}
