package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"nginx-proxy-guard/internal/model"
)

// DNS-01 propagation checks.
//
// Before lego asks the CA to validate a DNS-01 challenge, it checks that the
// TXT record is visible. Its own check asks every authoritative nameserver of
// the zone directly and fails until all of them return the record, so one
// nameserver that does not answer holds the certificate back until the
// timeout. Some of Dynu's nameservers do not answer UDP queries from some
// networks (#327), and Dynu certificates failed although the record was in
// place.
//
// So a Dynu record is checked in two steps. lego's own check comes first:
// where every nameserver answers, it confirms the record as quickly as it
// always has. Only when it does not confirm the record does an ordinary
// recursive look-up through the container's resolver follow, which skips the
// nameservers that do not answer. The resolver is not asked first because it
// may still remember that the name did not exist: lego looks the name up
// before the record is created.
//
// lego's own option to check the resolvers in /etc/resolv.conf is not used:
// it sends them non-recursive queries, which a resolver answers from its cache
// only and many refuse outright (Unbound does by default), and Docker's
// embedded DNS passes such a query on unchanged.

const (
	// dynuPropagationTimeout and dynuPollingInterval are how long lego tries
	// to confirm a Dynu record and how often. Each try asks the authoritative
	// nameservers first and, if they do not all confirm the record, the
	// resolver; the longer wait gives a resolver that remembers the name's
	// absence time to forget it.
	dynuPropagationTimeout = 10 * time.Minute
	dynuPollingInterval    = 10 * time.Second

	// resolverLookupTimeout bounds one look-up of a DNS-01 record through the
	// resolver.
	resolverLookupTimeout = 10 * time.Second
)

// txtLookup returns the TXT records of a name, as net.Resolver.LookupTXT does.
type txtLookup func(ctx context.Context, name string) ([]string, error)

// dns01ChallengeOptions returns the DNS-01 challenge options for a DNS provider
// type: none, so lego's defaults, except for Dynu.
func dns01ChallengeOptions(providerType string) []dns01.ChallengeOption {
	return dns01ChallengeOptionsWith(providerType, net.DefaultResolver.LookupTXT)
}

// dns01ChallengeOptionsWith is dns01ChallengeOptions with the resolver
// look-up given.
func dns01ChallengeOptionsWith(providerType string, lookup txtLookup) []dns01.ChallengeOption {
	check := dns01PreCheckFor(providerType, lookup)
	if check == nil {
		return nil
	}
	return []dns01.ChallengeOption{dns01.WrapPreCheck(check)}
}

// dns01PreCheckFor returns the check that wraps lego's for a DNS provider type,
// or nil to leave lego's alone. Dynu's runs lego's check, which asks every
// authoritative nameserver, and looks the record up through the resolver only
// when that does not confirm it.
func dns01PreCheckFor(providerType string, lookup txtLookup) dns01.WrapPreCheckFunc {
	if providerType != model.DNSProviderDynu {
		return nil
	}
	return func(_, fqdn, value string, legoCheck dns01.PreCheckFunc) (bool, error) {
		if ok, err := legoCheck(fqdn, value); ok && err == nil {
			return true, nil
		}
		found, reason := txtThroughResolver(lookup, fqdn, value)
		if found {
			return true, nil
		}
		// Neither lego's error nor the resolver's is quoted: they name
		// nameserver and resolver addresses, and lego quotes this error when
		// it gives up, which is stored with the certificate and sent in
		// notifications.
		return false, fmt.Errorf("TXT record for %s not visible yet: authoritative nameservers: not confirmed; resolver: %s", fqdn, reason)
	}
}

// txtThroughResolver reports whether the resolver returns value among the TXT
// records of fqdn and, when it does not, why, in a few words.
func txtThroughResolver(lookup txtLookup, fqdn, value string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), resolverLookupTimeout)
	defer cancel()

	records, err := lookup(ctx, fqdn)
	if err != nil {
		return false, lookupFailureReason(err)
	}
	for _, record := range records {
		if record == value {
			return true, ""
		}
	}
	return false, "found a different value"
}

// lookupFailureReason says why a look-up failed without quoting the error.
func lookupFailureReason(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "no such record"
		case dnsErr.IsTimeout:
			return "lookup timed out"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "lookup timed out"
	}
	return "lookup failed"
}
