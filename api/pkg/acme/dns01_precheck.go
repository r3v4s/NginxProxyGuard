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
// lego can ask the resolvers in /etc/resolv.conf instead, but it sends them
// non-recursive queries, which a resolver answers from its cache only and many
// refuse outright (Unbound does by default); Docker's embedded DNS passes such
// a query on unchanged. So a Dynu record is checked with an ordinary recursive
// look-up through the container's resolver, which skips the nameservers that
// do not answer.

const (
	// dynuPropagationTimeout and dynuPollingInterval are how long lego waits
	// for a Dynu record to show through the resolver and how often it looks.
	// The resolver may hold a "no such record" it cached before the record
	// existed; ten minutes outlasts that.
	dynuPropagationTimeout = 10 * time.Minute
	dynuPollingInterval    = 10 * time.Second

	// resolverLookupTimeout bounds one look-up of a DNS-01 record through the
	// resolver.
	resolverLookupTimeout = 10 * time.Second
)

// txtLookup returns the TXT records of a name, as net.Resolver.LookupTXT does.
type txtLookup func(ctx context.Context, name string) ([]string, error)

// dns01ChallengeOptions returns the DNS-01 challenge options for a DNS provider
// type: none, so lego's own check, except for Dynu.
func dns01ChallengeOptions(providerType string) []dns01.ChallengeOption {
	check := dns01PreCheckFor(providerType, net.DefaultResolver.LookupTXT)
	if check == nil {
		return nil
	}
	return []dns01.ChallengeOption{dns01.WrapPreCheck(check)}
}

// dns01PreCheckFor returns the check that replaces lego's for a DNS provider
// type, or nil to keep lego's. The replacement never runs lego's check.
func dns01PreCheckFor(providerType string, lookup txtLookup) dns01.WrapPreCheckFunc {
	if providerType != model.DNSProviderDynu {
		return nil
	}
	return func(_, fqdn, value string, _ dns01.PreCheckFunc) (bool, error) {
		return txtVisibleThroughResolver(lookup, fqdn, value)
	}
}

// txtVisibleThroughResolver reports whether the resolver returns value among
// the TXT records of fqdn. Until it does, the error gives the reason in a few
// words: lego quotes the last one when it gives up, and that text is stored
// with the certificate and sent in notifications, so it carries neither the
// resolver's address nor the resolver's own wording.
func txtVisibleThroughResolver(lookup txtLookup, fqdn, value string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolverLookupTimeout)
	defer cancel()

	records, err := lookup(ctx, fqdn)
	if err != nil {
		return false, txtNotVisible(fqdn, lookupFailureReason(err))
	}
	for _, record := range records {
		if record == value {
			return true, nil
		}
	}
	return false, txtNotVisible(fqdn, "found a different value")
}

func txtNotVisible(fqdn, reason string) error {
	return fmt.Errorf("TXT record for %s not visible through the resolver yet: %s", fqdn, reason)
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
