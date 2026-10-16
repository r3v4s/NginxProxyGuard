package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"nginx-proxy-guard/internal/model"
)

const (
	challengeFQDN  = "_acme-challenge.example.com."
	challengeValue = "dns01-expected-value"
)

// fakeTXTLookup stands in for the container's resolver.
type fakeTXTLookup struct {
	records []string
	err     error

	names       []string      // the names looked up
	hasDeadline bool          // whether the last look-up had a deadline
	left        time.Duration // how long the last look-up had
}

func (f *fakeTXTLookup) lookup(ctx context.Context, name string) ([]string, error) {
	f.names = append(f.names, name)
	var deadline time.Time
	deadline, f.hasDeadline = ctx.Deadline()
	f.left = time.Until(deadline)
	return f.records, f.err
}

// legosOwnCheck fails the test if it runs: for Dynu it is replaced, because it
// asks every authoritative nameserver of the zone directly.
func legosOwnCheck(t *testing.T) dns01.PreCheckFunc {
	t.Helper()
	return func(fqdn, _ string) (bool, error) {
		t.Errorf("lego's own propagation check ran for %s", fqdn)
		return false, errors.New("lego's own check")
	}
}

// Only Dynu's records are confirmed through the resolver. Every other provider
// keeps lego's own check and its other defaults.
func TestDNS01ChallengeOptionsReplaceLegosCheckOnlyForDynu(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{challengeValue}}
	if dns01PreCheckFor(model.DNSProviderDynu, fake.lookup) == nil {
		t.Error("Dynu keeps lego's own check, which asks every authoritative nameserver")
	}
	if got := len(dns01ChallengeOptions(model.DNSProviderDynu)); got != 1 {
		t.Errorf("Dynu gets %d challenge options, want the one that replaces lego's check", got)
	}
	for _, providerType := range []string{model.DNSProviderCloudflare, model.DNSProviderRoute53, model.DNSProviderDuckDNS} {
		if dns01PreCheckFor(providerType, fake.lookup) != nil {
			t.Errorf("%s: lego's own check was replaced", providerType)
		}
		if got := len(dns01ChallengeOptions(providerType)); got != 0 {
			t.Errorf("%s gets %d challenge options, want none: lego's defaults", providerType, got)
		}
	}
	if len(fake.names) != 0 {
		t.Errorf("building the options looked up %q", fake.names)
	}
}

// The Dynu check is an ordinary look-up through the resolver, which skips a
// nameserver that does not answer. It passes once the expected value is among
// the TXT records, each look-up has a deadline of its own, and lego's own check
// never runs.
func TestDynuDNS01CheckLooksTheRecordUpThroughTheResolver(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"an older challenge", challengeValue, "v=spf1 -all"}}
	check := dns01PreCheckFor(model.DNSProviderDynu, fake.lookup)

	ok, err := check("example.com", challengeFQDN, challengeValue, legosOwnCheck(t))
	if !ok || err != nil {
		t.Fatalf("check = %v, %v; want true, nil", ok, err)
	}
	if len(fake.names) != 1 || fake.names[0] != challengeFQDN {
		t.Errorf("looked up %q, want %q once", fake.names, challengeFQDN)
	}
	if !fake.hasDeadline || fake.left <= 0 || fake.left > 10*time.Second {
		t.Errorf("the look-up had a deadline: %v, %s left; want a deadline of at most 10s", fake.hasDeadline, fake.left)
	}
}

// Until the record shows, the check fails with the reason in a few words, so
// lego keeps polling and quotes the last reason when time runs out. That text
// is stored with the certificate and sent in notifications, so it names
// neither the resolver's address nor the resolver's own wording.
func TestDynuDNS01CheckKeepsPollingWithAGenericReason(t *testing.T) {
	const resolver = "192.0.2.53:53"
	cases := []struct {
		name    string
		records []string
		err     error
		reason  string
	}{
		{"no such record", nil,
			&net.DNSError{Err: "no such host", Name: challengeFQDN, Server: resolver, IsNotFound: true}, "no such record"},
		{"a different value", []string{"an older challenge"}, nil, "found a different value"},
		{"resolver timed out", nil,
			&net.DNSError{Err: "i/o timeout", Name: challengeFQDN, Server: resolver, IsTimeout: true}, "lookup timed out"},
		{"deadline passed", nil,
			fmt.Errorf("lookup %s on %s: %w", challengeFQDN, resolver, context.DeadlineExceeded), "lookup timed out"},
		{"server failure", nil,
			&net.DNSError{Err: "server misbehaving", Name: challengeFQDN, Server: resolver, IsTemporary: true}, "lookup failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			check := dns01PreCheckFor(model.DNSProviderDynu, (&fakeTXTLookup{records: tc.records, err: tc.err}).lookup)

			ok, err := check("example.com", challengeFQDN, challengeValue, legosOwnCheck(t))
			if ok || err == nil {
				t.Fatalf("check = %v, %v; want false and a reason, so lego keeps polling", ok, err)
			}
			want := "TXT record for " + challengeFQDN + " not visible through the resolver yet: " + tc.reason
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
			if tc.err != nil {
				for _, quoted := range []string{"192.0.2.53", tc.err.Error()} {
					if strings.Contains(err.Error(), quoted) {
						t.Errorf("the error quotes %q: %v", quoted, err)
					}
				}
			}
		})
	}
}

// Dynu's records are confirmed through the container's resolver, which may
// still hold a "no such record" it cached before the record existed, so lego
// gives them ten minutes, looking every ten seconds. Building the provider
// makes no request.
func TestDynuDNS01WaitsTenMinutesLookingEveryTenSeconds(t *testing.T) {
	p, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderDynu, model.DynuCredentials{APIKey: "dynu-key-0123456789"}))
	if err != nil {
		t.Fatal(err)
	}
	timeouts, ok := p.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("the Dynu provider has no Timeout")
	}
	if timeout, interval := timeouts.Timeout(); timeout != 10*time.Minute || interval != 10*time.Second {
		t.Errorf("Timeout() = %s, %s; want 10m0s, 10s", timeout, interval)
	}
}
