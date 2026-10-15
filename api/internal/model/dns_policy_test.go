package model

import (
	"net/netip"
	"testing"
)

// docsAsPublicPolicy is the production policy without the documentation
// rows, so 192.0.2.x, 198.51.100.x, 203.0.113.x and 2001:db8::/32 can stand
// in for public addresses. Other packages' tests build the same policy the
// same way.
func docsAsPublicPolicy() *AddressPolicy {
	docs := map[string]bool{"192.0.2.0/24": true, "198.51.100.0/24": true, "203.0.113.0/24": true, "2001:db8::/32": true}
	var rules []AddressPolicyRule
	for _, r := range DefaultAddressPolicyRules() {
		if !docs[r.Prefix.String()] {
			rules = append(rules, r)
		}
	}
	return NewAddressPolicy(rules)
}

func TestAddressPolicyClassifiesEachRange(t *testing.T) {
	p := docsAsPublicPolicy()
	cases := []struct{ addr, code string }{
		{"192.0.2.10", ""},
		{"198.51.100.7", ""},
		{"203.0.113.10", ""},
		{"2001:db8::10", ""},
		{"100.64.32.10", ""}, // CGNAT is allowed (with a warning)
		{"0.0.0.0", "reserved"},
		{"0.1.2.3", "reserved"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "reserved"},
		{"192.0.0.8", "reserved"},
		{"198.18.0.1", "reserved"},
		{"192.88.99.1", "reserved"},
		{"::", "reserved"},
		{"100::1", "reserved"},
		{"2001::1", "reserved"},
		{"64:ff9b::c000:20a", "reserved"},
		{"2002::1", "reserved"},
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback"},
		{"::1", "loopback"},
		{"10.9.8.7", "private"},
		{"172.16.5.4", "private"},
		{"172.31.255.254", "private"},
		{"192.168.99.1", "private"},
		{"fd12:3456::1", "private"},
		{"169.254.1.1", "link_local"},
		{"fe80::1", "link_local"},
		{"224.0.0.1", "multicast"},
		{"239.1.2.3", "multicast"},
		{"ff02::1", "multicast"},
		{"104.16.0.1", "cdn"},
		{"2606:4700::1", "cdn"},
	}
	for _, tc := range cases {
		if got := p.Classify(netip.MustParseAddr(tc.addr)); got != tc.code {
			t.Errorf("Classify(%s) = %q, want %q", tc.addr, got, tc.code)
		}
	}
}

// A hosts-file lookup returns IPv4 as ::ffff:a.b.c.d. The IPv4 rows must
// still apply (an IPv4 prefix never contains the mapped form).
func TestAddressPolicyUnmapsBeforeClassifying(t *testing.T) {
	p := docsAsPublicPolicy()
	cases := []struct{ addr, code string }{
		{"::ffff:100.64.32.10", ""},
		{"::ffff:10.9.8.7", "private"},
		{"::ffff:127.0.0.1", "loopback"},
		{"::ffff:0.0.0.0", "reserved"},
		{"::ffff:104.16.0.1", "cdn"},
	}
	for _, tc := range cases {
		if got := p.Classify(netip.MustParseAddr(tc.addr)); got != tc.code {
			t.Errorf("Classify(%s) = %q, want %q", tc.addr, got, tc.code)
		}
	}
	if got := DefaultAddressPolicy().Classify(netip.MustParseAddr("::ffff:192.0.2.1")); got != "reserved" {
		t.Errorf("default Classify(::ffff:192.0.2.1) = %q, want reserved", got)
	}
}

// Production has no exception for documentation ranges.
func TestDefaultAddressPolicyRefusesDocumentationRanges(t *testing.T) {
	for _, a := range []string{"192.0.2.1", "198.51.100.7", "203.0.113.10", "2001:db8::1"} {
		if got := DefaultAddressPolicy().Classify(netip.MustParseAddr(a)); got != "reserved" {
			t.Errorf("default Classify(%s) = %q, want reserved", a, got)
		}
	}
	var nilPolicy *AddressPolicy
	if got := nilPolicy.Classify(netip.MustParseAddr("192.0.2.1")); got != "reserved" {
		t.Errorf("a nil policy must be the default one, got %q", got)
	}
}

func TestDefaultAddressPolicyRefusesEveryCloudflareRange(t *testing.T) {
	for _, r := range CloudflareRanges {
		prefix := netip.MustParsePrefix(r)
		if got := DefaultAddressPolicy().Classify(prefix.Addr()); got != "cdn" {
			t.Errorf("Classify(%s) = %q, want cdn", prefix.Addr(), got)
		}
	}
}

func TestAddressPolicyRefusesWhatCannotBeWritten(t *testing.T) {
	p := docsAsPublicPolicy()
	if got := p.Classify(netip.Addr{}); got != "reserved" {
		t.Errorf("Classify(invalid) = %q, want reserved", got)
	}
	for _, a := range []string{"fe80::1%eth0", "2001:db8::1%eth0"} {
		if got := p.Classify(netip.MustParseAddr(a)); got != "link_local" {
			t.Errorf("Classify(%s) = %q, want link_local: a zone cannot go into an allow line", a, got)
		}
	}
}

func TestAddressPolicyRulesAreCopies(t *testing.T) {
	rules := DefaultAddressPolicyRules()
	rules[0] = AddressPolicyRule{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Code: "changed"}
	if got := DefaultAddressPolicy().Classify(netip.MustParseAddr("0.0.0.1")); got != "reserved" {
		t.Fatalf("changing the returned rules changed the default policy: %q", got)
	}
	in := []AddressPolicyRule{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Code: "private"}}
	p := NewAddressPolicy(in)
	in[0].Code = "changed"
	if got := p.Classify(netip.MustParseAddr("10.9.8.7")); got != "private" {
		t.Fatalf("NewAddressPolicy kept the caller's slice: %q", got)
	}
}

func TestIsCGNAT(t *testing.T) {
	for addr, want := range map[string]bool{
		"100.63.255.255":      false,
		"100.64.0.0":          true,
		"100.64.32.10":        true,
		"100.127.255.255":     true,
		"100.128.0.0":         false,
		"::ffff:100.64.32.10": true,
		"2001:db8::1":         false,
	} {
		if got := IsCGNAT(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsCGNAT(%s) = %v, want %v", addr, got, want)
		}
	}
}
