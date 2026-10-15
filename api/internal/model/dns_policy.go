package model

import "net/netip"

// Codes the address policy refuses an address with. They are stored and
// shown in place of the address itself, which is never kept (it may reveal
// a private network).
const (
	addressPolicyReserved  = "reserved"
	addressPolicyLoopback  = "loopback"
	addressPolicyPrivate   = "private"
	addressPolicyLinkLocal = "link_local"
	addressPolicyMulticast = "multicast"
	addressPolicyCDN       = "cdn"
)

// AddressPolicyRule refuses every address in Prefix with Code.
type AddressPolicyRule struct {
	Prefix netip.Prefix
	Code   string
}

// AddressPolicy decides which resolved addresses a domain entry may publish:
// a list of refusal rules, checked in order. An address no rule matches is
// allowed. Production uses DefaultAddressPolicy. Tests build their own with
// NewAddressPolicy from DefaultAddressPolicyRules minus the documentation
// rows (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), so
// documentation addresses can stand in for public ones.
type AddressPolicy struct {
	rules []AddressPolicyRule
}

// NewAddressPolicy returns a policy that refuses what reject lists. Classify
// answers with the first matching rule's code. The slice is copied.
func NewAddressPolicy(reject []AddressPolicyRule) *AddressPolicy {
	return &AddressPolicy{rules: append([]AddressPolicyRule(nil), reject...)}
}

var defaultAddressPolicy = NewAddressPolicy(defaultAddressPolicyRules())

// DefaultAddressPolicy is the production policy: DefaultAddressPolicyRules.
func DefaultAddressPolicy() *AddressPolicy {
	return defaultAddressPolicy
}

// DefaultAddressPolicyRules returns a fresh copy of the production rules in
// their fixed order: reserved, loopback, private, link_local, multicast, then
// Cloudflare's ranges as cdn. 100.64.0.0/10 (CGNAT, Tailscale and the like)
// is not refused; IsCGNAT lets the caller attach a warning instead.
func DefaultAddressPolicyRules() []AddressPolicyRule {
	return defaultAddressPolicyRules()
}

func defaultAddressPolicyRules() []AddressPolicyRule {
	var rules []AddressPolicyRule
	add := func(code string, prefixes ...string) {
		for _, p := range prefixes {
			rules = append(rules, AddressPolicyRule{Prefix: netip.MustParsePrefix(p), Code: code})
		}
	}
	add(addressPolicyReserved,
		"0.0.0.0/8", "240.0.0.0/4", "192.0.0.0/24", "198.18.0.0/15", "192.88.99.0/24",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"::/128", "2001:db8::/32", "100::/64", "2001::/23", "64:ff9b::/96", "2002::/16")
	add(addressPolicyLoopback, "127.0.0.0/8", "::1/128")
	add(addressPolicyPrivate, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
	add(addressPolicyLinkLocal, "169.254.0.0/16", "fe80::/10")
	add(addressPolicyMulticast, "224.0.0.0/4", "ff00::/8")
	add(addressPolicyCDN, CloudflareRanges...)
	return rules
}

// Classify returns the code of the first rule that refuses a, or "" when a
// may be published. An IPv4-mapped IPv6 address ("::ffff:10.0.0.5", what a
// hosts-file lookup returns) is unmapped first: an IPv4 prefix never contains
// the mapped form, so without that the IPv4 rows would let it through. An
// invalid address is "reserved" and an address with a zone "link_local":
// neither can be written into an nginx allow line. A nil policy is the
// default one.
func (p *AddressPolicy) Classify(a netip.Addr) string {
	if p == nil {
		p = defaultAddressPolicy
	}
	if !a.IsValid() {
		return addressPolicyReserved
	}
	if a.Zone() != "" {
		return addressPolicyLinkLocal
	}
	a = a.Unmap()
	for _, r := range p.rules {
		if r.Prefix.Contains(a) {
			return r.Code
		}
	}
	return ""
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// IsCGNAT reports whether a, unmapped, is in 100.64.0.0/10: allowed, but
// worth a "cgnat" note (an overlay network address such as Tailscale's).
func IsCGNAT(a netip.Addr) bool {
	return cgnatPrefix.Contains(a.Unmap())
}
