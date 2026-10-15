package dnsentry

import (
	"fmt"
	"net/netip"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// docsAsPublic is the production policy without the documentation rows, so
// 192.0.2.x, 198.51.100.x, 203.0.113.x and 2001:db8::/32 stand in for public
// addresses (the production policy refuses them as reserved).
func docsAsPublic() *model.AddressPolicy {
	docs := map[string]bool{"192.0.2.0/24": true, "198.51.100.0/24": true, "203.0.113.0/24": true, "2001:db8::/32": true}
	var rules []model.AddressPolicyRule
	for _, r := range model.DefaultAddressPolicyRules() {
		if !docs[r.Prefix.String()] {
			rules = append(rules, r)
		}
	}
	return model.NewAddressPolicy(rules)
}

func okFamily(ss ...string) FamilyAnswer {
	return FamilyAnswer{Outcome: "ok", Addrs: addrs(ss...)}
}

func TestObserveAppliesThePolicyToEachFamily(t *testing.T) {
	a := Answer{
		V4:          okFamily("203.0.113.10", "10.9.8.7", "100.64.32.10"),
		V6:          okFamily("fe80::1", "fd12:3456::1"),
		CNAMEBefore: "partner.example.com",
		CNAMEAfter:  "partner.example.com",
	}
	o, notes := Observe(a, docsAsPublic(), 4)
	if o.V4.Outcome != "ok" || fmt.Sprint(o.V4.Addrs) != "[100.64.32.10 203.0.113.10]" {
		t.Errorf("V4 = %+v, want the private address dropped and the rest kept", o.V4)
	}
	// fd12:3456::1 sorts before fe80::1: the first refused address names the code.
	if o.V6.Outcome != "rejected" || o.V6.Code != "private" || o.V6.Addrs != nil {
		t.Errorf("V6 = %+v, want rejected with the first refused address's code and no addresses", o.V6)
	}
	if !notes.PartialRejected || !notes.CGNAT {
		t.Errorf("notes = %+v, want partial_rejected and cgnat", notes)
	}
	if !o.CNAMEOK || o.Canonical != "partner.example.com" {
		t.Errorf("CNAME = %v %q", o.CNAMEOK, o.Canonical)
	}

	// The production policy refuses documentation addresses.
	o, notes = Observe(Answer{V4: okFamily("203.0.113.10")}, nil, 4)
	if o.V4.Outcome != "rejected" || o.V4.Code != "reserved" || notes.PartialRejected {
		t.Errorf("default policy: V4 = %+v notes %+v, want rejected reserved", o.V4, notes)
	}
}

// A family with more addresses than allowed is refused whole, before the
// policy: part of a large answer is not trusted.
func TestObserveRefusesTooManyAddressesWhole(t *testing.T) {
	five := okFamily("203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5")
	if o, _ := Observe(Answer{V4: five}, docsAsPublic(), 4); o.V4.Outcome != "rejected" || o.V4.Code != "too_many" {
		t.Errorf("five addresses, limit 4: %+v, want rejected too_many", o.V4)
	}
	if o, _ := Observe(Answer{V4: five}, docsAsPublic(), 5); o.V4.Outcome != "ok" || len(o.V4.Addrs) != 5 {
		t.Errorf("five addresses, limit 5: %+v", o.V4)
	}
	withPrivate := okFamily("203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "10.0.0.5")
	if o, notes := Observe(Answer{V4: withPrivate}, docsAsPublic(), 4); o.V4.Code != "too_many" || notes.PartialRejected {
		t.Errorf("an address the policy refuses still counts: %+v %+v, want too_many", o.V4, notes)
	}
	// The same address twice, once mapped, is one address.
	dup := okFamily("203.0.113.1", "::ffff:203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4")
	if o, _ := Observe(Answer{V4: dup}, docsAsPublic(), 4); o.V4.Outcome != "ok" || len(o.V4.Addrs) != 4 {
		t.Errorf("duplicates counted twice: %+v", o.V4)
	}
	// Below 1 is the default limit (4).
	if o, _ := Observe(Answer{V4: five}, docsAsPublic(), 0); o.V4.Code != "too_many" {
		t.Errorf("limit 0: %+v, want the default limit", o.V4)
	}
}

// A hosts-file lookup returns IPv4 as ::ffff:a.b.c.d. It must meet the IPv4
// rows and come out as a.b.c.d: nginx accepts a mapped address in an allow
// line, but it never matches an IPv4 client.
func TestObserveUnmapsHostsFileAddresses(t *testing.T) {
	a := Answer{V4: FamilyAnswer{Outcome: "ok", Addrs: []netip.Addr{
		netip.MustParseAddr("::ffff:10.9.8.7"),
		netip.MustParseAddr("::ffff:100.64.32.10"),
	}}}
	o, notes := Observe(a, docsAsPublic(), 4)
	if o.V4.Outcome != "ok" || fmt.Sprint(o.V4.Addrs) != "[100.64.32.10]" || !notes.PartialRejected || !notes.CGNAT {
		t.Errorf("V4 = %+v %+v, want [100.64.32.10] with the private address dropped", o.V4, notes)
	}
	// A mapped IPv4 address in an AAAA answer belongs to neither family.
	o, _ = Observe(Answer{V6: okFamily("::ffff:203.0.113.5")}, docsAsPublic(), 4)
	if o.V6.Outcome != "rejected" || o.V6.Code != "reserved" {
		t.Errorf("V6 = %+v, want rejected reserved", o.V6)
	}
}

func TestObservePassesFailuresThrough(t *testing.T) {
	a := Answer{
		V4: FamilyAnswer{Outcome: "transient", Code: "refused"},
		V6: FamilyAnswer{Outcome: "notfound", Code: "not_found"},
	}
	o, _ := Observe(a, docsAsPublic(), 4)
	if o.V4.Outcome != "transient" || o.V4.Code != "refused" || o.V4.Addrs != nil || o.V6.Outcome != "notfound" || o.V6.Code != "not_found" {
		t.Errorf("observation = %+v", o)
	}
	o, _ = Observe(Answer{V4: FamilyAnswer{Outcome: "ok"}, V6: FamilyAnswer{}}, docsAsPublic(), 4)
	if o.V4.Outcome != "notfound" || o.V6.Outcome != "transient" || o.V6.Code != "network" {
		t.Errorf("an ok answer without addresses and an empty one: %+v", o)
	}
}

func TestObserveCNAME(t *testing.T) {
	cases := []struct {
		before, after string
		ok            bool
		canonical     string
	}{
		{"edge.example.net", "edge.example.net", true, "edge.example.net"},
		{"Edge.Example.NET.", "edge.example.net", true, "edge.example.net"}, // 0x20 case and the dot are no change
		{"edge.example.net", "other.example.net", false, ""},
		{"", "edge.example.net", false, ""},
		{"edge.example.net", "", false, ""},
		{"", "", false, ""},
	}
	for _, tc := range cases {
		o, _ := Observe(Answer{CNAMEBefore: tc.before, CNAMEAfter: tc.after}, docsAsPublic(), 4)
		if o.CNAMEOK != tc.ok || o.Canonical != tc.canonical {
			t.Errorf("CNAME %q then %q: %v %q, want %v %q", tc.before, tc.after, o.CNAMEOK, o.Canonical, tc.ok, tc.canonical)
		}
	}
}
