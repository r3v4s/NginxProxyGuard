package model

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// alRule is a request rule; kind is optional.
func alRule(directive, address string, kind ...string) CreateAccessListItemRequest {
	r := CreateAccessListItemRequest{Directive: directive, Address: address}
	if len(kind) > 0 {
		r.Kind = kind[0]
	}
	return r
}

// describeRules shows checked rules as "kind directive address hostname sort_order".
func describeRules(items []CreateAccessListItemRequest) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fmt.Sprintf("%s %s %s %s %d", it.Kind, it.Directive, it.Address, it.Hostname, it.SortOrder))
	}
	return out
}

// expectItemError asserts that err refuses the rule at field with code.
func expectItemError(t *testing.T, err error, field, code string) {
	t.Helper()
	var ie *AccessListItemError
	if !errors.As(err, &ie) {
		t.Fatalf("err = %v, want an *AccessListItemError on %s", err, field)
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v does not match ErrInvalidInput", err)
	}
	if ie.Field != field || ie.Code != code || !strings.HasPrefix(ie.Message, field) {
		t.Errorf("error = %+v, want field %s, code %q and a message that starts with the field", ie, field, code)
	}
}

// A domain is stored as the placeholder (deny, all, name) that versions
// without domains read as deny all, after the address rules.
func TestAccessListDomainRuleIsStoredAsThePlaceholder(t *testing.T) {
	req := &CreateAccessListRequest{Name: "partners", Items: []CreateAccessListItemRequest{
		alRule("allow", " Partner.Example.COM. ", AccessListKindHostname),
		alRule("allow", "192.0.2.10"),
	}}
	if err := ValidateCreateAccessListRequest(req); err != nil {
		t.Fatal(err)
	}
	want := []string{"address allow 192.0.2.10  0", "hostname deny all partner.example.com 1"}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("stored as %q, want %q", got, want)
	}
}

// Only kind=hostname makes a domain, only as allow, once per list, and never
// behind a rule that denies everyone. The field is the
// rule's position in the request.
func TestAccessListDomainRulesAreRefused(t *testing.T) {
	cases := []struct {
		name        string
		items       []CreateAccessListItemRequest
		field, code string
	}{
		{"domain without kind", []CreateAccessListItemRequest{alRule("allow", "192.0.2.1"), alRule("allow", "partner.example.com")},
			"items[1].address", AccessListCodeHostnameNeedsKind},
		{"domain as kind address", []CreateAccessListItemRequest{alRule("allow", "partner.example.com", AccessListKindAddress)},
			"items[0].address", AccessListCodeHostnameNeedsKind},
		{"domain as a legacy rule that is not stored", []CreateAccessListItemRequest{alRule("allow", "partner.example.com", AccessListKindLegacy)},
			"items[0].address", AccessListCodeLegacyNotInList},
		{"denied domain without kind", []CreateAccessListItemRequest{alRule("deny", "partner.example.com")},
			"items[0].directive", AccessListCodeDenyHostname},
		{"denied domain", []CreateAccessListItemRequest{alRule("deny", "partner.example.com", AccessListKindHostname)},
			"items[0].directive", AccessListCodeDenyHostname},
		{"same domain twice", []CreateAccessListItemRequest{
			alRule("allow", "partner.example.com", AccessListKindHostname), alRule("allow", "192.0.2.1"),
			alRule("allow", "PARTNER.example.com.", AccessListKindHostname)},
			"items[2].address", AccessListCodeDuplicateHostname},
		{"deny all next to a domain", []CreateAccessListItemRequest{
			alRule("allow", "192.0.2.1"), alRule("deny", "all"), alRule("allow", "partner.example.com", AccessListKindHostname)},
			"items[1].address", AccessListCodeDenyAllWithHostname},
		// Stored, the deny all would be rule 1; the error names the rule by its
		// request position, never the domain.
		{"deny all after a domain, named by its request position", []CreateAccessListItemRequest{
			alRule("allow", "partner.example.com", AccessListKindHostname), alRule("allow", "192.0.2.1"), alRule("deny", "all")},
			"items[2].address", AccessListCodeDenyAllWithHostname},
		{"unknown kind", []CreateAccessListItemRequest{alRule("allow", "192.0.2.1", "ip")}, "items[0].kind", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectItemError(t, ValidateCreateAccessListRequest(&CreateAccessListRequest{Name: "n", Items: tc.items}), tc.field, tc.code)
		})
	}
}

// A domain that breaks a name rule is refused with that rule's
// code, which the UI shows at the row.
func TestAccessListDomainNameRulesCarryTheirCode(t *testing.T) {
	for _, bad := range []string{"*.example.com", "partner_x.example.com", "partner", "printer.local", "203.0.113.300", "partner.example.com:8443"} {
		t.Run(bad, func(t *testing.T) {
			ne, ok := IsDNSNameError(ValidateDNSName(NormalizeDNSName(bad)))
			if !ok {
				t.Fatalf("%q passes the name rules", bad)
			}
			err := ValidateCreateAccessListRequest(&CreateAccessListRequest{Name: "n", Items: []CreateAccessListItemRequest{
				alRule("allow", "192.0.2.1"), alRule("allow", bad, AccessListKindHostname),
			}})
			expectItemError(t, err, "items[1].address", ne.Code)
		})
	}
}

// A rule sent back as it was read keeps what it is: a legacy rule stays
// legacy (it never becomes a working domain by an unrelated save), and an
// older client that drops kind keeps the list's domains. A name in
// neither form is new and needs kind=hostname.
func TestAccessListUpdateKeepsRulesSentBackAsTheyWereRead(t *testing.T) {
	stored := []AccessListItem{
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "allow", Address: "old.example.com"},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}
	req := &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("allow", "192.0.2.10"), alRule("allow", "old.example.com"), alRule("allow", "Partner.Example.com"),
	}}
	if err := ValidateUpdateAccessListRequest(req, stored); err != nil {
		t.Fatal(err)
	}
	want := []string{"address allow 192.0.2.10  0", "legacy allow old.example.com  1", "hostname deny all partner.example.com 2"}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("saved as %q, want %q", got, want)
	}

	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{alRule("allow", "old.example.com"), alRule("allow", "new.example.com")}}
	expectItemError(t, ValidateUpdateAccessListRequest(req, stored), "items[1].address", AccessListCodeHostnameNeedsKind)

	// The stored legacy rule is an allow: a deny of the same name is not it.
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{alRule("deny", "old.example.com")}}
	expectItemError(t, ValidateUpdateAccessListRequest(req, stored), "items[0].directive", AccessListCodeDenyHostname)

	// A legacy deny is written as deny all: next to a domain it is refused.
	storedDeny := []AccessListItem{{Directive: "deny", Address: "blocked.example.com"}}
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("deny", "blocked.example.com"), alRule("allow", "partner.example.com", AccessListKindHostname),
	}}
	expectItemError(t, ValidateUpdateAccessListRequest(req, storedDeny), "items[0].address", AccessListCodeDenyAllWithHostname)

	// A legacy rule can read the same as a domain of the list: both are
	// allow partner.example.com, the legacy rule first. Sent back without
	// kind, each stored legacy rule takes one rule and the next one is the
	// domain, so neither is lost.
	storedPair := []AccessListItem{
		{Directive: "allow", Address: "partner.example.com"},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("allow", "partner.example.com"), alRule("allow", "partner.example.com"),
	}}
	if err := ValidateUpdateAccessListRequest(req, storedPair); err != nil {
		t.Fatal(err)
	}
	want = []string{"legacy allow partner.example.com  0", "hostname deny all partner.example.com 1"}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("a legacy rule and a domain that read the same: saved as %q, want %q", got, want)
	}

	// Two legacy rules of the same text, and no domain, stay two legacy
	// rules. A third copy was never read: it is a new name.
	storedTwice := []AccessListItem{
		{Directive: "allow", Address: "old.example.com"},
		{Directive: "allow", Address: "old.example.com"},
	}
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("allow", "old.example.com"), alRule("allow", "old.example.com"),
	}}
	if err := ValidateUpdateAccessListRequest(req, storedTwice); err != nil {
		t.Fatal(err)
	}
	want = []string{"legacy allow old.example.com  0", "legacy allow old.example.com  1"}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("two legacy rules of the same text: saved as %q, want %q", got, want)
	}
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("allow", "old.example.com"), alRule("allow", "old.example.com"), alRule("allow", "old.example.com"),
	}}
	expectItemError(t, ValidateUpdateAccessListRequest(req, storedTwice), "items[2].address", AccessListCodeHostnameNeedsKind)
}

// kind address takes only an IP address, a CIDR range or all. kind legacy
// keeps a stored legacy rule exactly as it is, and refuses a rule the list
// does not hold: neither turns a name into an address or a domain.
func TestAccessListKindAddressAndLegacyRules(t *testing.T) {
	stored := []AccessListItem{
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "allow", Address: "Old.Example.COM"},
		{Directive: "deny", Address: "bad.example.com"},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}
	req := &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{
		alRule("allow", "192.0.2.10", AccessListKindAddress),
		alRule("deny", "2001:db8::/32", AccessListKindAddress),
		alRule("allow", "Old.Example.COM", AccessListKindLegacy),
		alRule("deny", "bad.example.com", AccessListKindLegacy),
		alRule("deny", "all", AccessListKindAddress),
	}}
	if err := ValidateUpdateAccessListRequest(req, stored); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"address allow 192.0.2.10  0",
		"address deny 2001:db8::/32  1",
		"legacy allow Old.Example.COM  2",
		"legacy deny bad.example.com  3",
		"address deny all  4",
	}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("saved as %q, want %q", got, want)
	}

	for _, tc := range []struct {
		name        string
		item        CreateAccessListItemRequest
		field, code string
	}{
		{"a legacy rule the list does not hold", alRule("allow", "other.example.com", AccessListKindLegacy), "items[0].address", AccessListCodeLegacyNotInList},
		{"a stored legacy allow sent as a deny", alRule("deny", "Old.Example.COM", AccessListKindLegacy), "items[0].address", AccessListCodeLegacyNotInList},
		{"a domain of the list sent as legacy", alRule("allow", "partner.example.com", AccessListKindLegacy), "items[0].address", AccessListCodeLegacyNotInList},
		{"an address sent as legacy", alRule("allow", "192.0.2.10", AccessListKindLegacy), "items[0].address", AccessListCodeLegacyNotInList},
		{"a stored legacy rule sent as an address", alRule("allow", "Old.Example.COM", AccessListKindAddress), "items[0].address", AccessListCodeHostnameNeedsKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{tc.item}}
			expectItemError(t, ValidateUpdateAccessListRequest(req, stored), tc.field, tc.code)
		})
	}
}

// Rules keep the order nginx checks them in, (sort_order, request position),
// address rules first and domains after; sort_order is renumbered.
func TestAccessListRulesAreOrderedAddressesFirst(t *testing.T) {
	req := &CreateAccessListRequest{Name: "n", Items: []CreateAccessListItemRequest{
		{Directive: "allow", Address: "a.example.com", Kind: AccessListKindHostname, SortOrder: 0},
		{Directive: "allow", Address: "192.0.2.1", SortOrder: 2},
		{Directive: "deny", Address: "198.51.100.0/24", SortOrder: 1},
		{Directive: "allow", Address: "b.example.com", Kind: AccessListKindHostname, SortOrder: 1},
		{Directive: "allow", Address: "192.0.2.2", SortOrder: 1},
	}}
	if err := ValidateCreateAccessListRequest(req); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"address deny 198.51.100.0/24  0",
		"address allow 192.0.2.2  1",
		"address allow 192.0.2.1  2",
		"hostname deny all a.example.com 3",
		"hostname deny all b.example.com 4",
	}
	if got := describeRules(req.Items); !reflect.DeepEqual(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
}

// An update without items keeps the stored rules; an empty list clears them.
func TestAccessListUpdateWithoutItemsKeepsThem(t *testing.T) {
	stored := []AccessListItem{{Directive: "allow", Address: "192.0.2.10"}}
	req := &UpdateAccessListRequest{}
	if err := ValidateUpdateAccessListRequest(req, stored); err != nil || req.Items != nil {
		t.Errorf("no items: err %v, items %v, want nil items (keep)", err, req.Items)
	}
	req = &UpdateAccessListRequest{Items: []CreateAccessListItemRequest{}}
	if err := ValidateUpdateAccessListRequest(req, stored); err != nil || req.Items == nil || len(req.Items) != 0 {
		t.Errorf("empty items: err %v, items %#v, want an empty list (clear)", err, req.Items)
	}
}

// The kind of a stored rule follows what the config does with it.
func TestAccessListItemKindOfStoredRules(t *testing.T) {
	cases := []struct {
		item         AccessListItem
		kind, effect string
	}{
		{AccessListItem{Directive: "deny", Address: "all", Hostname: "partner.example.com"}, AccessListKindHostname, ""},
		{AccessListItem{Directive: "allow", Address: "192.0.2.0/24"}, AccessListKindAddress, ""},
		{AccessListItem{Directive: "deny", Address: " all "}, AccessListKindAddress, ""},
		{AccessListItem{Directive: "allow", Address: "old.example.com"}, AccessListKindLegacy, AccessListEffectIgnored},
		{AccessListItem{Directive: "deny", Address: "old.example.com"}, AccessListKindLegacy, AccessListEffectDenyAll},
	}
	for _, tc := range cases {
		kind, effect := AccessListItemKind(tc.item), ""
		if kind == AccessListKindLegacy {
			effect = AccessListLegacyEffect(tc.item)
		}
		if kind != tc.kind || effect != tc.effect {
			t.Errorf("%+v: kind %q effect %q, want %q %q", tc.item, kind, effect, tc.kind, tc.effect)
		}
	}
}
