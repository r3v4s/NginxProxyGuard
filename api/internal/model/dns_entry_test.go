package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// dnsNameCheck is the CHECK on access_list_items.hostname and
// dns_entry_states.hostname (001_init.sql).
var dnsNameCheck = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// kelvinSign is U+212A KELVIN SIGN; strings.ToLower turns it into an ASCII "k".
var kelvinSign = string(rune(0x212A))

func dnsLabelOf(n int) string { return strings.Repeat("a", n) }

// dnsNameOfLength builds a valid name of exactly n characters (n >= 9).
func dnsNameOfLength(n int) string {
	var labels []string
	left := n - len(".example")
	for left > 0 {
		size := min(left, 63)
		if left-size == 1 { // never end on a dot with no label after it
			size--
		}
		labels = append(labels, dnsLabelOf(size))
		left -= size + 1
	}
	return strings.Join(labels, ".") + ".example"
}

func TestNormalizeDNSName(t *testing.T) {
	cases := map[string]string{
		"  Partner.Example.COM.  ":    "partner.example.com",
		"partner.example.com.":        "partner.example.com",
		"partner.example.com..":       "partner.example.com.", // only one dot is stripped
		"\tpartner.e2e.example\n":     "partner.e2e.example",
		kelvinSign + "ey.example.com": kelvinSign + "ey.example.com", // stays non-ASCII, never "key..."
		"":                            "",
	}
	for in, want := range cases {
		if got := NormalizeDNSName(in); got != want {
			t.Errorf("NormalizeDNSName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Inputs go through NormalizeDNSName first, as every caller does.
func TestValidateDNSNameAfterNormalize(t *testing.T) {
	accepted := []string{
		"partner.example.com",
		"Partner.Example.COM.", // upper case and one trailing dot normalize away
		"partner.e2e.example",  // .example stays usable for tests
		"a-b.example",
		"ab--cd.example",
		"203-0-113-10.example", // digits in labels, letters in the TLD
		"xn--bcher-kva.example",
		"partner.example.xn--9t4b11yi5a",
		dnsLabelOf(63) + ".example",
		dnsNameOfLength(253),
	}
	for _, in := range accepted {
		name := NormalizeDNSName(in)
		if err := ValidateDNSName(name); err != nil {
			t.Errorf("ValidateDNSName(%q) = %v, want accepted", name, err)
			continue
		}
		if !dnsNameCheck.MatchString(name) {
			t.Errorf("accepted %q fails the hostname CHECK, so storing it would abort the transaction", name)
		}
	}

	refused := []struct{ in, code string }{
		{"", "empty"},
		{"   ", "empty"},
		{"203.0.113.10", "looks_like_ip"},
		{"203.0.113.0/24", "looks_like_ip"},
		{"2001:db8::1", "looks_like_ip"},
		{"::ffff:192.0.2.1", "looks_like_ip"},
		{"all", "looks_like_ip"},
		{"ALL", "looks_like_ip"},
		{"203.0.113.300", "looks_like_ip"},
		{"partner.example.123", "looks_like_ip"},
		{"partner .example.com", "whitespace"},
		{"partner\n.example.com", "whitespace"},
		{"partner\x00.example.com", "whitespace"},
		{"partner" + string(rune(0x2028)) + ".example.com", "whitespace"},
		{"bücher.example", "non_ascii"},
		{kelvinSign + "ey.example.com", "non_ascii"},
		{"partner" + string(rune(0x200b)) + ".example.com", "non_ascii"},
		{"*.example.com", "wildcard"},
		{"_dmarc.example.com", "underscore"},
		{"https://partner.example.com/", "url_or_port"},
		{"partner.example.com:8443", "url_or_port"},
		{"203.0.113.10:8443", "url_or_port"},
		{"user@example.com", "url_or_port"},
		{"partner.example.com/x", "url_or_port"},
		{"partner.example.com?x", "url_or_port"},
		{"a#b.example.com", "url_or_port"},
		{"[2001:db8::1]", "url_or_port"},
		{`a\b.example.com`, "url_or_port"},
		{dnsNameOfLength(254), "too_long"},
		{"a;b.example.com", "label"},
		{"a{b}.example.com", "label"},
		{"partner..example.com", "label"},
		{".example.com", "label"},
		{"partner.example.com..", "label"},
		{dnsLabelOf(64) + ".example", "label"},
		{"-partner.example.com", "hyphen"},
		{"partner-.example.com", "hyphen"},
		{"partner", "single_label"},
		{"localhost", "single_label"},
		{"example.c0m", "tld"},
		{"example.c-m", "tld"},
		{"nas.local", "internal_suffix"},
		{"router.home.arpa", "internal_suffix"},
		{"home.arpa", "internal_suffix"},
		{"printer.lan", "internal_suffix"},
		{"api.internal", "internal_suffix"},
		{"svc.corp", "internal_suffix"},
		{"x.test", "internal_suffix"},
		{"site.onion", "internal_suffix"},
	}
	for _, tc := range refused {
		name := NormalizeDNSName(tc.in)
		err := ValidateDNSName(name)
		e, ok := IsDNSNameError(err)
		if !ok {
			t.Errorf("ValidateDNSName(%q) = %v, want a *DNSNameError with code %q", name, err, tc.code)
			continue
		}
		if e.Code != tc.code {
			t.Errorf("ValidateDNSName(%q) code = %q, want %q", name, e.Code, tc.code)
		}
		if e.Name != name {
			t.Errorf("ValidateDNSName(%q) Name = %q", name, e.Name)
		}
	}
}

// ValidateDNSName expects a normalized name: one that still has upper case
// letters or a trailing dot is refused, never stored as it is.
func TestValidateDNSNameRefusesAnUnnormalizedName(t *testing.T) {
	for _, name := range []string{"Partner.example.com", "partner.example.com."} {
		e, ok := IsDNSNameError(ValidateDNSName(name))
		if !ok || e.Code != "label" {
			t.Errorf("ValidateDNSName(%q) = %v, want code label", name, e)
		}
	}
}

func TestDNSNameErrorHasASentenceForEveryCode(t *testing.T) {
	codes := []string{"empty", "too_long", "label", "hyphen", "single_label", "tld", "looks_like_ip",
		"wildcard", "underscore", "url_or_port", "whitespace", "non_ascii", "internal_suffix"}
	seen := map[string]string{}
	for _, code := range codes {
		msg := (&DNSNameError{Code: code, Name: "x.example"}).Error()
		if msg == (&DNSNameError{Code: "no-such-code"}).Error() {
			t.Errorf("code %q has no sentence of its own", code)
		}
		if strings.Contains(msg, "x.example") {
			t.Errorf("code %q: the sentence repeats the name: %q", code, msg)
		}
		if other, dup := seen[msg]; dup {
			t.Errorf("codes %q and %q share the sentence %q", other, code, msg)
		}
		seen[msg] = code
	}
}

func TestIsDNSNameErrorFindsAWrappedError(t *testing.T) {
	err := fmt.Errorf("items[2].address: %w", ValidateDNSName("partner"))
	e, ok := IsDNSNameError(err)
	if !ok || e.Code != "single_label" || e.Name != "partner" {
		t.Fatalf("IsDNSNameError(%v) = %+v, %v", err, e, ok)
	}
	if _, ok := IsDNSNameError(errors.New("partner")); ok {
		t.Fatal("a plain error is not a DNSNameError")
	}
	if _, ok := IsDNSNameError(nil); ok {
		t.Fatal("nil is not a DNSNameError")
	}
}

func TestDNSScopes(t *testing.T) {
	const id = "0b5e0c3a-8f2d-4c1e-9a7b-6d5e4f3a2b1c"
	if got := AccessListDNSScope(id); got != "acl:"+id {
		t.Fatalf("AccessListDNSScope = %q", got)
	}
	ok := []struct{ scope, kind, owner string }{
		{"acl:" + id, "acl", id},
		{"uri:" + id, "uri", id},
		{"uri:global", "uri", "global"},
		{"prio:global", "prio", "global"},
		{"rl:" + id, "rl", id},
		{"trusted", "trusted", ""},
	}
	for _, tc := range ok {
		kind, owner, parsed := ParseDNSScope(tc.scope)
		if !parsed || kind != tc.kind || owner != tc.owner {
			t.Errorf("ParseDNSScope(%q) = %q, %q, %v; want %q, %q, true", tc.scope, kind, owner, parsed, tc.kind, tc.owner)
		}
	}
	for _, scope := range []string{
		"", "acl", "acl:", "acl:global", "ACL:" + id, "acl:" + strings.ToUpper(id), "acl:" + id + " ",
		" acl:" + id, "acl:" + id + ":x", "acl:not-a-uuid", "trusted:", "trusted:global", "uri:",
		"uri:Global", "geo:" + id, "acl:{" + id + "}",
	} {
		if kind, owner, parsed := ParseDNSScope(scope); parsed {
			t.Errorf("ParseDNSScope(%q) = %q, %q, true; want ok=false", scope, kind, owner)
		}
	}
}

func dnsJSONKeys(t *testing.T, v interface{}) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dnsSameKeys(t *testing.T, what string, got, want []string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s JSON keys = %v, want %v", what, got, want)
	}
}

// The UI reads these names.
func TestDNSEntryStatusJSONKeys(t *testing.T) {
	dnsSameKeys(t, "DNSEntryStatus", dnsJSONKeys(t, DNSEntryStatus{}), []string{
		"hostname", "status", "review_reason", "disabled", "addresses", "pending_addresses", "next_apply_at",
		"applied", "revoke_pending", "blocked_reason", "blocking_file", "observed_addresses", "canonical_name",
		"observed_canonical_name", "families", "warnings", "error_code", "stale_until", "last_checked_at",
		"last_changed_at",
	})
	dnsSameKeys(t, "DNSFamilyStatus without a code", dnsJSONKeys(t, DNSFamilyStatus{State: "ok"}), []string{"state"})
	dnsSameKeys(t, "DNSApplyState", dnsJSONKeys(t, DNSApplyState{}), []string{
		"last_dns_reload_at", "pending_additions", "revoke_pending", "blocked_outcome", "blocked_detail",
		"blocking_file", "next_retry_at",
	})
	dnsSameKeys(t, "DNSApplyResponse", dnsJSONKeys(t, DNSApplyResponse{}), []string{"outcome", "detail", "blocking_file"})
}

// The overview entry carries the status fields at its top level, next to the
// uses, not under a nested key.
func TestDNSEntryOverviewEntryInlinesTheStatus(t *testing.T) {
	entry := DNSEntryOverviewEntry{DNSEntryStatus: DNSEntryStatus{Hostname: "partner.example.com"}}
	keys := dnsJSONKeys(t, entry)
	want := append(dnsJSONKeys(t, DNSEntryStatus{}), "uses", "hidden_uses", "login_bypass_hosts")
	dnsSameKeys(t, "DNSEntryOverviewEntry", keys, want)
	b, _ := json.Marshal(entry)
	if !strings.Contains(string(b), `"hostname":"partner.example.com"`) {
		t.Fatalf("hostname is not at the top level: %s", b)
	}
}
