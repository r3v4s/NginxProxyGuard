package model

import (
	"errors"
	"strings"
	"testing"
)

func TestSingleLine(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"Office #2 (Seoul)":         "Office #2 (Seoul)",
		"사무실 허용 목록":                 "사무실 허용 목록",
		"first line\nsecond line":   "first line second line",
		"first line\r\nsecond line": "first line second line",
		"tab\there":                 "tab here",
		"a\u2028b\u0085c":           "a b c",
		"\n\nleading":               " leading",
	}
	for in, want := range cases {
		if got := SingleLine(in); got != want {
			t.Errorf("SingleLine(%q) = %q, want %q", in, got, want)
		}
		if HasLineBreakOrControl(SingleLine(in)) {
			t.Errorf("SingleLine(%q) still holds a line break or control character", in)
		}
	}
}

func TestValidateSingleLine(t *testing.T) {
	if err := ValidateSingleLine("name", "Office #2; Seoul {main}", 0); err != nil {
		t.Errorf("plain text rejected: %v", err)
	}
	for _, bad := range []string{"first line\nsecond line", "a\rb", "a\x00b", "a\x7fb", "a\u2029b"} {
		err := ValidateSingleLine("name", bad, 0)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ValidateSingleLine(%q) = %v, want ErrInvalidInput", bad, err)
		} else if !strings.Contains(err.Error(), "name") {
			t.Errorf("error %q does not name the field", err)
		}
	}
	if err := ValidateSingleLine("name", strings.Repeat("x", 11), 10); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("over-long value: got %v, want ErrInvalidInput", err)
	}
}

func TestValidateAccessListRequest_AcceptsRulesNginxTakes(t *testing.T) {
	req := &CreateAccessListRequest{
		Name:        "Office #2",
		Description: "staff only; {VPN}",
		Items: []CreateAccessListItemRequest{
			{Directive: "allow", Address: "192.0.2.10"},
			{Directive: "allow", Address: " 192.0.2.0/24 ", Description: "office LAN"},
			{Directive: "allow", Address: "2001:db8::/32"},
			{Directive: "allow", Address: "::1"},
			{Directive: "deny", Address: "all"},
		},
	}
	if err := ValidateCreateAccessListRequest(req); err != nil {
		t.Fatalf("valid access list rejected: %v", err)
	}
	if got := req.Items[1].Address; got != "192.0.2.0/24" {
		t.Errorf("address saved as %q, want it trimmed", got)
	}
}

func TestValidateAccessListRequest_RejectsLineBreaksAndBadRules(t *testing.T) {
	item := func(directive, address, description string) []CreateAccessListItemRequest {
		return []CreateAccessListItemRequest{{Directive: directive, Address: address, Description: description}}
	}
	cases := []struct {
		name  string
		req   CreateAccessListRequest
		field string
	}{
		{"line break in name", CreateAccessListRequest{Name: "first line\nsecond line"}, "name"},
		{"line break in description", CreateAccessListRequest{Name: "n", Description: "a\r\nb"}, "description"},
		{"line break in rule description", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.1", "a\nb")}, "items[0].description"},
		{"long rule description", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.1", strings.Repeat("d", accessListRuleMaxDescription+1))}, "items[0].description"},
		{"unknown directive", CreateAccessListRequest{Name: "n", Items: item("permit", "192.0.2.1", "")}, "items[0].directive"},
		{"directive in capitals", CreateAccessListRequest{Name: "n", Items: item("ALLOW", "192.0.2.1", "")}, "items[0].directive"},
		{"host name", CreateAccessListRequest{Name: "n", Items: item("allow", "example.com", "")}, "items[0].address"},
		{"address with a separator", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.1;", "")}, "items[0].address"},
		{"address with a brace", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.1 {", "")}, "items[0].address"},
		{"two addresses", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.1 192.0.2.2", "")}, "items[0].address"},
		{"prefix out of range", CreateAccessListRequest{Name: "n", Items: item("allow", "192.0.2.0/33", "")}, "items[0].address"},
		{"all in capitals", CreateAccessListRequest{Name: "n", Items: item("deny", "ALL", "")}, "items[0].address"},
		{"empty address", CreateAccessListRequest{Name: "n", Items: item("deny", "  ", "")}, "items[0].address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCreateAccessListRequest(&tc.req)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("got %v, want ErrInvalidInput", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name %s", err, tc.field)
			}

			// The same values in an update.
			update := UpdateAccessListRequest{Name: &tc.req.Name, Description: &tc.req.Description, Items: tc.req.Items}
			if err := ValidateUpdateAccessListRequest(&update, nil); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("update: got %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestValidateUpdateAccessListRequest_ChecksOnlyWhatIsSent(t *testing.T) {
	if err := ValidateUpdateAccessListRequest(&UpdateAccessListRequest{}, nil); err != nil {
		t.Errorf("empty update rejected: %v", err)
	}
	name := "renamed"
	if err := ValidateUpdateAccessListRequest(&UpdateAccessListRequest{Name: &name}, nil); err != nil {
		t.Errorf("rename rejected: %v", err)
	}
}

func TestNormalizeCountryCode(t *testing.T) {
	for in, want := range map[string]string{
		"KR": "KR", "XK": "XK", "kr": "KR", "Kr": "KR", " cn ": "CN", "KR\n": "KR", "--": "--", " -- ": "--",
	} {
		if got, ok := NormalizeCountryCode(in); !ok || got != want {
			t.Errorf("NormalizeCountryCode(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "K", "KOR", "A1", "K R", "K\nR", "KR|CN", `K"R`, ".*", "-", "---", "한국", "\u017fk", "\u212aR"} {
		if got, ok := NormalizeCountryCode(in); ok {
			t.Errorf("NormalizeCountryCode(%q) = %q, accepted", in, got)
		}
	}
}

func TestValidateGeoLists(t *testing.T) {
	countries := []string{"KR", "us", " GB ", "XK", "--"}
	allowed := []string{"192.0.2.10", " 198.51.100.0/24", "2001:db8::1", "2001:db8::/48", "::ffff:192.0.2.1", "::ffff:192.0.2.0/120"}
	if err := ValidateGeoLists(countries, allowed); err != nil {
		t.Fatalf("valid lists rejected: %v", err)
	}
	if got := strings.Join(countries, ","); got != "KR,US,GB,XK,--" {
		t.Errorf("countries saved as %q, want them in upper case without spaces", got)
	}
	if allowed[1] != "198.51.100.0/24" {
		t.Errorf("entry saved as %q, want it trimmed", allowed[1])
	}
	if err := ValidateGeoLists(nil, nil); err != nil {
		t.Errorf("fields not sent rejected: %v", err)
	}

	for _, c := range []string{"KOR", "", "K", "A1", "KR|CN", "K\"R", "K\nR", "한국"} {
		if err := ValidateGeoLists([]string{"KR", c}, nil); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "countries[1]") {
			t.Errorf("country %q: got %v, want an error naming countries[1]", c, err)
		}
	}
	for _, ip := range []string{"example.com", "192.0.2.1\"", "192.0.2.1;", "192.0.2.*", "192.0.2.0/33", "192.0.2.1 192.0.2.2", "fe80::1%eth0", ""} {
		if err := ValidateGeoLists(nil, []string{"192.0.2.10", ip}); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "allowed_ips[1]") {
			t.Errorf("allowed ip %q: got %v, want an error naming allowed_ips[1]", ip, err)
		}
	}
}

func TestUsableGeoLists(t *testing.T) {
	countries, ips, dropped := UsableGeoLists([]string{"KR", "KOR", "cn", "XK"}, []string{" 192.0.2.1 ", "example.com", "2001:db8::/32"})
	if strings.Join(countries, ",") != "KR,CN,XK" || strings.Join(ips, ",") != "192.0.2.1,2001:db8::/32" || len(dropped) != 2 {
		t.Errorf("got countries %v, ips %v, dropped %v", countries, ips, dropped)
	}
	// An empty list stays a list (the columns are NOT NULL arrays); an absent
	// one stays absent.
	countries, ips, _ = UsableGeoLists([]string{"KOR"}, nil)
	if countries == nil || len(countries) != 0 || ips != nil {
		t.Errorf("got countries %#v, ips %#v", countries, ips)
	}
}

func TestValidateCloudIPRanges(t *testing.T) {
	ranges := []string{"192.0.2.0/24", " 198.51.100.7 ", "2001:db8::/32"}
	if err := ValidateCloudIPRanges(ranges); err != nil {
		t.Fatalf("valid ranges rejected: %v", err)
	}
	if ranges[1] != "198.51.100.7" {
		t.Errorf("range saved as %q, want it trimmed", ranges[1])
	}
	for _, bad := range []string{"192.0.2.0/24;", "192.0.2.0/24\n198.51.100.0/24", "example.com", "default", "192.0.2.1-192.0.2.9"} {
		if err := ValidateCloudIPRanges([]string{"192.0.2.0/24", bad}); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ip_ranges[1]") {
			t.Errorf("range %q: got %v, want an error naming ip_ranges[1]", bad, err)
		}
	}
}

func TestValidateSecurityHeaderValues_AcceptsPresetsAndCommonValues(t *testing.T) {
	for name, p := range SecurityHeaderPresets {
		if err := ValidateSecurityHeaderValues(p.XFrameOptions, p.ReferrerPolicy, p.ContentSecurityPolicy, p.PermissionsPolicy); err != nil {
			t.Errorf("preset %q rejected: %v", name, err)
		}
	}
	for _, v := range [][4]string{
		{"", "", "", ""},
		{"DENY", "no-referrer", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'", "geolocation=(), camera=()"},
		{"sameorigin", "no-referrer, strict-origin-when-cross-origin", "script-src 'nonce-$request_id' 'strict-dynamic'", `geolocation=(self "https://maps.example.com")`},
	} {
		if err := ValidateSecurityHeaderValues(v[0], v[1], v[2], v[3]); err != nil {
			t.Errorf("values %q rejected: %v", v, err)
		}
	}
}

func TestValidateSecurityHeaderValues_RejectsValuesThatCannotStayInTheirHeader(t *testing.T) {
	long := strings.Repeat("a", maxSecurityHeaderValue+1)
	cases := []struct {
		name, field                string
		xfo, referrer, csp, policy string
	}{
		{"unknown frame option", "x_frame_options", "ALLOWALL", "", "", ""},
		{"line break in frame option", "x_frame_options", "DENY\n", "", "", ""},
		{"unknown referrer policy", "referrer_policy", "", "everything", "", ""},
		{"empty token in referrer list", "referrer_policy", "", "no-referrer,", "", ""},
		{"line break in csp", "content_security_policy", "", "", "default-src 'self'\nimg-src *", ""},
		{"double quote in csp", "content_security_policy", "", "", `default-src "self"`, ""},
		{"backslash in csp", "content_security_policy", "", "", `default-src 'self' \`, ""},
		{"long csp", "content_security_policy", "", "", long, ""},
		{"line break in permissions policy", "permissions_policy", "", "", "", "camera=()\r\nmicrophone=()"},
		{"long permissions policy", "permissions_policy", "", "", "", long},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSecurityHeaderValues(tc.xfo, tc.referrer, tc.csp, tc.policy)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("got %v, want an error naming %s", err, tc.field)
			}
			req := &CreateSecurityHeadersRequest{XFrameOptions: tc.xfo, ReferrerPolicy: tc.referrer, ContentSecurityPolicy: tc.csp, PermissionsPolicy: tc.policy}
			if err := ValidateCreateSecurityHeadersRequest(req); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("per-host request: got %v", err)
			}
			global := &UpdateGlobalSecurityHeadersRequest{XFrameOptions: tc.xfo, ReferrerPolicy: tc.referrer, ContentSecurityPolicy: tc.csp, PermissionsPolicy: tc.policy}
			if err := ValidateUpdateGlobalSecurityHeadersRequest(global); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("global request: got %v", err)
			}
		})
	}
}

func TestResetUnusableSecurityHeaderValues(t *testing.T) {
	xfo, referrer, csp, policy := "DENY", "no-referrer", "default-src 'self'", `camera=(self "https://a.example.com")`
	if reset := ResetUnusableSecurityHeaderValues(&xfo, &referrer, &csp, &policy); len(reset) != 0 {
		t.Errorf("usable values reset: %v", reset)
	}
	xfo, referrer, csp, policy = "ALLOW-FROM x", "x\ny", `default-src "self"`, "a\nb"
	reset := ResetUnusableSecurityHeaderValues(&xfo, &referrer, &csp, &policy)
	if len(reset) != 4 || xfo != "SAMEORIGIN" || referrer != "strict-origin-when-cross-origin" || csp != "" || policy != "" {
		t.Errorf("reset %v to %q %q %q %q", reset, xfo, referrer, csp, policy)
	}
}

func TestValidateURIBlockRule_AcceptsCommonPatterns(t *testing.T) {
	for _, p := range CommonURIPatterns {
		rule := URIBlockRule{Pattern: p.Pattern, MatchType: p.MatchType, Description: p.Description}
		if err := ValidateURIBlockRule(&rule); err != nil {
			t.Errorf("common pattern %q rejected: %v", p.Pattern, err)
		}
	}
	rule := URIBlockRule{Pattern: "  /admin\n", MatchType: URIMatchPrefix}
	if err := ValidateURIBlockRule(&rule); err != nil || rule.Pattern != "/admin" {
		t.Errorf("got %v, pattern %q; want it trimmed and accepted", err, rule.Pattern)
	}

	// Patterns nginx reads as one location argument, saved as they are.
	for _, rule := range []URIBlockRule{
		{Pattern: `"^/[0-9a-f]{32}\.php$"`, MatchType: URIMatchRegex},
		{Pattern: `'^/\d{4}/'`, MatchType: URIMatchRegex},
		{Pattern: `^/a\{2\}`, MatchType: URIMatchRegex},
		{Pattern: `\.php\;`, MatchType: URIMatchRegex},
		{Pattern: `\.php#`, MatchType: URIMatchRegex},
		{Pattern: `"^/a b$"`, MatchType: URIMatchRegex},
		{Pattern: "/a#b", MatchType: URIMatchPrefix},
		{Pattern: "/a}b", MatchType: URIMatchPrefix},
		{Pattern: `/a"b`, MatchType: URIMatchExact},
		{Pattern: "/it's", MatchType: URIMatchPrefix},
		{Pattern: `"/a b"`, MatchType: URIMatchExact},
		{Pattern: "/x${y}", MatchType: URIMatchPrefix},
	} {
		want := rule.Pattern
		if err := ValidateURIBlockRule(&rule); err != nil || rule.Pattern != want {
			t.Errorf("pattern %q: got %v, saved as %q", want, err, rule.Pattern)
		}
	}
}

func TestValidateURIBlockRule_RejectsAPatternThatIsNotOneToken(t *testing.T) {
	cases := []struct {
		name      string
		rule      URIBlockRule
		inMessage string
	}{
		{"unknown match type", URIBlockRule{Pattern: "/a", MatchType: "glob"}, "match_type"},
		{"empty pattern", URIBlockRule{Pattern: " ", MatchType: URIMatchExact}, "pattern"},
		{"empty quoted pattern", URIBlockRule{Pattern: `""`, MatchType: URIMatchRegex}, "pattern"},
		{"space in path", URIBlockRule{Pattern: "/a b", MatchType: URIMatchPrefix}, "pattern"},
		{"separator in path", URIBlockRule{Pattern: "/a;", MatchType: URIMatchExact}, "pattern"},
		{"brace in path", URIBlockRule{Pattern: "/a{", MatchType: URIMatchPrefix}, "pattern"},
		{"comment sign first", URIBlockRule{Pattern: `#\.php$`, MatchType: URIMatchRegex}, "pattern"},
		{"closing brace first", URIBlockRule{Pattern: "}/a", MatchType: URIMatchRegex}, "pattern"},
		{"quote left open", URIBlockRule{Pattern: `"^/a`, MatchType: URIMatchRegex}, "pattern"},
		{"escaped closing quote", URIBlockRule{Pattern: `"^/a\"`, MatchType: URIMatchRegex}, "pattern"},
		{"text after the closing quote", URIBlockRule{Pattern: `"^/a"b`, MatchType: URIMatchRegex}, "pattern"},
		{"block after the pattern", URIBlockRule{Pattern: "/x { return 200; } location /y", MatchType: URIMatchPrefix}, "pattern"},
		{"line break in path", URIBlockRule{Pattern: "/a\n/b", MatchType: URIMatchExact}, "pattern"},
		{"line break in quotes", URIBlockRule{Pattern: "\"^/a\nb\"", MatchType: URIMatchRegex}, "pattern"},
		{"escaped line break", URIBlockRule{Pattern: "/a\\\nb", MatchType: URIMatchPrefix}, "pattern"},
		{"path without slash", URIBlockRule{Pattern: "wp-admin", MatchType: URIMatchPrefix}, "pattern"},
		{"quoted path without slash", URIBlockRule{Pattern: `"wp admin"`, MatchType: URIMatchPrefix}, "pattern"},
		{"backslash in path", URIBlockRule{Pattern: `/a\b`, MatchType: URIMatchExact}, "pattern"},
		{"long path", URIBlockRule{Pattern: "/" + strings.Repeat("a", uriBlockMaxPathPattern), MatchType: URIMatchPrefix}, "pattern"},
		{"space in regex", URIBlockRule{Pattern: `\.php$ x`, MatchType: URIMatchRegex}, "pattern"},
		{"separator in regex", URIBlockRule{Pattern: `\.php$;`, MatchType: URIMatchRegex}, "pattern"},
		{"quantifier braces outside quotes", URIBlockRule{Pattern: `^/\d{2}$`, MatchType: URIMatchRegex}, "double quotes"},
		{"line break in description", URIBlockRule{Pattern: "/a", MatchType: URIMatchExact, Description: "a\nb"}, "description"},
		{"long description", URIBlockRule{Pattern: "/a", MatchType: URIMatchExact, Description: strings.Repeat("d", uriBlockMaxDescription+1)}, "description"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := tc.rule
			err := ValidateURIBlockRule(&rule)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tc.inMessage) {
				t.Errorf("got %v, want an error about %s", err, tc.inMessage)
			}
		})
	}
}

// The boundary RenderableURIBlockPattern draws is the one nginx -t draws for
// "location <modifier> <pattern> {": each kept pattern below was checked with
// nginx -t, written as it is, and each pattern left out is not one argument on
// that line (or is longer than nginx reads).
func TestRenderableURIBlockPattern(t *testing.T) {
	for in, want := range map[string]string{
		"/admin":                              "/admin",
		" /admin\t":                           "/admin",
		"\t/admin\r\n":                        "/admin",
		`\.(sql|bak)$`:                        `\.(sql|bak)$`,
		"wp-admin":                            "wp-admin", // useless, but one argument
		`(?i)^/x(?=y)`:                        `(?i)^/x(?=y)`,
		"/café/été":                           "/café/été",
		"/a\u2028b":                           "/a\u2028b", // not a line break to nginx
		`"^/a{2,3}$"`:                         `"^/a{2,3}$"`,
		`'^/[0-9]{4}/'`:                       `'^/[0-9]{4}/'`,
		`"^/a b$"`:                            `"^/a b$"`,
		"\"a\tb\"":                            "\"a\tb\"",
		`"a\"b"`:                              `"a\"b"`,
		`"#x"`:                                `"#x"`,
		`""`:                                  `""`, // one argument, empty (the API refuses it)
		`^/a\{2\}`:                            `^/a\{2\}`,
		`\.php\;`:                             `\.php\;`,
		`/a\ b`:                               `/a\ b`,
		`\.php\ `:                             `\.php\ `, // the escaped space is part of it
		`\.php\`:                              `\.php\`,  // takes in the separator after it
		"/x${y}":                              "/x${y}",
		`/a"b`:                                `/a"b`,
		"/it's":                               "/it's",
		`\.php#`:                              `\.php#`,
		"/a}b":                                "/a}b",
		"$x":                                  "$x",
		"=/x":                                 "=/x",
		"/" + strings.Repeat("a", 4093):       "/" + strings.Repeat("a", 4093),
		`"` + strings.Repeat("a", 4093) + `"`: `"` + strings.Repeat("a", 4093) + `"`,
	} {
		if got, ok := RenderableURIBlockPattern(in); !ok || got != want {
			t.Errorf("RenderableURIBlockPattern(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", "  ", "/a b", "/a\tb", "/a\rb", "/a;", ";x", "/a{", "{x", `^/a{2,3}$`, "}x", "#x", "/a #b",
		`"abc`, `'abc`, `"abc\"`, `"abc"def`, `"abc" "def"`, `"abc";`,
		"/a\nb", "\"a\nb\"", "\"a\rb\"", "/a\\\nb", "/x${;",
		"/x { return 200; } location /y", "/x {} location = /y",
		"/" + strings.Repeat("a", 4094), `"` + strings.Repeat("a", 4094) + `"`,
	} {
		if _, ok := RenderableURIBlockPattern(in); ok {
			t.Errorf("RenderableURIBlockPattern(%q) accepted", in)
		}
	}
}

func TestURIBlockPatternValue(t *testing.T) {
	for in, want := range map[string]string{
		"/admin":      "/admin",
		" /admin ":    "/admin",
		`"^/a{2,3}$"`: "^/a{2,3}$",
		`'^/a b$'`:    "^/a b$",
		`"a\"b"`:      `a"b`,
		`a\\.b`:       `a\.b`,
		`\.php$`:      `\.php$`,
		`a\tb`:        "a\tb",
		`"\d+\n"`:     "\\d+\n",
		`'it\'s'`:     "it's",
		`/a"b`:        `/a"b`,
		`""`:          "",
	} {
		if got := URIBlockPatternValue(in); got != want {
			t.Errorf("URIBlockPatternValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateExclusionText(t *testing.T) {
	if err := ValidateExclusionText("SQLI", "SQL Injection Attack Detected via libinjection", "false positive on /search (Café #2)"); err != nil {
		t.Errorf("one-line text rejected: %v", err)
	}
	if err := ValidateExclusionText("", "", ""); err != nil {
		t.Errorf("empty text rejected: %v", err)
	}
	for _, tc := range []struct{ category, description, reason, field string }{
		{"SQLI\nx", "", "", "rule_category"},
		{"", "first line\nsecond line", "", "rule_description"},
		{"", "", "first line\r\nsecond line", "reason"},
		{"", "", "a\u2028b", "reason"},
		{"", "", "a\x00b", "reason"},
	} {
		err := ValidateExclusionText(tc.category, tc.description, tc.reason)
		if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%q %q %q: got %v, want an error naming %s", tc.category, tc.description, tc.reason, err, tc.field)
		}
	}
}
