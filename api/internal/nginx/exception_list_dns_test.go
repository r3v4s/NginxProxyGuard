package nginx

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

const (
	excTestHostID = "00000000-0000-0000-0000-0000000000d4"
	excTestSID    = "00000000_0000_0000_0000_0000000000d4"
)

// geoIncludeLine is the include line of the .geo file of (scope, name).
func geoIncludeLine(scope, name string) string {
	return "include " + DNSIncludeRenderDir + "/" + DNSIncludeKey(scope, name) + ".geo;"
}

// adminRule is the URI block rule of the exception tests.
var adminRule = model.URIBlockRule{ID: "00000000-0000-0000-0000-0000000000d5", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true}

// A host whose Advanced Config asks for a login (auth_basic here, in a
// location of its own) gets no URI block exception domains: the exception
// path cannot run that login, so a domain there would open the blocked paths
// to whoever holds the name's DNS. Its static exceptions work as before, and
// a host without that login gets the include.
func TestURIExceptionDomainsAreSkippedOnAdvancedConfigAuthHosts(t *testing.T) {
	scope := "uri:" + excTestHostID
	host := goldenBaseHost(excTestHostID, "uri-auth.example.com")
	host.AdvancedConfig = "location /private {\n    auth_basic \"Private\";\n    auth_basic_user_file /etc/nginx/htpasswd;\n}"
	block := func(ips ...string) *model.URIBlock {
		return &model.URIBlock{ProxyHostID: excTestHostID, Enabled: true, Rules: []model.URIBlockRule{adminRule},
			ExceptionIPs: ips, ExceptionDNS: []model.DNSRef{{Scope: scope, Name: "partner.example.com"}}}
	}
	exception := "if ($npg_uri_exc_" + excTestSID + " = 1) {"

	data := ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), URIBlock: block("192.0.2.20")}
	out := generateForTest(t, data)
	if strings.Contains(out, DNSIncludeRenderDir) {
		t.Errorf("a host with auth_basic in its Advanced Config includes a domain file:\n%s", geoBlock(t, out, "$npg_uri_exc_"+excTestSID))
	}
	if lines := hostDNSIncludeLines(data); len(lines) != 0 {
		t.Errorf("hostDNSIncludeLines = %+v, want none", lines)
	}
	if geo := geoBlock(t, out, "$npg_uri_exc_"+excTestSID); !strings.Contains(geo, "192.0.2.20 1;") {
		t.Errorf("the static exception is missing:\n%s", geo)
	}
	if loc := locationBlock(t, out, "location ^~ /admin {"); !strings.Contains(loc, exception) {
		t.Errorf("the static exception check is missing:\n%s", loc)
	}

	// Domains alone: no exception, every client gets the block's 403.
	data.URIBlock = block()
	out = generateForTest(t, data)
	if strings.Contains(out, "geo $npg_uri_exc_") || strings.Contains(out, "$uri_block_exception") {
		t.Errorf("a host with exception domains alone and auth_basic renders an exception")
	}
	if loc := locationBlock(t, out, "location ^~ /admin {"); !strings.Contains(loc, "return 403;") {
		t.Errorf("the block does not answer 403:\n%s", loc)
	}

	data.Host = goldenBaseHost(excTestHostID, "uri-auth.example.com")
	out = generateForTest(t, data)
	if geo := geoBlock(t, out, "$npg_uri_exc_"+excTestSID); !strings.Contains(geo, "# dns: partner.example.com") ||
		!strings.Contains(geo, geoIncludeLine(scope, "partner.example.com")) {
		t.Errorf("a host without that login does not include the domain:\n%s", geo)
	}
	if loc := locationBlock(t, out, "location ^~ /admin {"); !strings.Contains(loc, exception) {
		t.Errorf("the exception check is missing for a domain alone:\n%s", loc)
	}
}

// Priority allow domains alone define the geo variable and every bypass
// that reads it: the geo direct block, the geo challenge, the cloud provider
// block and the bot filter.
func TestPriorityAllowDomainsOnlyRenderTheGeoAndEveryBypass(t *testing.T) {
	refs := []model.DNSRef{{Scope: "prio:" + excTestHostID, Name: "partner.example.com"}, {Scope: "prio:global", Name: "office.example.com"}}
	geo := func(enabled, challenge bool) *model.GeoRestriction {
		return &model.GeoRestriction{ProxyHostID: excTestHostID, Mode: "whitelist", Countries: []string{"KR"},
			Enabled: enabled, ChallengeMode: challenge, AllowedDNS: refs}
	}
	prio := "$npg_prio_" + excTestSID
	for _, tc := range []struct {
		name string
		data ProxyHostConfigData
		want []string
	}{
		{"direct block, cloud provider block, bot filter", ProxyHostConfigData{GeoRestriction: geo(true, false),
			BlockedCloudIPRanges: []string{"192.0.2.128/25"}, BotFilter: &model.BotFilter{Enabled: true, CustomBlockedAgents: "BadBot"}},
			[]string{
				"set $geo_allowed_ip " + prio + ";",
				"if (" + prio + " = 1) {\n        set $is_priority_allow_cloud 1;",
				"if (" + prio + " = 1) {\n        set $priority_allow 1;",
			}},
		{"challenge", ProxyHostConfigData{GeoRestriction: geo(true, true)},
			[]string{"if (" + prio + " = 1) {\n        set $geo_blocked 0;"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.data.Host = goldenBaseHost(excTestHostID, "prio-domains.example.com")
			tc.data.GlobalSettings = baseGlobalSettings()
			out := generateForTest(t, tc.data)
			block := geoBlock(t, out, prio)
			for _, ref := range refs {
				if !strings.Contains(block, "# dns: "+ref.Name+"\n    "+geoIncludeLine(ref.Scope, ref.Name)) {
					t.Errorf("the geo block does not include %s (%s):\n%s", ref.Name, ref.Scope, block)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q", want)
				}
			}
		})
	}
}

// Rate limit exception domains are includes in the exception geo block. The
// zone's key does not change with them: a running nginx refuses a reload
// that changes a zone's key.
func TestRateLimitDomainsLeaveTheZoneKeyAlone(t *testing.T) {
	refs := []model.DNSRef{{Scope: "rl:" + excTestHostID, Name: "partner.example.com"}, {Scope: "rl:" + excTestHostID, Name: "shop.example.com"}}
	render := func(refs []model.DNSRef) string {
		return renderForTest(t, ProxyHostConfigData{Host: goldenBaseHost(excTestHostID, "rl-domains.example.com"), GlobalSettings: baseGlobalSettings(),
			RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 10, BurstSize: 5, ZoneSize: "10m", LimitBy: "ip", LimitResponse: 429,
				WhitelistIPs: "192.0.2.10", WhitelistDNS: refs}})
	}
	zone := func(out string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "limit_req_zone ") {
				return line
			}
		}
		t.Fatalf("no limit_req_zone line")
		return ""
	}
	none, two := render(nil), render(refs)
	if zone(none) != zone(two) {
		t.Errorf("the zone line changed with the domains:\n%s\n%s", zone(none), zone(two))
	}
	if block := geoBlock(t, none, "$rate_wl_"+excTestSID); strings.Contains(block, "include ") {
		t.Errorf("a list without domains has an include:\n%s", block)
	}
	block := geoBlock(t, two, "$rate_wl_"+excTestSID)
	for _, want := range []string{"192.0.2.10 1;", geoIncludeLine(refs[0].Scope, refs[0].Name), geoIncludeLine(refs[1].Scope, refs[1].Name)} {
		if !strings.Contains(block, want) {
			t.Errorf("the exception geo block is missing %q:\n%s", want, block)
		}
	}
}

// Priority allow domains bypass the geo restriction, the cloud provider
// block and the bot filter, never the WAF: the host's WAF file gets the
// static addresses only (id:900900 turns its rule engine off).
func TestPriorityAllowDomainsNeverReachTheWAFAllowList(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	host := goldenBaseHost(excTestHostID, "prio-waf.example.com")
	host.WAFEnabled, host.WAFMode = true, "blocking"
	scope := "prio:" + excTestHostID
	data := ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(),
		GeoRestriction: &model.GeoRestriction{ProxyHostID: excTestHostID, AllowedDNS: []model.DNSRef{{Scope: scope, Name: "partner.example.com"}}}}
	if err := m.GenerateConfigAndReload(context.Background(), data, nil); err != nil {
		t.Fatalf("GenerateConfigAndReload: %v", err)
	}
	waf, err := os.ReadFile(filepath.Join(m.modsecPath, "host_"+excTestHostID+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(waf), "id:900900") || strings.Contains(string(waf), "@ipMatch") {
		t.Errorf("the WAF file lets priority allow domains past the WAF:\n%s", waf)
	}
	conf, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(host)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(geoBlock(t, string(conf), "$npg_prio_"+excTestSID), geoIncludeLine(scope, "partner.example.com")) {
		t.Errorf("the host config does not include the domain")
	}
}

// Before a host config is written, every exception list domain file it
// includes exists: a missing one is created empty, one the DNS entry
// service wrote keeps its content.
func TestGenerateConfigFullCreatesMissingExceptionIncludes(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	host := goldenBaseHost(excTestHostID, "exceptions.example.com")
	uri, prio, rl := "uri:"+excTestHostID, "prio:global", "rl:"+excTestHostID
	data := ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(),
		URIBlock: &model.URIBlock{ProxyHostID: excTestHostID, Enabled: true, Rules: []model.URIBlockRule{adminRule},
			ExceptionDNS: []model.DNSRef{{Scope: uri, Name: "partner.example.com"}}},
		GeoRestriction: &model.GeoRestriction{ProxyHostID: excTestHostID, AllowedDNS: []model.DNSRef{{Scope: prio, Name: "office.example.com"}}},
		RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 10, BurstSize: 5, ZoneSize: "10m", LimitBy: "ip", LimitResponse: 429,
			WhitelistDNS: []model.DNSRef{{Scope: rl, Name: "partner.example.com"}}},
	}
	keyURI, keyPrio, keyRL := DNSIncludeKey(uri, "partner.example.com"), DNSIncludeKey(prio, "office.example.com"), DNSIncludeKey(rl, "partner.example.com")
	written := FormatDNSIncludeFile("office.example.com", prio, 3, ".geo", []string{"192.0.2.7"})
	if err := os.MkdirAll(m.dnsIncludeDiskDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.dnsIncludeDiskPath(keyPrio, ".geo"), written, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.GenerateConfigFull(context.Background(), data); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	refs, err := m.ScanDNSIncludeReferences()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 || !refs[keyURI+".geo"] || !refs[keyPrio+".geo"] || !refs[keyRL+".geo"] {
		t.Fatalf("the config includes %v, want the files of the three lists", refs)
	}
	if got, err := os.ReadFile(m.dnsIncludeDiskPath(keyPrio, ".geo")); err != nil || !bytes.Equal(got, written) {
		t.Errorf("the render changed the file the DNS entry service wrote: %q (%v)", got, err)
	}
	for _, key := range []string{keyURI, keyRL} {
		if info, err := os.Stat(m.dnsIncludeDiskPath(key, ".geo")); err != nil || info.Size() != 0 {
			t.Errorf("the missing file %s.geo was not created empty (%v)", key, err)
		}
	}
	if files, err := m.ReadDNSIncludeDir(); err != nil || len(files) != 3 {
		t.Errorf("%d file(s) in the directory (%v), want 3", len(files), err)
	}
}

// trustedIncludeLine is the include line of the global trusted domain
// name's file with the extension ext.
func trustedIncludeLine(name, ext string) string {
	return "include " + DNSIncludeRenderDir + "/" + DNSIncludeKey(model.DNSScopeKindTrusted, name) + ext + ";"
}

// accessBlock returns the access list block of out, from the line that
// marks its denials up to and including its final deny all.
func accessBlock(t *testing.T, out string) string {
	t.Helper()
	start := strings.Index(out, `set $block_reason_var "access_denied";`)
	if start < 0 {
		t.Fatalf("no access list block in the config")
	}
	end := strings.Index(out[start:], "\n    deny all;\n")
	if end < 0 {
		t.Fatalf("the access list block has no final deny all")
	}
	return out[start : start+end+len("\n    deny all;")]
}

// inOrder reports the first of wants that is missing from s or out of order.
func inOrder(s string, wants ...string) (string, bool) {
	at := 0
	for _, want := range wants {
		i := strings.Index(s[at:], want)
		if i < 0 {
			return want, false
		}
		at += i + len(want)
	}
	return "", true
}

// A global trusted domain enters an access list block after the list's
// address rules, its denies included, and before the list's own domains:
// the static trusted addresses, the list's rules, the trusted domains, the
// list's domains, deny all. An address the list denies stays denied,
// whoever's DNS points at it.
func TestTrustedDomainsFollowTheListsAddressRules(t *testing.T) {
	const listID = "00000000-0000-0000-0000-0000000000d6"
	data := ProxyHostConfigData{Host: goldenBaseHost(excTestHostID, "trusted-acl.example.com"), GlobalSettings: baseGlobalSettings(),
		GlobalTrustedIPs: []string{"192.0.2.10"}, TrustedHostnames: []string{"office.example.com"},
		AccessList: &model.AccessList{ID: listID, Name: "partners", Items: []model.AccessListItem{
			{ID: "r1", Directive: "allow", Address: "192.0.2.64/26"},
			{ID: "r2", Directive: "deny", Address: "192.0.2.70", SortOrder: 1},
			{ID: "r3", Directive: "deny", Address: "all", Hostname: "partner.example.com", SortOrder: 2},
		}}}
	if !data.DNSTrustInAccessList() {
		t.Fatalf("DNSTrustInAccessList = false for a list without satisfy any")
	}
	block := accessBlock(t, generateForTest(t, data))
	if missing, ok := inOrder(block,
		"allow 192.0.2.10;",
		"allow 192.0.2.64/26;",
		"deny 192.0.2.70;",
		"# dns(trusted): office.example.com\n    "+trustedIncludeLine("office.example.com", ".allow"),
		"# dns: partner.example.com\n    include "+DNSIncludeRenderDir+"/"+DNSIncludeKey(model.AccessListDNSScope(listID), "partner.example.com")+".allow;",
		"deny all;",
	); !ok {
		t.Errorf("the access list block is missing %q or has it out of order:\n%s", missing, block)
	}
	if n := strings.Count(block, "include "); n != 2 {
		t.Errorf("%d include line(s) in the block, want the trusted domain's and the list's", n)
	}
	var files []string
	for _, line := range hostDNSIncludeLines(data) {
		files = append(files, line.Path)
	}
	if want := DNSIncludeRenderDir + "/" + DNSIncludeKey(model.DNSScopeKindTrusted, "office.example.com") + ".allow"; !slices.Contains(files, want) {
		t.Errorf("hostDNSIncludeLines = %v, want the trusted domain's .allow among them", files)
	}
}

// On a host with a login (ForwardAuth here) whose access list renders
// "satisfy any", an address the list allows skips the login. A trusted
// domain is not put in such a list, so whoever holds its DNS still signs
// in; the geo restriction and the bot filter still let it through. Without
// satisfy any the same list includes it.
func TestTrustedDomainsSkipASatisfyAnyListOnALoginHost(t *testing.T) {
	host := goldenBaseHost(excTestHostID, "trusted-login.example.com")
	apID := "00000000-0000-0000-0000-0000000000d7"
	host.AuthProviderID = &apID
	data := ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), TrustedHostnames: []string{"office.example.com"},
		AuthProvider: &model.AuthProvider{ID: apID, Name: "authelia", Type: "authelia", ProviderURL: "http://127.0.0.1:9091", TimeoutMs: 5000, Enabled: true},
		AccessList: &model.AccessList{ID: "00000000-0000-0000-0000-0000000000d8", Name: "office", SatisfyAny: true, Items: []model.AccessListItem{
			{ID: "s1", Directive: "allow", Address: "192.0.2.64/26"}}},
		GeoRestriction: &model.GeoRestriction{ProxyHostID: excTestHostID, Mode: "whitelist", Countries: []string{"KR"}, Enabled: true},
		BotFilter:      &model.BotFilter{Enabled: true, CustomBlockedAgents: "BadBot"},
	}
	trusted := "$npg_trusted_" + excTestSID
	if data.DNSTrustInAccessList() {
		t.Errorf("DNSTrustInAccessList = true for a satisfy any list on a ForwardAuth host")
	}
	out := generateForTest(t, data)
	block := accessBlock(t, out)
	if !strings.Contains(block, "satisfy any;") {
		t.Fatalf("the list does not render satisfy any:\n%s", block)
	}
	if strings.Contains(block, "dns(trusted)") || strings.Contains(block, trustedIncludeLine("office.example.com", ".allow")) {
		t.Errorf("a satisfy any list on a login host includes the trusted domain:\n%s", block)
	}
	if geo := geoBlock(t, out, trusted); !strings.Contains(geo, trustedIncludeLine("office.example.com", ".geo")) {
		t.Errorf("the trusted geo does not include the domain:\n%s", geo)
	}
	for _, want := range []string{
		"if (" + trusted + " = 1) {\n        set $geo_direct_block \"\";",
		"if (" + trusted + " = 1) {\n        set $priority_allow 1;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing the trusted bypass %q", want)
		}
	}
	for _, line := range hostDNSIncludeLines(data) {
		if strings.HasSuffix(line.Path, ".allow") {
			t.Errorf("hostDNSIncludeLines ensures %s, which the config does not include", line.Path)
		}
	}

	data.AccessList.SatisfyAny = false
	if !data.DNSTrustInAccessList() {
		t.Errorf("DNSTrustInAccessList = false for the same list without satisfy any")
	}
	if block := accessBlock(t, generateForTest(t, data)); !strings.Contains(block, "# dns(trusted): office.example.com\n    "+trustedIncludeLine("office.example.com", ".allow")) {
		t.Errorf("the list without satisfy any does not include the trusted domain:\n%s", block)
	}
}

// Bans and filter subscription IPs win over a trusted domain: the ban geo's
// override lines and the filter subscription bypass read the static
// addresses alone ($trusted_ip_<id>), and include no domain file.
func TestTrustedDomainsNeverOverrideBansOrFilterSubscription(t *testing.T) {
	hostID := excTestHostID
	data := ProxyHostConfigData{Host: goldenBaseHost(excTestHostID, "trusted-ban.example.com"), GlobalSettings: baseGlobalSettings(),
		GlobalTrustedIPs: []string{"192.0.2.10"}, TrustedHostnames: []string{"office.example.com"},
		BannedIPs:             []model.BannedIP{{ID: "00000000-0000-0000-0000-0000000000d9", ProxyHostID: &hostID, IPAddress: "192.0.2.99", Reason: "test ban"}},
		UseFilterSubscription: true,
	}
	filterSection := func(t *testing.T, out string) string {
		t.Helper()
		start := strings.Index(out, "# Filter Subscription IP Blocking")
		end := strings.Index(out, "if ($filter_ip_check = 2)")
		if start < 0 || end < start {
			t.Fatalf("no filter subscription section")
		}
		return out[start:end]
	}

	out := generateForTest(t, data)
	if geo := geoBlock(t, out, "$npg_trusted_"+excTestSID); !strings.Contains(geo, trustedIncludeLine("office.example.com", ".geo")) {
		t.Errorf("the trusted domain does not reach the perimeter geo:\n%s", geo)
	}
	ban := geoBlock(t, out, "$banned_ip_"+excTestSID)
	if !strings.Contains(ban, "192.0.2.10 0;") {
		t.Errorf("the ban geo lost the static trusted override:\n%s", ban)
	}
	if strings.Contains(ban, "include ") || strings.Contains(ban, "npg_trusted") {
		t.Errorf("the ban geo lets a trusted domain override a ban:\n%s", ban)
	}
	filter := filterSection(t, out)
	if !strings.Contains(filter, "if ($trusted_ip_"+excTestSID+" = 1) {") {
		t.Errorf("the static trusted bypass of the filter subscription is missing:\n%s", filter)
	}
	if strings.Contains(filter, "npg_trusted") || strings.Contains(filter, "include ") {
		t.Errorf("a trusted domain bypasses the filter subscription:\n%s", filter)
	}
	if static := geoBlock(t, out, "$trusted_ip_"+excTestSID); strings.Contains(static, "include ") {
		t.Errorf("the static trusted geo includes a domain file:\n%s", static)
	}

	// Domains alone: no override in the ban geo, no filter bypass at all.
	data.GlobalTrustedIPs = nil
	out = generateForTest(t, data)
	if ban := geoBlock(t, out, "$banned_ip_"+excTestSID); strings.Count(ban, " 0;") != 1 {
		t.Errorf("the ban geo overrides a ban for a trusted domain:\n%s", ban)
	}
	if filter := filterSection(t, out); strings.Contains(filter, "trusted") {
		t.Errorf("trusted domains alone bypass the filter subscription:\n%s", filter)
	}
}

// Trusted domains alone, without a trusted address, define
// $npg_trusted_<id> and every perimeter bypass that reads it: the four
// forms of the geo direct block, the geo challenge, the cloud provider
// block, the bot filter and the rate limit chain. No check reads the static
// list's $trusted_ip_<id> then.
func TestTrustedDomainsAloneRenderEveryPerimeterBypass(t *testing.T) {
	trusted := "$npg_trusted_" + excTestSID
	geo := func(mode string, challenge, searchBots bool, prio ...string) *model.GeoRestriction {
		return &model.GeoRestriction{ProxyHostID: excTestHostID, Mode: mode, Countries: []string{"KR"}, Enabled: true,
			ChallengeMode: challenge, AllowSearchBots: searchBots, AllowedIPs: prio}
	}
	for _, tc := range []struct {
		name string
		data ProxyHostConfigData
		want string
	}{
		{"geo direct block with priority allow", ProxyHostConfigData{GeoRestriction: geo("whitelist", false, false, "192.0.2.70")},
			"if (" + trusted + " = 1) {\n        set $geo_allowed_ip 1;"},
		{"geo direct block letting search bots through", ProxyHostConfigData{GeoRestriction: geo("whitelist", false, true)},
			"if (" + trusted + " = 1) {\n        set $geo_block_check \"\";"},
		{"geo direct block, whitelist", ProxyHostConfigData{GeoRestriction: geo("whitelist", false, false)},
			"if (" + trusted + " = 1) {\n        set $geo_direct_block \"\";"},
		{"geo direct block, blacklist", ProxyHostConfigData{GeoRestriction: geo("blacklist", false, false)},
			"if (" + trusted + " = 1) {\n        set $geo_direct_block \"\";"},
		{"geo challenge", ProxyHostConfigData{GeoRestriction: geo("whitelist", true, false)},
			"if (" + trusted + " = 1) {\n        set $geo_blocked 0;"},
		{"cloud provider block", ProxyHostConfigData{BlockedCloudIPRanges: []string{"192.0.2.128/25"}},
			"if (" + trusted + " = 1) {\n        set $is_priority_allow_cloud 1;"},
		{"bot filter", ProxyHostConfigData{BotFilter: &model.BotFilter{Enabled: true, CustomBlockedAgents: "BadBot"}},
			"if (" + trusted + " = 1) {\n        set $priority_allow 1;"},
		{"rate limit", ProxyHostConfigData{RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 10, BurstSize: 5, ZoneSize: "10m", LimitBy: "ip", LimitResponse: 429}},
			"map " + trusted + " $rate_final_key_" + excTestSID + " {"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.data.Host = goldenBaseHost(excTestHostID, "trusted-domains.example.com")
			tc.data.GlobalSettings = baseGlobalSettings()
			tc.data.TrustedHostnames = []string{"office.example.com", "partner.example.com"}
			if !tc.data.TrustedConfigured() {
				t.Fatalf("TrustedConfigured = false with trusted domains")
			}
			out := generateForTest(t, tc.data)
			block := geoBlock(t, out, trusted)
			for _, name := range tc.data.TrustedHostnames {
				if !strings.Contains(block, "# dns: "+name+"\n    "+trustedIncludeLine(name, ".geo")) {
					t.Errorf("the trusted geo does not include %s:\n%s", name, block)
				}
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q", tc.want)
			}
			if strings.Contains(out, "($trusted_ip_") || strings.Contains(out, "map $trusted_ip_") {
				t.Errorf("a check reads the static trusted list, which is empty")
			}
		})
	}
}
