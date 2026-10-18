package nginx

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
