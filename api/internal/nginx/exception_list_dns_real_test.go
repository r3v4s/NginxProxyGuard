package nginx

// The exception lists' domains (#320) against a real nginx, skipped unless
// NPG_REAL_NGINX_CONTAINER and NPG_REAL_NGINX_CONFD are set
// (reload_hooks_real_test.go). GenerateConfigFull renders the host configs.
// The container's nginx.conf must also load the headers-more module (a WAF
// host sets its Host header with it), size the variables hash and load the
// CRS at the http level, as NPG's nginx.conf does, and its conf.d must hold
// a copy of nginx/conf.d/forwarded-port.conf ($npg_forwarded_port):
//
//	load_module /usr/lib/nginx/modules/ngx_http_headers_more_filter_module.so;
//	...
//	variables_hash_bucket_size 256;
//	variables_hash_max_size 4096;
//	modsecurity on;
//	modsecurity_rules_file /etc/nginx/modsec/crs-global.conf;
//
// The host's WAF file is written under conf.d (npg320r3_modsec/) and linked,
// inside the container, to the path its host config reads. Clients are the
// container's loopback addresses: the domain's files hold 127.0.0.2, and
// 127.0.0.3 is everyone else.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// realRequestOnce asks the container's nginx for path on host from the
// loopback address ip, with the extra curl arguments, and returns the status.
func realRequestOnce(t *testing.T, container, ip, host, path string, extra ...string) string {
	t.Helper()
	args := append([]string{"exec", container, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"--interface", ip, "-H", "Host: " + host}, extra...)
	out, err := exec.Command("docker", append(args, "http://127.0.0.1:8080"+path)...).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s%s from %s: %v: %s", host, path, ip, err, out)
	}
	return strings.TrimSpace(string(out))
}

// realRequestStatus asks as realRequestOnce until nginx answers want (old
// workers can take a request or two after a reload), and returns the last
// answer.
func realRequestStatus(t *testing.T, container, ip, host, path, want string, extra ...string) string {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		got := realRequestOnce(t, container, ip, host, path, extra...)
		if got == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRealExceptionListDomainEntries(t *testing.T) {
	m, confd := realNginxManager(t)
	container := os.Getenv("NPG_REAL_NGINX_CONTAINER")
	m.httpPort = "8080"
	m.SetEnableIPv6(false)
	ctx := context.Background()

	const partner = "partner.example.com"
	newHost := func(id, domain string) *model.ProxyHost {
		h := baseHost(id, "127.0.0.1", true)
		h.DomainNames, h.ForwardPort = []string{domain}, 8081
		return h
	}
	hostURI := newHost("00000000-0000-0000-0000-0000000000f4", "uri.example.com")
	hostPrio := newHost("00000000-0000-0000-0000-0000000000f5", "prio.example.com")
	hostPrio.WAFEnabled, hostPrio.WAFMode = true, "blocking"
	hostRL := newHost("00000000-0000-0000-0000-0000000000f6", "rl.example.com")
	scopeURI, scopePrio, scopeRL := "uri:"+hostURI.ID, "prio:"+hostPrio.ID, "rl:global"

	const backendConf = "npg320r3_backend.conf"
	modsecDir := filepath.Join(confd, "npg320r3_modsec")
	wafLink := "/etc/nginx/modsec/host_" + hostPrio.ID + ".conf"
	t.Cleanup(func() {
		for _, f := range []string{backendConf, GetConfigFilename(hostURI), GetConfigFilename(hostPrio), GetConfigFilename(hostRL), "npg_request_path.conf"} {
			_ = os.Remove(filepath.Join(confd, f))
		}
		_ = os.RemoveAll(filepath.Join(confd, "includes"))
		_ = os.RemoveAll(modsecDir)
		_ = exec.Command("docker", "exec", container, "rm", "-f", wafLink).Run()
	})
	if err := os.WriteFile(filepath.Join(confd, backendConf), []byte("server {\n    listen 127.0.0.1:8081;\n    modsecurity off;\n    location / {\n        return 200 \"backend\\n\";\n    }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modsecDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m.modsecPath = modsecDir
	if out, err := exec.Command("docker", "exec", container, "ln", "-sf",
		"/etc/nginx/conf.d/npg320r3_modsec/host_"+hostPrio.ID+".conf", wafLink).CombinedOutput(); err != nil {
		t.Fatalf("link the WAF file: %v: %s", err, out)
	}

	// URI: /admin is blocked except for the domain. Priority allow: the
	// domain skips the bot filter, not the WAF. Rate limit, 1 r/s with a
	// burst of 1 (nginx refuses burst=0), so a third request in a row is
	// limited: the domain is exempt.
	renders := []ProxyHostConfigData{
		{Host: hostURI, URIBlock: &model.URIBlock{ProxyHostID: hostURI.ID, Enabled: true, Rules: []model.URIBlockRule{adminRule},
			ExceptionDNS: []model.DNSRef{{Scope: scopeURI, Name: partner}}}},
		{Host: hostPrio, GeoRestriction: &model.GeoRestriction{ProxyHostID: hostPrio.ID, AllowedDNS: []model.DNSRef{{Scope: scopePrio, Name: partner}}},
			BotFilter: &model.BotFilter{Enabled: true, CustomBlockedAgents: "BadBot"}},
		{Host: hostRL, RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 1, BurstSize: 1, ZoneSize: "1m", LimitBy: "ip", LimitResponse: 429,
			WhitelistDNS: []model.DNSRef{{Scope: scopeRL, Name: partner}}}},
	}
	for _, d := range renders {
		if err := m.GenerateConfigFull(ctx, d); err != nil {
			t.Fatalf("GenerateConfigFull: %v", err)
		}
	}
	if err := m.GenerateHostWAFConfig(ctx, hostPrio, nil, renders[1].GeoRestriction.AllowedIPs); err != nil {
		t.Fatalf("GenerateHostWAFConfig: %v", err)
	}

	apply := func(step string) {
		t.Helper()
		if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
			t.Fatalf("%s: apply = %+v, want accepted (nginx started new workers)", step, res)
		}
	}
	expect := func(step, ip, host, path, want string, extra ...string) {
		t.Helper()
		if got := realRequestStatus(t, container, ip, host, path, want, extra...); got != want {
			t.Errorf("%s: %s%s from %s = %s, want %s", step, host, path, ip, got, want)
		}
	}
	publish := func(gen int64, addrs ...string) {
		t.Helper()
		for _, scope := range []string{scopeURI, scopePrio, scopeRL} {
			if _, err := m.WriteDNSIncludeFiles(scope, partner, gen, addrs); err != nil {
				t.Fatal(err)
			}
		}
	}
	// limited checks that ip gets the rate limit's 429, and unlimited that
	// five requests in a row from ip, after one that passed, all pass: at
	// 1 r/s with a burst of 1, the third would be limited.
	limited := func(step, ip string) { t.Helper(); expect(step, ip, "rl.example.com", "/", "429") }
	unlimited := func(step, ip string) {
		t.Helper()
		expect(step, ip, "rl.example.com", "/", "200")
		for i := 0; i < 5; i++ {
			if got := realRequestOnce(t, container, ip, "rl.example.com", "/"); got != "200" {
				t.Errorf("%s: request %d in a row from %s = %s, want 200", step, i+2, ip, got)
				return
			}
		}
	}
	const sqli = "/?id=1%27%20OR%20%271%27%3D%271"

	// 1. The render created the files empty: the domain lets no one in.
	apply("empty files")
	expect("empty files", "127.0.0.2", "uri.example.com", "/admin", "403")
	expect("empty files", "127.0.0.3", "uri.example.com", "/admin", "403")
	expect("empty files", "127.0.0.2", "uri.example.com", "/", "200")
	expect("empty files", "127.0.0.2", "prio.example.com", "/", "403", "-A", "BadBot")
	limited("empty files", "127.0.0.2")

	// 2. partner resolves to .2: .2 passes each list, .3 does not, and .2's
	// SQL injection still meets the WAF.
	publish(1, "127.0.0.2")
	apply("published")
	expect("published", "127.0.0.2", "uri.example.com", "/admin", "200")
	expect("published", "127.0.0.3", "uri.example.com", "/admin", "403")
	expect("published", "127.0.0.2", "prio.example.com", "/", "200", "-A", "BadBot")
	expect("published", "127.0.0.3", "prio.example.com", "/", "403", "-A", "BadBot")
	expect("published", "127.0.0.2", "prio.example.com", "/", "200")
	expect("published", "127.0.0.2", "prio.example.com", sqli, "403")
	unlimited("published", "127.0.0.2")
	limited("published", "127.0.0.3")

	// 3. The files are emptied again (a revocation): .2 loses every exception.
	publish(2)
	apply("revoked")
	expect("revoked", "127.0.0.2", "uri.example.com", "/admin", "403")
	expect("revoked", "127.0.0.2", "prio.example.com", "/", "403", "-A", "BadBot")
	limited("revoked", "127.0.0.2")
}

// TestRealTrustedDomains checks the global trusted domains (#320). The rate
// limit host starts as v2.63.0 rendered it, with its zone, from
// testdata/real_nginx/rate_limit_trusted_v2.63.0.conf, rendered from the
// same host (rlData without its domain) by the templates of that release.
// The container's nginx.conf must also include
// /etc/nginx/geoip/geoip-active.conf, for $geoip2_country_code: the image's
// placeholder answers "--" for every client, which a whitelist of KR blocks.
func TestRealTrustedDomains(t *testing.T) {
	m, confd := realNginxManager(t)
	container := os.Getenv("NPG_REAL_NGINX_CONTAINER")
	m.httpPort = "8080"
	m.SetEnableIPv6(false)
	ctx := context.Background()

	const partner = "partner.example.com"
	newHost := func(id, domain string) *model.ProxyHost {
		h := baseHost(id, "127.0.0.1", true)
		h.DomainNames, h.ForwardPort = []string{domain}, 8081
		return h
	}
	hostGeo := newHost("00000000-0000-0000-0000-0000000000f7", "trusted-geo.example.com")
	hostACL := newHost("00000000-0000-0000-0000-0000000000f8", "trusted-acl.example.com")
	hostRL := newHost("00000000-0000-0000-0000-0000000000f9", "trusted-rl.example.com")

	const backendConf = "npg320r3_trusted_backend.conf"
	t.Cleanup(func() {
		for _, f := range []string{backendConf, GetConfigFilename(hostGeo), GetConfigFilename(hostACL), GetConfigFilename(hostRL), "npg_request_path.conf"} {
			_ = os.Remove(filepath.Join(confd, f))
		}
		_ = os.RemoveAll(filepath.Join(confd, "includes"))
	})
	if err := os.WriteFile(filepath.Join(confd, backendConf), []byte("server {\n    listen 127.0.0.1:8081;\n    modsecurity off;\n    location / {\n        return 200 \"backend\\n\";\n    }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Geo: a whitelist of KR. Access list: .2 denied by address. Rate
	// limit: 1 r/s with a burst of 1, so a third request in a row is
	// limited, and 127.0.0.4 trusted by address. Each host trusts partner.
	geoData := ProxyHostConfigData{Host: hostGeo, TrustedHostnames: []string{partner},
		GeoRestriction: &model.GeoRestriction{ProxyHostID: hostGeo.ID, Mode: "whitelist", Countries: []string{"KR"}, Enabled: true}}
	aclData := ProxyHostConfigData{Host: hostACL, TrustedHostnames: []string{partner},
		AccessList: &model.AccessList{ID: "00000000-0000-0000-0000-0000000000fa", Name: "not-two", Items: []model.AccessListItem{
			{ID: "00000000-0000-0000-0000-0000000000fb", Directive: "deny", Address: "127.0.0.2"}}}}
	rlData := ProxyHostConfigData{Host: hostRL, GlobalTrustedIPs: []string{"127.0.0.4"}, TrustedHostnames: []string{partner},
		RateLimit: &model.RateLimit{Enabled: true, RequestsPerSecond: 1, BurstSize: 1, ZoneSize: "1m", LimitBy: "ip", LimitResponse: 429}}

	apply := func(step string) {
		t.Helper()
		if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
			t.Fatalf("%s: apply = %+v, want accepted (nginx started new workers)", step, res)
		}
	}
	expect := func(step, ip, host, want string) {
		t.Helper()
		if got := realRequestStatus(t, container, ip, host, "/", want); got != want {
			t.Errorf("%s: %s from %s = %s, want %s", step, host, ip, got, want)
		}
	}
	render := func(data ...ProxyHostConfigData) {
		t.Helper()
		for _, d := range data {
			if err := m.GenerateConfigFull(ctx, d); err != nil {
				t.Fatalf("GenerateConfigFull: %v", err)
			}
		}
	}
	publish := func(gen int64, addrs ...string) {
		t.Helper()
		if _, err := m.WriteDNSIncludeFiles(model.DNSScopeKindTrusted, partner, gen, addrs); err != nil {
			t.Fatal(err)
		}
	}
	const rl = "trusted-rl.example.com"
	limited := func(step, ip string) { t.Helper(); expect(step, ip, rl, "429") }
	unlimited := func(step, ip string) {
		t.Helper()
		expect(step, ip, rl, "200")
		for i := 0; i < 5; i++ {
			if got := realRequestOnce(t, container, ip, rl, "/"); got != "200" {
				t.Errorf("%s: request %d in a row from %s = %s, want 200", step, i+2, ip, got)
				return
			}
		}
	}

	// 1. The rate limit host as v2.63.0 wrote it, then the current
	// templates over it: the zone's key is unchanged, so the running nginx
	// takes the reload.
	if err := m.ensureHostCommonInclude(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join("testdata", "real_nginx", "rate_limit_trusted_v2.63.0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, GetConfigFilename(hostRL)), old, 0o644); err != nil {
		t.Fatal(err)
	}
	apply("v2.63.0 rate limit host")
	unlimited("v2.63.0", "127.0.0.4")
	limited("v2.63.0", "127.0.0.3")
	render(geoData, aclData, rlData)
	apply("current templates over v2.63.0")
	unlimited("current templates", "127.0.0.4")
	limited("current templates", "127.0.0.3")

	// 2. The render created the domain's files empty: it trusts no one.
	expect("empty files", "127.0.0.2", "trusted-geo.example.com", "403")
	expect("empty files", "127.0.0.5", "trusted-acl.example.com", "403")

	// 3. partner resolves to .2 and .5: both pass the geo whitelist and the
	// rate limit. On the access list host the list's own deny of .2 comes
	// first; .5 gets in. Everyone else gets the 403 or the 429.
	publish(1, "127.0.0.2", "127.0.0.5")
	apply("published")
	expect("published", "127.0.0.2", "trusted-geo.example.com", "200")
	expect("published", "127.0.0.5", "trusted-geo.example.com", "200")
	expect("published", "127.0.0.3", "trusted-geo.example.com", "403")
	expect("published", "127.0.0.2", "trusted-acl.example.com", "403")
	expect("published", "127.0.0.5", "trusted-acl.example.com", "200")
	expect("published", "127.0.0.3", "trusted-acl.example.com", "403")
	unlimited("published", "127.0.0.2")
	limited("published", "127.0.0.3")

	// 4. A ban of .2 wins over the domain; .5 still passes.
	geoData.BannedIPs = []model.BannedIP{{ID: "00000000-0000-0000-0000-0000000000fc", IPAddress: "127.0.0.2", Reason: "test ban"}}
	render(geoData)
	apply("banned")
	expect("banned", "127.0.0.2", "trusted-geo.example.com", "403")
	expect("banned", "127.0.0.5", "trusted-geo.example.com", "200")

	// 5. The files are emptied again (a revocation): .5 loses every bypass.
	publish(2)
	apply("revoked")
	expect("revoked", "127.0.0.5", "trusted-geo.example.com", "403")
	expect("revoked", "127.0.0.5", "trusted-acl.example.com", "403")
	limited("revoked", "127.0.0.5")
}
