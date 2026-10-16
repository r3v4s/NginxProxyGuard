package nginx

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestAdvancedConfigHasAuth(t *testing.T) {
	for _, tc := range []struct {
		cfg  string
		want bool
	}{
		// TestAdvancedConfigHasTopLevel's inputs, answered for any depth.
		{"auth_request /ext;", true},
		{"  auth_request off;\n", true},
		{"proxy_set_header X-A b; auth_request /ext;", true},
		{"location /a/ {\n    auth_request /ext;\n}\n", true},
		{"location /a/ { proxy_pass http://192.0.2.1; }\nauth_request /ext;", true},
		{"if ($x) {\n    auth_request /ext;\n}", true},
		{"auth_request_set $a $upstream_status;", false},
		{"# auth_request /ext;\nclient_max_body_size 1m;", false},
		{"add_header X-Note \"auth_request /x;\";", false},
		{"add_header X-Note 'a { b'; auth_request /ext;", true},
		{"", false},
		// auth_basic, in any block; only as a directive name.
		{"location /private { auth_basic \"Restricted\"; auth_basic_user_file /etc/nginx/.htpasswd; }", true},
		{"location /a { location /b { auth_basic x; } }", true},
		{"auth_basic_user_file /etc/nginx/.htpasswd;", false},
		{"location /x {\n    # auth_basic \"x\";\n    proxy_pass http://192.0.2.1;\n}", false},
		{"proxy_set_header X-Mode auth_basic;", false},
		// nginx's tokens: "#" and quotes open a comment or a string only at the
		// start of a word, "${" stays in the word, "\" escapes one byte.
		{"set $a b#c; auth_basic \"x\";", true},
		{"add_header X a\"b; auth_basic x; c\"d;", true},
		{"set $a ${b}auth_basic;", false},
		{"add_header X-A \"a\\\"b; auth_basic x;\";", false},
		{"add_header X-A \"a\\\"b\"; auth_basic x;", true},
	} {
		if got := AdvancedConfigHasAuth(tc.cfg); got != tc.want {
			t.Errorf("AdvancedConfigHasAuth(%q) = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

func TestAdvancedConfigHasAccessRules(t *testing.T) {
	for _, tc := range []struct {
		cfg  string
		want bool
	}{
		{"allow 192.0.2.1;\ndeny all;", true},
		{"location /admin {\n    deny all;\n}", true},
		{"location /api { allow 192.0.2.0/24; proxy_pass http://192.0.2.1; }", true},
		{"satisfy any;", true},
		{"location /api { proxy_pass http://192.0.2.1; }", false},
		{"# deny all;\nproxy_read_timeout 60s;", false},
		{"add_header X-Policy \"deny all\";", false},
		{"proxy_set_header X-Allow allow;", false},
		{"", false},
	} {
		if got := AdvancedConfigHasAccessRules(tc.cfg); got != tc.want {
			t.Errorf("AdvancedConfigHasAccessRules(%q) = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

// One answer to "does this host have a login": an auth
// provider, or auth_basic or an old auth_request anywhere in Advanced Config.
func TestAccessPhaseAuth(t *testing.T) {
	fa := &model.AuthProvider{Type: "authelia", ProviderURL: "http://192.0.2.40:9091", TimeoutMs: 2000, Enabled: true}
	for _, tc := range []struct {
		name     string
		provider *model.AuthProvider
		advanced string
		want     bool
	}{
		{"nothing", nil, "", false},
		{"forwardauth", fa, "", true},
		{"auth_basic at the top", nil, "auth_basic \"Restricted\";\nauth_basic_user_file /etc/nginx/.htpasswd;", true},
		{"auth_basic in a location", nil, "location /private { auth_basic \"x\"; auth_basic_user_file /etc/nginx/.htpasswd; }", true},
		{"old auth_request", nil, "location /app/ {\n    proxy_pass http://192.0.2.20:8080;\n}\nauth_request /check;", true},
		{"in a comment", nil, "# auth_basic \"x\";\nclient_max_body_size 1m;", false},
		{"in a quoted string", nil, "add_header X-Note \"auth_basic off\";", false},
		{"auth_basic_user_file alone", nil, "auth_basic_user_file /etc/nginx/.htpasswd;", false},
	} {
		h := baseHost(dnsTestHostID, "192.0.2.20", true)
		h.AdvancedConfig = tc.advanced
		if got := (ProxyHostConfigData{Host: h, AuthProvider: tc.provider}).AccessPhaseAuth(); got != tc.want {
			t.Errorf("%s: AccessPhaseAuth = %v, want %v", tc.name, got, tc.want)
		}
	}
	if (ProxyHostConfigData{}).AccessPhaseAuth() {
		t.Error("no host and no auth provider: AccessPhaseAuth = true")
	}
}

// ListSkipsLogin is true exactly when the rendered block has "satisfy any"
// and the host has a login. The list editor's and the host form's warnings
// and the fail2ban gate rely on it matching the config.
func TestListSkipsLoginMatchesTheRenderedBlock(t *testing.T) {
	fa := &model.AuthProvider{Type: "authelia", ProviderURL: "http://192.0.2.40:9091", TimeoutMs: 2000, Enabled: true}
	logins := []struct {
		name     string
		provider *model.AuthProvider
		advanced string
	}{
		{"no login", nil, ""},
		{"forwardauth", fa, ""},
		{"auth_basic in a location", nil, "location /private {\n    auth_basic \"x\";\n    auth_basic_user_file /etc/nginx/.htpasswd;\n    proxy_pass http://192.0.2.20:8080;\n}\n"},
	}
	for _, login := range logins {
		for _, satisfyAny := range []bool{false, true} {
			for _, challenge := range []bool{false, true} {
				h := baseHost(dnsTestHostID, "192.0.2.20", true)
				h.AdvancedConfig = login.advanced
				list := dnsTestList(model.AccessListItem{ID: "r1", Directive: "allow", Address: "192.0.2.0/24"}, domainRow("r2", "partner.example.com", 1))
				list.SatisfyAny = satisfyAny
				d := ProxyHostConfigData{Host: h, AuthProvider: login.provider, AccessList: list}
				if challenge {
					d.GeoRestriction = geoChallenge(false)
				}
				rendered := strings.Contains(renderForTest(t, d), "    satisfy any;")
				if got, want := d.ListSkipsLogin(), rendered && d.AccessPhaseAuth(); got != want {
					t.Errorf("%s, satisfy any %v, challenge %v: ListSkipsLogin = %v, want %v (satisfy any rendered: %v)",
						login.name, satisfyAny, challenge, got, want, rendered)
				}
			}
		}
	}
	empty := ProxyHostConfigData{Host: baseHost(dnsTestHostID, "192.0.2.20", true), AuthProvider: fa,
		AccessList: &model.AccessList{ID: dnsTestListID, SatisfyAny: true}}
	if empty.ListSkipsLogin() {
		t.Error("a list without rules renders no block, so it lets nobody skip the login")
	}
}
