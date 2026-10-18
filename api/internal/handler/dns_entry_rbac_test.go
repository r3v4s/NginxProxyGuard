package handler

import (
	"context"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
)

// permGrants is an authorizer that grants exactly the permissions in it. A
// handler test that checks permissions needs one: without an authorizer in
// the context every check passes (HasPermissionFromContext).
type permGrants map[string]bool

func (g permGrants) CanUser(_ context.Context, _ string, permission string) bool {
	return g[permission]
}

func (g permGrants) CanToken(_ context.Context, _ *model.APIToken, permission string) bool {
	return g[permission]
}

// callWithGrants runs h on a JSON body, with the given path parameters, as a
// signed-in user who holds exactly g.
func callWithGrants(t *testing.T, h echo.HandlerFunc, g permGrants, method, body string, params ...string) *httptest.ResponseRecorder {
	t.Helper()
	return callWithGrantsCtx(t, context.Background(), h, g, method, body, params...)
}

// callWithGrantsCtx is callWithGrants on a request whose context is ctx: a
// test cancels it to stand for a client that leaves.
func callWithGrantsCtx(t *testing.T, ctx context.Context, h echo.HandlerFunc, g permGrants, method, body string, params ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	var names, values []string
	for i := 0; i+1 < len(params); i += 2 {
		names = append(names, params[i])
		values = append(values, params[i+1])
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	c.Set(authMiddleware.ContextKeyAuthorizer, g)
	c.Set("user_id", "00000000-0000-4000-8000-0000000016f1")
	if err := h(c); err != nil {
		t.Fatalf("handler returned %v", err)
	}
	return rec
}

// One table says which permission reads and writes a name's use in a scope.
// A scope that does not parse is readable and writable by no one.
func TestDNSScopePermissions(t *testing.T) {
	cases := map[string][2]string{
		"acl:" + testListID: {"access:read", "access:write"},
		"acl:not-a-uuid":    {"", ""},
		"uri:not-a-uuid":    {"", ""},
		"trusted:global":    {"", ""},
		"":                  {"", ""},
	}
	for scope, want := range cases {
		if got := dnsScopeReadPermission(scope); got != want[0] {
			t.Errorf("read %q = %q, want %q", scope, got, want[0])
		}
		if got := dnsScopeWritePermission(scope); got != want[1] {
			t.Errorf("write %q = %q, want %q", scope, got, want[1])
		}
	}
}

// Each use of a name in an exception list (#320) is read and changed with
// the permissions of the list's own screen: a host's lists proxy, the
// global lists waf (the screens they sit under), the global trusted list
// settings. A use without a row would make a confirm of every name used
// there answer 403 to everyone, and hide it in every overview.
func TestDNSScopePermissionsCoverEveryScopeKind(t *testing.T) {
	const host = "00000000-0000-4000-8000-0000000006a1"
	cases := map[string][2]string{
		"uri:" + host:  {"proxy:read", "proxy:write"},
		"prio:" + host: {"proxy:read", "proxy:write"},
		"rl:" + host:   {"proxy:read", "proxy:write"},
		"uri:global":   {"waf:read", "waf:write"},
		"prio:global":  {"waf:read", "waf:write"},
		"rl:global":    {"waf:read", "waf:write"},
		"trusted":      {"settings:read", "settings:write"},
	}
	for scope, want := range cases {
		if got := dnsScopeReadPermission(scope); got != want[0] {
			t.Errorf("read %q = %q, want %q", scope, got, want[0])
		}
		if got := dnsScopeWritePermission(scope); got != want[1] {
			t.Errorf("write %q = %q, want %q", scope, got, want[1])
		}
	}
	// Every permission in the table is one a role can hold.
	for _, want := range cases {
		for _, p := range want {
			if !slices.Contains(model.AllAreaPermissions, p) {
				t.Errorf("%q is not a permission of any area", p)
			}
		}
	}
}

// What a caller may see of a name's state: banned needs waf:read, self_ip
// ddns:read, the blocking file proxy:read.
func TestDNSStatusViewHidesWhatTheCallerMayNotRead(t *testing.T) {
	file := "proxy_host_x.conf"
	warnings := []string{model.DNSWarnBanned, model.DNSWarnSelfIP, model.DNSWarnCGNAT}
	st := model.DNSEntryStatus{Hostname: "partner.example.com", Warnings: warnings, BlockingFile: &file}

	got := dnsStatusView{}.filter(st)
	if !reflect.DeepEqual(got.Warnings, []string{model.DNSWarnCGNAT}) || got.BlockingFile != nil {
		t.Errorf("without permissions: warnings %v, blocking file %v", got.Warnings, got.BlockingFile)
	}
	got = dnsStatusView{banned: true, selfIP: true, proxyRead: true}.filter(st)
	if !reflect.DeepEqual(got.Warnings, warnings) || got.BlockingFile == nil {
		t.Errorf("with every permission: warnings %v, blocking file %v", got.Warnings, got.BlockingFile)
	}
	if !reflect.DeepEqual(st.Warnings, []string{model.DNSWarnBanned, model.DNSWarnSelfIP, model.DNSWarnCGNAT}) {
		t.Errorf("filter changed the service's slice: %v", st.Warnings)
	}
	// The DNS service gets the same view: banned, self_ip and the blocking
	// file each follow their own permission.
	if got := (dnsStatusView{banned: true, proxyRead: true}).serviceView(); got != (model.DNSStatusView{Banned: true, BlockingFile: true}) {
		t.Errorf("serviceView = %+v, want Banned and BlockingFile only", got)
	}
	if got := (dnsStatusView{selfIP: true}).serviceView(); got != (model.DNSStatusView{SelfIP: true}) {
		t.Errorf("serviceView = %+v, want SelfIP only", got)
	}
}
