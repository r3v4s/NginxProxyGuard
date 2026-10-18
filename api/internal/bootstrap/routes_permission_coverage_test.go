package bootstrap

import (
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/middleware"
)

// registerAllRoutesForAudit boots an Echo with every route registered but no
// working dependencies. Registration only stores handler method values and
// middleware closures — nothing dereferences the container until a request is
// served — so nil handlers are safe here and let the audit run without a
// database. If this panics, a register function gained work at registration
// time and needs looking at.
func registerAllRoutesForAudit(t *testing.T) *echo.Echo {
	t.Helper()
	e := echo.New()
	c := &Container{
		Handlers:     &Handlers{},
		Services:     &Services{},
		Repositories: &Repositories{},
	}
	RegisterRoutes(e, c)
	return e
}

// isEchoCatchAll reports whether a route is one of Echo's own per-group
// not-found / method-not-allowed placeholders rather than one of our handlers.
// Echo carries the sentinel in the METHOD field (echo.RouteNotFound ==
// "echo_route_not_found"), not in Name — matching on Name silently matched
// nothing and left 54 placeholders in the audit.
func isEchoCatchAll(r *echo.Route) bool {
	return r.Method == echo.RouteNotFound || r.Method == "echo_method_not_allowed"
}

// Authorization is default-deny, and this test is what makes that a fact rather
// than an intention: add a route without recording a permission decision and the
// build goes red instead of the route quietly reaching every logged-in user.
// (#222)
func TestEveryRouteHasAPermissionDecision(t *testing.T) {
	e := registerAllRoutesForAudit(t)

	var unmapped []string
	for _, r := range e.Routes() {
		if isEchoCatchAll(r) {
			continue
		}
		if !middleware.RouteDecisionExists(r.Method, r.Path) {
			unmapped = append(unmapped, r.Method+" "+r.Path)
		}
	}
	sort.Strings(unmapped)
	if len(unmapped) > 0 {
		t.Fatalf("%d route(s) have no authorization decision — add each to middleware/permissions.go "+
			"(routePermissions), or to SelfRoutes/PublicRoutes:\n%s",
			len(unmapped), strings.Join(unmapped, "\n"))
	}
}

// A route must not be in two buckets at once: an ambiguous decision is a bug
// that would be invisible at runtime because one bucket silently wins.
func TestNoRouteHasTwoDecisions(t *testing.T) {
	e := registerAllRoutesForAudit(t)
	for _, r := range e.Routes() {
		key := r.Method + " " + r.Path
		n := 0
		if middleware.SelfRoutes[key] {
			n++
		}
		if middleware.PublicRoutes[key] {
			n++
		}
		if _, ok := middleware.RoutePermission(r.Method, r.Path); ok {
			n++
		}
		if n > 1 {
			t.Errorf("%s belongs to %d decision buckets, want at most 1", key, n)
		}
	}
}

// The allowlists must describe routes that actually exist. A stale entry is how
// a permission silently stops applying after a path is renamed.
func TestAllowlistsHaveNoStaleEntries(t *testing.T) {
	e := registerAllRoutesForAudit(t)
	live := map[string]bool{}
	for _, r := range e.Routes() {
		live[r.Method+" "+r.Path] = true
	}
	for _, set := range []struct {
		name string
		m    map[string]bool
	}{
		{"SelfRoutes", middleware.SelfRoutes},
		{"PublicRoutes", middleware.PublicRoutes},
	} {
		for key := range set.m {
			if !live[key] {
				t.Errorf("%s contains %q, which is not a registered route", set.name, key)
			}
		}
	}
}

// The confirm routes of the four exception lists (#320) are registered,
// so the coverage test above holds them to a decision, and each needs
// the permission of its list's PUT: a confirm allows the domain again there.
// The handler checks the other lists that use the name.
func TestExceptionListConfirmRoutesNeedTheirListsWritePermission(t *testing.T) {
	want := map[string]string{
		"/api/v1/proxy-hosts/:id/dns-confirm":            "proxy:write",
		"/api/v1/global-uri-block/dns-confirm":           "waf:write",
		"/api/v1/settings/global-geo/dns-confirm":        "waf:write",
		"/api/v1/settings/global-rate-limit/dns-confirm": "waf:write",
		"/api/v1/system-settings/trusted-dns-confirm":    "settings:write",
	}
	registered := map[string]bool{}
	for _, r := range registerAllRoutesForAudit(t).Routes() {
		if r.Method == "POST" {
			registered[r.Path] = true
		}
	}
	for path, perm := range want {
		if !registered[path] {
			t.Errorf("POST %s is not registered", path)
		}
		if p, ok := middleware.RoutePermission("POST", path); !ok || p != perm {
			t.Errorf("POST %s needs %q (mapped %v), want %s", path, p, ok, perm)
		}
	}
}
