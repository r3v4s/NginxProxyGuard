package bootstrap

import (
	"net/http"
	"testing"

	"nginx-proxy-guard/internal/middleware"
)

// The domain entries' overview and "apply now" belong to the settings
// screen: settings:read and settings:write, like the tunables.
// Operator and viewer hold neither, so no screen of theirs may call
// them.
func TestDNSEntryRoutesNeedSettingsPermissions(t *testing.T) {
	want := map[[2]string]string{
		{http.MethodGet, "/api/v1/dns-entries"}:        "settings:read",
		{http.MethodPost, "/api/v1/dns-entries/apply"}: "settings:write",
	}
	registered := map[[2]string]bool{}
	for _, r := range registerAllRoutesForAudit(t).Routes() {
		registered[[2]string{r.Method, r.Path}] = true
	}
	for route, perm := range want {
		if !registered[route] {
			t.Errorf("%s %s is not registered", route[0], route[1])
		}
		if p, ok := middleware.RoutePermission(route[0], route[1]); !ok || p != perm {
			t.Errorf("%s %s needs %q (mapped %v), want %s", route[0], route[1], p, ok, perm)
		}
	}
}
