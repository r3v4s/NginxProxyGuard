package bootstrap

import (
	"net/http"
	"testing"

	"nginx-proxy-guard/internal/middleware"
)

// The confirm route allows a domain again in every list that uses it, so it
// needs what the list's PUT needs, access:write.
func TestDNSConfirmRouteNeedsAccessWrite(t *testing.T) {
	const path = "/api/v1/access-lists/:id/dns-confirm"
	registered := false
	for _, r := range registerAllRoutesForAudit(t).Routes() {
		if r.Method == http.MethodPost && r.Path == path {
			registered = true
		}
	}
	if !registered {
		t.Fatalf("POST %s is not registered", path)
	}
	if p, ok := middleware.RoutePermission(http.MethodPost, path); !ok || p != "access:write" {
		t.Fatalf("POST %s needs %q (mapped %v), want access:write", path, p, ok)
	}
}
