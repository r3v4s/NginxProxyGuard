package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// swaggerCoverageAllowlist names the registered routes that are deliberately
// not in swagger.yaml, each with the reason. Everything else a client can
// call must be documented: generated clients only know what the spec lists
// (#232, #337).
var swaggerCoverageAllowlist = map[string]string{
	// Swagger UI assets.
	"GET /api/docs/assets/:version/:file": "swagger-ui's own css/js for the /api/docs page, not an API call",
}

// servedSwaggerSpec fetches swagger.yaml through the route the server
// serves it on, so the test reads the same embedded file as /api/docs.
func servedSwaggerSpec(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	registerAllRoutesForAudit(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/docs/swagger.yaml", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("GET /api/docs/swagger.yaml = %d with %d bytes, want 200 with the spec", rec.Code, rec.Body.Len())
	}
	return rec.Body.String()
}

var (
	swaggerPathKey   = regexp.MustCompile(`^  ['"]?(/[^'"]*?)['"]?:\s*(#.*)?$`)
	swaggerMethodKey = regexp.MustCompile(`^    (get|put|post|delete|patch|head|options|trace):\s*(#.*)?$`)
	swaggerServerURL = regexp.MustCompile(`^\s*- url:\s*['"]?([^'"\s]+)`)
	swaggerParam     = regexp.MustCompile(`\{[^}/]+\}`)
	echoParam        = regexp.MustCompile(`:[^/]+`)
)

// swaggerOperations lists "METHOD /full/path" for every operation in the
// spec's paths. A path is joined to the document's server URL (/api/v1)
// unless it carries its own servers entry, as /health and /api/docs do.
// Parameters become {} so /x/{id} and /x/:id meet whatever they are named.
func swaggerOperations(t *testing.T, spec string) map[string]bool {
	t.Helper()
	lines := strings.Split(spec, "\n")
	firstServerURL := func(from int) string {
		for _, l := range lines[from:] {
			if m := swaggerServerURL.FindStringSubmatch(l); m != nil {
				return m[1]
			}
		}
		return ""
	}

	base := ""
	type pathItem struct {
		server  string
		methods []string
	}
	var order []string
	items := map[string]*pathItem{}
	var cur *pathItem
	inPaths := false
	for i, l := range lines {
		if l != "" && l[0] != ' ' && l[0] != '#' {
			inPaths = l == "paths:"
			if l == "servers:" {
				base = firstServerURL(i + 1)
			}
			continue
		}
		if !inPaths {
			continue
		}
		if m := swaggerPathKey.FindStringSubmatch(l); m != nil {
			cur = &pathItem{}
			items[m[1]] = cur
			order = append(order, m[1])
			continue
		}
		if cur == nil {
			continue
		}
		if strings.TrimRight(l, " ") == "    servers:" {
			cur.server = firstServerURL(i + 1)
		} else if m := swaggerMethodKey.FindStringSubmatch(l); m != nil {
			cur.methods = append(cur.methods, strings.ToUpper(m[1]))
		}
	}
	if base == "" || len(order) == 0 {
		t.Fatalf("swagger.yaml: found server %q and %d paths; the parser no longer understands the file", base, len(order))
	}

	ops := map[string]bool{}
	for _, p := range order {
		server := base
		if items[p].server != "" {
			server = items[p].server
		}
		full := swaggerParam.ReplaceAllString(strings.TrimSuffix(server, "/")+p, "{}")
		for _, m := range items[p].methods {
			ops[m+" "+full] = true
		}
	}
	return ops
}

// Every route the API registers is in swagger.yaml under the same path and
// method, or in the allowlist above with its reason. Without this the spec
// drifts silently: GET /filter-subscriptions/match shipped undocumented
// (#337), and in #232 a client generated from the spec dropped fields the
// API accepted.
func TestEveryRouteIsInSwagger(t *testing.T) {
	documented := swaggerOperations(t, servedSwaggerSpec(t))

	registered := map[string]bool{}
	var missing []string
	for _, r := range registerAllRoutesForAudit(t).Routes() {
		if isEchoCatchAll(r) {
			continue
		}
		key := r.Method + " " + r.Path
		registered[key] = true
		if _, allowed := swaggerCoverageAllowlist[key]; allowed {
			continue
		}
		if !documented[r.Method+" "+echoParam.ReplaceAllString(r.Path, "{}")] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d registered route(s) are not in api/internal/handler/swagger.yaml — document each "+
			"(the path without /api/v1, with {param}), or add it to swaggerCoverageAllowlist with the reason:\n%s",
			len(missing), strings.Join(missing, "\n"))
	}

	// An allowlist entry must name a live route that is still undocumented;
	// otherwise it would silently cover whatever is registered there next.
	for key := range swaggerCoverageAllowlist {
		method, path, _ := strings.Cut(key, " ")
		switch {
		case !registered[key]:
			t.Errorf("swaggerCoverageAllowlist has %q, which is not a registered route", key)
		case documented[method+" "+echoParam.ReplaceAllString(path, "{}")]:
			t.Errorf("swaggerCoverageAllowlist has %q, which swagger.yaml now documents — remove the entry", key)
		}
	}
}
