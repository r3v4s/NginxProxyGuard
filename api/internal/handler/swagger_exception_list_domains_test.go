package handler

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// swaggerPathBlock returns the text of path in swagger.yaml's paths, up to
// the next path.
func swaggerPathBlock(t *testing.T, path string) string {
	t.Helper()
	spec := string(swaggerYAML)
	start := strings.Index(spec, "\n  "+path+":\n")
	if start < 0 {
		t.Fatalf("swagger.yaml has no path %s", path)
	}
	block := spec[start+1:]
	if end := regexp.MustCompile(`\n  /|\ncomponents:`).FindStringIndex(block); end != nil {
		block = block[:end[0]+1]
	}
	return block
}

// Generated clients read these schemas (#320), so they must list what the
// four exception lists take and send for domains, the five confirm routes
// with their answers, and every kind of use the overview names.
func TestSwaggerDocumentsExceptionListDomains(t *testing.T) {
	for _, path := range []string{
		"/proxy-hosts/{id}/dns-confirm",
		"/global-uri-block/dns-confirm",
		"/settings/global-geo/dns-confirm",
		"/settings/global-rate-limit/dns-confirm",
		"/system-settings/trusted-dns-confirm",
	} {
		block := swaggerPathBlock(t, path)
		if !strings.HasPrefix(block, "  "+path+":\n    post:\n") {
			t.Errorf("%s: no post", path)
		}
		for _, want := range []string{"'200':", "'400':", "'403':", "'409':", "not_in_list", "not_in_review",
			"lookup_unavailable", "observation_changed", "nginx_reload_rejected", "DNSEntryStatus"} {
			if !strings.Contains(block, want) {
				t.Errorf("%s does not document %s", path, want)
			}
		}
	}
	if !strings.Contains(swaggerPathBlock(t, "/proxy-hosts/{id}/dns-confirm"), "'404':") {
		t.Error("/proxy-hosts/{id}/dns-confirm does not document 404")
	}

	// The fields the requests take and the GET responses carry.
	documented := func(schema string) []string { return swaggerSchemaProperties(t, schema) }
	for schema, want := range map[string][]string{
		"URIBlockConfig":             {"exception_hostnames", "exception_hostname_status", "exception_hostnames_skipped"},
		"CreateURIBlock":             {"exception_hostnames"},
		"GlobalURIBlockConfig":       {"exception_hostnames"},
		"GlobalURIBlock":             {"exception_hostnames", "exception_hostname_status"},
		"GeoRestriction":             {"allowed_hostnames", "allowed_hostname_status", "allowed_ips_ignored"},
		"CreateGeoRestriction":       {"allowed_hostnames"},
		"UpdateGeoRestriction":       {"allowed_hostnames"},
		"GlobalGeoRestriction":       {"allowed_hostnames", "allowed_hostname_status", "allowed_ips_ignored"},
		"UpdateGlobalGeoRestriction": {"allowed_hostnames"},
		"RateLimit":                  {"whitelist_hostnames", "whitelist_hostname_status"},
		"CreateRateLimit":            {"whitelist_hostnames"},
		"GlobalRateLimit":            {"whitelist_hostnames", "whitelist_hostname_status"},
		"UpdateGlobalRateLimit":      {"whitelist_hostnames"},
		"SystemSettings": {"global_trusted_ips", "global_trusted_ips_bypass_waf", "global_trusted_hostnames",
			"global_trusted_hostname_status", "global_trusted_ips_ignored"},
	} {
		have := documented(schema)
		for _, p := range want {
			if !slices.Contains(have, p) {
				t.Errorf("swagger %s has no property %s", schema, p)
			}
		}
	}
	// What the GET views add is documented on the schema the GET answers
	// with (the URI block list's entries are URIBlockConfig too).
	for schema, view := range map[string]reflect.Type{
		"URIBlockConfig":       reflect.TypeOf(uriBlockView{}),
		"GlobalURIBlock":       reflect.TypeOf(globalURIBlockView{}),
		"GeoRestriction":       reflect.TypeOf(geoRestrictionView{}),
		"GlobalGeoRestriction": reflect.TypeOf(globalGeoRestrictionView{}),
		"RateLimit":            reflect.TypeOf(rateLimitView{}),
		"GlobalRateLimit":      reflect.TypeOf(globalRateLimitView{}),
		"SystemSettings":       reflect.TypeOf(systemSettingsView{}),
	} {
		have := documented(schema)
		for _, p := range modelJSONNames(view) {
			if !slices.Contains(have, p) {
				t.Errorf("swagger %s has no property %s, which %s adds", schema, p, view.Name())
			}
		}
	}
	if list := modelJSONNames(reflect.TypeOf(uriBlockListEntryView{})); !slices.Equal(list, modelJSONNames(reflect.TypeOf(uriBlockView{}))) {
		t.Errorf("a URI block list entry adds %v, a host's URI block GET adds %v", list, modelJSONNames(reflect.TypeOf(uriBlockView{})))
	}

	use := swaggerSchemaBlock(t, "DNSEntryUse")
	m := regexp.MustCompile(`(?m)^        kind:\n(?:          .*\n)*?          enum: \[([^\]]*)\]`).FindStringSubmatch(use)
	if m == nil {
		t.Fatal("swagger DNSEntryUse.kind has no enum")
	}
	kinds := strings.Split(strings.ReplaceAll(m[1], " ", ""), ",")
	for _, k := range []string{"access_list", "uri_block", "priority_allow", "rate_limit", "trusted"} {
		if !slices.Contains(kinds, k) {
			t.Errorf("swagger DNSEntryUse.kind enum %v has no %s", kinds, k)
		}
	}
	for _, want := range []string{".geo", "global"} {
		if !strings.Contains(use, want) {
			t.Errorf("swagger DNSEntryUse does not mention %q (key, owner_id)", want)
		}
	}
}
