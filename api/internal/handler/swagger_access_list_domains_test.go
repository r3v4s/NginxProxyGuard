package handler

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// swaggerSchemaProperties returns the property names of the components schema
// name in swagger.yaml.
func swaggerSchemaProperties(t *testing.T, name string) []string {
	t.Helper()
	spec := string(swaggerYAML)
	start := strings.Index(spec, "\n    "+name+":\n")
	if start < 0 {
		t.Fatalf("%s schema not found in swagger.yaml", name)
	}
	block := spec[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[1:]); end != nil {
		block = block[:end[0]+1]
	}
	var props []string
	for _, m := range regexp.MustCompile(`(?m)^        ([a-z0-9_]+):$`).FindAllStringSubmatch(block, -1) {
		props = append(props, m[1])
	}
	return props
}

// Generated clients read these schemas, so they must list what the access
// list API sends and takes for domains.
func TestSwaggerDocumentsAccessListDomains(t *testing.T) {
	if !strings.Contains(string(swaggerYAML), "\n  /access-lists/{id}/dns-confirm:\n") {
		t.Error("swagger.yaml has no path /access-lists/{id}/dns-confirm")
	}
	for schema, want := range map[string][]string{
		"AccessList":           {"login_bypass_hosts"},
		"AccessListItem":       {"kind", "effect", "dns"},
		"CreateAccessListItem": {"kind"},
		"AccessListDNSConfirm": {"hostname", "expected_addresses", "expected_canonical_name"},
	} {
		have := map[string]bool{}
		for _, p := range swaggerSchemaProperties(t, schema) {
			have[p] = true
		}
		for _, p := range want {
			if !have[p] {
				t.Errorf("swagger %s has no property %s", schema, p)
			}
		}
	}

	var fields []string
	rt := reflect.TypeOf(model.DNSEntryStatus{})
	for i := 0; i < rt.NumField(); i++ {
		if name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	documented := swaggerSchemaProperties(t, "DNSEntryStatus")
	sort.Strings(fields)
	sort.Strings(documented)
	if strings.Join(documented, ",") != strings.Join(fields, ",") {
		t.Fatalf("swagger DNSEntryStatus\n  %v\ndiffers from model.DNSEntryStatus\n  %v", documented, fields)
	}
}
