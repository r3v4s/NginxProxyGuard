package handler

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// swaggerSchemaBlock returns the text of the components schema name in
// swagger.yaml, ending with a newline.
func swaggerSchemaBlock(t *testing.T, name string) string {
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
	return block + "\n"
}

// modelJSONNames returns the JSON names of rt's own fields, sorted. Embedded
// structs are left out.
func modelJSONNames(rt reflect.Type) []string {
	var names []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Anonymous {
			continue
		}
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Generated clients read these schemas, so they must list what
// GET /dns-entries, POST /dns-entries/apply and the system settings send
// send.
func TestSwaggerDocumentsTheDNSEntriesAPI(t *testing.T) {
	spec := string(swaggerYAML)
	for route, p := range map[string]string{
		"GET /dns-entries":        "\n  /dns-entries:\n    get:\n",
		"POST /dns-entries/apply": "\n  /dns-entries/apply:\n    post:\n",
	} {
		if !strings.Contains(spec, p) {
			t.Errorf("swagger.yaml does not document %s", route)
		}
	}
	for name, rt := range map[string]reflect.Type{
		"DNSEntrySettings": reflect.TypeOf(model.DNSEntrySettings{}),
		"DNSEntryOverview": reflect.TypeOf(model.DNSEntryOverview{}),
		"DNSEntryUse":      reflect.TypeOf(model.DNSEntryUse{}),
		"DNSApplyState":    reflect.TypeOf(model.DNSApplyState{}),
		"DNSApplyResponse": reflect.TypeOf(model.DNSApplyResponse{}),
	} {
		documented := swaggerSchemaProperties(t, name)
		sort.Strings(documented)
		if want := modelJSONNames(rt); strings.Join(documented, ",") != strings.Join(want, ",") {
			t.Errorf("swagger %s\n  %v\ndiffers from model.%s\n  %v", name, documented, rt.Name(), want)
		}
	}

	// An overview entry is a DNSEntryStatus plus its uses.
	entry := swaggerSchemaBlock(t, "DNSEntryOverviewEntry")
	if !strings.Contains(entry, "- $ref: '#/components/schemas/DNSEntryStatus'") {
		t.Error("swagger DNSEntryOverviewEntry does not include DNSEntryStatus")
	}
	var own []string
	for _, m := range regexp.MustCompile(`(?m)^            ([a-z0-9_]+):$`).FindAllStringSubmatch(entry, -1) {
		own = append(own, m[1])
	}
	sort.Strings(own)
	if want := modelJSONNames(reflect.TypeOf(model.DNSEntryOverviewEntry{})); strings.Join(own, ",") != strings.Join(want, ",") {
		t.Errorf("swagger DNSEntryOverviewEntry adds %v, model.DNSEntryOverviewEntry adds %v", own, want)
	}

	// Only this property of SystemSettings is pinned: the schema documents a
	// third of the response's fields.
	found := false
	for _, p := range swaggerSchemaProperties(t, "SystemSettings") {
		found = found || p == "dns_entry_settings"
	}
	if !found {
		t.Error("swagger SystemSettings has no property dns_entry_settings")
	}
}

// The ranges and defaults swagger documents are the ones the server applies:
// each documented minimum and maximum is accepted, one past it is refused.
func TestSwaggerDNSEntrySettingsRangesMatchTheServer(t *testing.T) {
	block := swaggerSchemaBlock(t, "DNSEntrySettings")
	defaults := map[string]interface{}{}
	raw, _ := json.Marshal(model.DefaultDNSEntrySettings())
	if err := json.Unmarshal(raw, &defaults); err != nil {
		t.Fatal(err)
	}
	props := regexp.MustCompile(`(?m)^        ([a-z_]+):\n((?:          .*\n)+)`).FindAllStringSubmatch(block, -1)
	if len(props) != len(defaults) {
		t.Fatalf("swagger DNSEntrySettings documents %d properties, the model has %d", len(props), len(defaults))
	}
	accepts := func(key string, v int) bool {
		_, err := model.MergeDNSEntrySettings(model.DefaultDNSEntrySettings(), json.RawMessage(fmt.Sprintf(`{%q: %d}`, key, v)))
		return err == nil
	}
	for _, p := range props {
		key, body := p[1], p[2]
		documented := ""
		if m := regexp.MustCompile(`(?m)^          default: (\S+)$`).FindStringSubmatch(body); m != nil {
			documented = m[1]
		}
		if documented != fmt.Sprint(defaults[key]) {
			t.Errorf("%s: documented default %q, the server's is %v", key, documented, defaults[key])
		}
		if key == "enabled" {
			continue
		}
		bounds := map[string]int{}
		for _, m := range regexp.MustCompile(`(?m)^          (minimum|maximum): (\d+)$`).FindAllStringSubmatch(body, -1) {
			bounds[m[1]], _ = strconv.Atoi(m[2])
		}
		lo, hasLo := bounds["minimum"]
		hi, hasHi := bounds["maximum"]
		if !hasLo || !hasHi {
			t.Errorf("%s: no documented minimum and maximum", key)
			continue
		}
		if !accepts(key, lo) || accepts(key, lo-1) || !accepts(key, hi) || accepts(key, hi+1) {
			t.Errorf("%s: documented %d-%d is not the range the server accepts", key, lo, hi)
		}
	}
}
