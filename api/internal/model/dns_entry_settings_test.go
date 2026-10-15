package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dnsSettingsRanges are the documented ranges, written out here instead of
// read from the implementation's table.
var dnsSettingsRanges = []struct {
	key           string
	min, max, def int
}{
	{"check_interval_seconds", 30, 3600, 60},
	{"min_reload_gap_seconds", 60, 3600, 300},
	{"stale_grace_hours", 1, 168, 24},
	{"not_found_checks", 1, 10, 2},
	{"max_changes_per_day", 2, 48, 6},
	{"max_per_list", 1, 64, 16},
	{"max_total", 1, 256, 64},
	{"max_addresses_per_family", 1, 16, 4},
}

// dnsSettingsValue reads one key of s through its JSON form.
func dnsSettingsValue(t *testing.T, s DNSEntrySettings, key string) interface{} {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	v, ok := m[key]
	if !ok {
		t.Fatalf("DNSEntrySettings has no JSON key %q", key)
	}
	return v
}

func TestDefaultDNSEntrySettings(t *testing.T) {
	s := DefaultDNSEntrySettings()
	if !s.Enabled {
		t.Error("the feature must be on by default")
	}
	for _, r := range dnsSettingsRanges {
		if got := dnsSettingsValue(t, s, r.key); got != float64(r.def) {
			t.Errorf("default %s = %v, want %d", r.key, got, r.def)
		}
	}
	if err := s.Validate(); err != nil {
		t.Errorf("the defaults fail Validate: %v", err)
	}
	if s.CheckInterval() != time.Minute || s.MinReloadGap() != 5*time.Minute || s.StaleGrace() != 24*time.Hour {
		t.Errorf("durations = %v %v %v", s.CheckInterval(), s.MinReloadGap(), s.StaleGrace())
	}
}

// The struct, the documented keys and Merge agree on the key list (Parse,
// Normalize, Validate and Diff walk the same table as Merge).
func TestDNSEntrySettingsKeysMatchTheStruct(t *testing.T) {
	var tags []string
	rt := reflect.TypeOf(DNSEntrySettings{})
	for i := 0; i < rt.NumField(); i++ {
		tags = append(tags, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	want := []string{"enabled"}
	for _, r := range dnsSettingsRanges {
		want = append(want, r.key)
	}
	sort.Strings(tags)
	sort.Strings(want)
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Fatalf("json keys = %v, want %v", tags, want)
	}
	for _, r := range dnsSettingsRanges {
		if _, err := MergeDNSEntrySettings(DefaultDNSEntrySettings(), json.RawMessage(`{"`+r.key+`": `+strconv.Itoa(r.min)+`}`)); err != nil {
			t.Errorf("Merge does not know %s: %v", r.key, err)
		}
	}
}

func TestParseDNSEntrySettings(t *testing.T) {
	def := DefaultDNSEntrySettings()
	for _, raw := range []string{"", "null", "{}", "not json", "[]", `"x"`, "5", `{"check_interval": 30}`} {
		if got := ParseDNSEntrySettings([]byte(raw)); got != def {
			t.Errorf("Parse(%q) = %+v, want the defaults", raw, got)
		}
	}
	if got := ParseDNSEntrySettings(nil); got != def {
		t.Errorf("Parse(nil) = %+v, want the defaults", got)
	}

	got := ParseDNSEntrySettings([]byte(`{"check_interval_seconds": 90}`))
	want := def
	want.CheckIntervalSeconds = 90
	if got != want {
		t.Errorf("a missing key must take its default: got %+v", got)
	}

	got = ParseDNSEntrySettings([]byte(`{"enabled": false}`))
	if got.Enabled || got.CheckIntervalSeconds != 60 {
		t.Errorf(`{"enabled": false} = %+v`, got)
	}

	// An unusable value takes its default; the rest still counts, so the
	// feature does not come back on next to a typo.
	got = ParseDNSEntrySettings([]byte(`{"enabled": false, "check_interval_seconds": "90", "max_total": 1.5}`))
	if got.Enabled || got.CheckIntervalSeconds != 60 || got.MaxTotal != 64 {
		t.Errorf("wrongly typed values = %+v, want enabled false and the two numbers at their defaults", got)
	}
	got = ParseDNSEntrySettings([]byte(`{"enabled": null, "max_per_list": null}`))
	if got != def {
		t.Errorf("null values = %+v, want the defaults", got)
	}

	// Hand-edited values out of range are clamped, not replaced.
	got = ParseDNSEntrySettings([]byte(`{"check_interval_seconds": 5, "max_total": 100000, "not_found_checks": 0, "stale_grace_hours": -3}`))
	if got.CheckIntervalSeconds != 30 || got.MaxTotal != 256 || got.NotFoundChecks != 1 || got.StaleGraceHours != 1 {
		t.Errorf("out-of-range values = %+v, want 30, 256, 1, 1", got)
	}
}

func TestDNSEntrySettingsNormalizeClampsEachKey(t *testing.T) {
	for _, r := range dnsSettingsRanges {
		for _, tc := range []struct{ in, want int }{{r.min - 1, r.min}, {r.min, r.min}, {r.max, r.max}, {r.max + 1, r.max}, {0, r.min}} {
			s := ParseDNSEntrySettings([]byte(`{"` + r.key + `": ` + strconv.Itoa(tc.in) + `}`))
			if got := dnsSettingsValue(t, s, r.key); got != float64(tc.want) {
				t.Errorf("%s=%d normalizes to %v, want %d", r.key, tc.in, got, tc.want)
			}
		}
	}
}

func TestDNSEntrySettingsValidate(t *testing.T) {
	for _, r := range dnsSettingsRanges {
		for _, v := range []int{r.min, r.max} {
			if _, err := MergeDNSEntrySettings(DefaultDNSEntrySettings(), json.RawMessage(`{"`+r.key+`": `+strconv.Itoa(v)+`}`)); err != nil {
				t.Errorf("%s=%d refused: %v", r.key, v, err)
			}
		}
		for _, v := range []int{r.min - 1, r.max + 1} {
			_, err := MergeDNSEntrySettings(DefaultDNSEntrySettings(), json.RawMessage(`{"`+r.key+`": `+strconv.Itoa(v)+`}`))
			want := "dns_entry_settings." + r.key + " must be between " + strconv.Itoa(r.min) + " and " + strconv.Itoa(r.max) + " (got " + strconv.Itoa(v) + ")"
			if !errors.Is(err, ErrInvalidInput) || !strings.HasSuffix(err.Error(), want) {
				t.Errorf("%s=%d: err = %v, want ErrInvalidInput ending in %q", r.key, v, err, want)
			}
		}
	}
	s := DefaultDNSEntrySettings()
	s.NotFoundChecks = 11
	if err := s.Validate(); !errors.Is(err, ErrInvalidInput) || !strings.HasSuffix(err.Error(), "dns_entry_settings.not_found_checks must be between 1 and 10 (got 11)") {
		t.Errorf("Validate() = %v", err)
	}
	// No rule across keys: a list limit above the install limit is fine.
	s = DefaultDNSEntrySettings()
	s.MaxPerList, s.MaxTotal = 64, 1
	if err := s.Validate(); err != nil {
		t.Errorf("max_per_list above max_total refused: %v", err)
	}
}

func TestMergeDNSEntrySettings(t *testing.T) {
	cur := DefaultDNSEntrySettings()
	cur.Enabled = false
	cur.CheckIntervalSeconds = 120

	got, err := MergeDNSEntrySettings(cur, json.RawMessage(`{"check_interval_seconds": 90}`))
	if err != nil || got.Enabled || got.CheckIntervalSeconds != 90 || got.MaxTotal != 64 {
		t.Fatalf("partial merge = %+v, %v; want enabled kept false and the interval 90", got, err)
	}
	got, err = MergeDNSEntrySettings(cur, json.RawMessage(`{"enabled": null, "check_interval_seconds": null}`))
	if err != nil || got != cur {
		t.Fatalf("null values = %+v, %v; want no change", got, err)
	}
	got, err = MergeDNSEntrySettings(cur, json.RawMessage(`null`))
	if err != nil || got != cur {
		t.Fatalf("null object = %+v, %v; want no change", got, err)
	}

	// A hand-edited stored value never blocks saving another key.
	raw := cur
	raw.CheckIntervalSeconds = 5
	got, err = MergeDNSEntrySettings(raw, json.RawMessage(`{"max_total": 100}`))
	if err != nil || got.MaxTotal != 100 || got.CheckIntervalSeconds != 30 {
		t.Fatalf("merge over a hand-edited value = %+v, %v", got, err)
	}

	bad := []struct{ raw, want string }{
		{`{"check_interval": 30}`, `dns_entry_settings: unknown key "check_interval"`},
		{`{"Enabled": false}`, `dns_entry_settings: unknown key "Enabled"`},
		{`{"check_interval_seconds": "60"}`, "dns_entry_settings.check_interval_seconds must be a whole number"},
		{`{"check_interval_seconds": 60.5}`, "dns_entry_settings.check_interval_seconds must be a whole number"},
		{`{"enabled": "yes"}`, "dns_entry_settings.enabled must be true or false"},
		{`[1]`, "dns_entry_settings must be a JSON object"},
		{`"x"`, "dns_entry_settings must be a JSON object"},
		{`{"max_total": 300}`, "dns_entry_settings.max_total must be between 1 and 256 (got 300)"},
	}
	for _, tc := range bad {
		got, err := MergeDNSEntrySettings(cur, json.RawMessage(tc.raw))
		if !errors.Is(err, ErrInvalidInput) || !strings.HasSuffix(err.Error(), tc.want) {
			t.Errorf("Merge(%s): err = %v, want ErrInvalidInput ending in %q", tc.raw, err, tc.want)
		}
		if got != cur {
			t.Errorf("Merge(%s) returned %+v on error, want cur unchanged", tc.raw, got)
		}
	}
}

func TestDiffDNSEntrySettings(t *testing.T) {
	before := DefaultDNSEntrySettings()
	if d := DiffDNSEntrySettings(before, before); len(d) != 0 {
		t.Fatalf("no change gave %v", d)
	}
	after := before
	after.Enabled = false
	after.CheckIntervalSeconds = 30
	want := map[string]interface{}{
		"enabled":                []interface{}{true, false},
		"check_interval_seconds": []interface{}{60, 30},
	}
	if d := DiffDNSEntrySettings(before, after); !reflect.DeepEqual(d, want) {
		t.Fatalf("diff = %#v, want %#v", d, want)
	}
}

// GET /system-settings shows the stored value normalized: an out-of-range
// hand edit echoed back by the form would make every later save fail.
func TestSystemSettingsResponseNormalizesDNSEntrySettings(t *testing.T) {
	s := &SystemSettings{DNSEntrySettings: json.RawMessage(`{"enabled": false, "check_interval_seconds": 5}`)}
	got := s.ToResponse().DNSEntrySettings
	if got.Enabled || got.CheckIntervalSeconds != 30 || got.MaxTotal != 64 {
		t.Fatalf("response dns_entry_settings = %+v", got)
	}
	if got := (&SystemSettings{}).ToResponse().DNSEntrySettings; got != DefaultDNSEntrySettings() {
		t.Fatalf("a row without the column = %+v, want the defaults", got)
	}
}

// The repository caches SystemSettings as JSON in Valkey; the tunables must
// survive that round trip or every read after the first cache write would
// see the defaults (enabled true).
func TestSystemSettingsCacheCopyKeepsDNSEntrySettings(t *testing.T) {
	in := SystemSettings{DNSEntrySettings: json.RawMessage(`{"enabled":false}`)}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SystemSettings
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if ParseDNSEntrySettings(out.DNSEntrySettings).Enabled {
		t.Fatalf("cached copy lost dns_entry_settings: %s", out.DNSEntrySettings)
	}
}

func TestUpdateSystemSettingsRequestCarriesDNSEntrySettings(t *testing.T) {
	var req UpdateSystemSettingsRequest
	if err := json.Unmarshal([]byte(`{"dns_entry_settings": {"check_interval_seconds": 90}}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.DNSEntrySettings == nil || !strings.Contains(string(*req.DNSEntrySettings), "90") {
		t.Fatalf("request field = %v", req.DNSEntrySettings)
	}
	req = UpdateSystemSettingsRequest{}
	if err := json.Unmarshal([]byte(`{"dns_entry_settings": null}`), &req); err != nil || req.DNSEntrySettings != nil {
		t.Fatalf("null must leave the field nil (no change): %v %v", req.DNSEntrySettings, err)
	}
}

// GET /dns-entries; the UI reads these names.
func TestDNSEntryOverviewJSONKeys(t *testing.T) {
	dnsSameKeys(t, "DNSEntryOverview", dnsJSONKeys(t, DNSEntryOverview{}), []string{
		"settings", "env_disabled", "env_interval_seconds", "total_names", "apply", "entries",
	})
}
