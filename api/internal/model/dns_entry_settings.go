package model

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Domain entry tunables (#320, system_settings.dns_entry_settings): the
// ranges the server accepts. The UI mirrors these numbers
// (ui/src/components/settings/dnsEntryLimits.ts), so it never offers a value
// the server refuses. Changing one here means changing it there.
const (
	// How often every used name is resolved again, in seconds.
	DNSEntryCheckIntervalMin     = 30
	DNSEntryCheckIntervalMax     = 3600
	DNSEntryCheckIntervalDefault = 60

	// Least time between two reloads that add DNS addresses, in seconds.
	// Revocations never wait for it.
	DNSEntryMinReloadGapMin     = 60
	DNSEntryMinReloadGapMax     = 3600
	DNSEntryMinReloadGapDefault = 300

	// How long a family keeps its last addresses while lookups fail with a
	// transient error, in hours.
	DNSEntryStaleGraceHoursMin     = 1
	DNSEntryStaleGraceHoursMax     = 168
	DNSEntryStaleGraceHoursDefault = 24

	// Consecutive "no such name" answers before a family is emptied.
	DNSEntryNotFoundChecksMin     = 1
	DNSEntryNotFoundChecksMax     = 10
	DNSEntryNotFoundChecksDefault = 2

	// Applied changes of one name in 24 hours before it needs review.
	DNSEntryMaxChangesPerDayMin     = 2
	DNSEntryMaxChangesPerDayMax     = 48
	DNSEntryMaxChangesPerDayDefault = 6

	// Domain names in one list.
	DNSEntryMaxPerListMin     = 1
	DNSEntryMaxPerListMax     = 64
	DNSEntryMaxPerListDefault = 16

	// Distinct domain names in the whole install.
	DNSEntryMaxTotalMin     = 1
	DNSEntryMaxTotalMax     = 256
	DNSEntryMaxTotalDefault = 64

	// Addresses of one name per family; a larger answer is refused whole.
	DNSEntryMaxAddressesPerFamilyMin     = 1
	DNSEntryMaxAddressesPerFamilyMax     = 16
	DNSEntryMaxAddressesPerFamilyDefault = 4
)

// DNSEntrySettings are the domain entry tunables. The stored form is one
// jsonb object; read it with ParseDNSEntrySettings, which fills missing keys
// with defaults and clamps hand-edited values into range.
type DNSEntrySettings struct {
	Enabled               bool `json:"enabled"`
	CheckIntervalSeconds  int  `json:"check_interval_seconds"`
	MinReloadGapSeconds   int  `json:"min_reload_gap_seconds"`
	StaleGraceHours       int  `json:"stale_grace_hours"`
	NotFoundChecks        int  `json:"not_found_checks"`
	MaxChangesPerDay      int  `json:"max_changes_per_day"`
	MaxPerList            int  `json:"max_per_list"`
	MaxTotal              int  `json:"max_total"`
	MaxAddressesPerFamily int  `json:"max_addresses_per_family"`
}

const dnsEntrySettingsEnabledKey = "enabled"

// dnsEntrySettingsInt describes one numeric tunable. Parse, Merge, Normalize,
// Validate and Diff all walk this one table, so a new key cannot be handled
// by some of them and missed by others.
type dnsEntrySettingsInt struct {
	key           string
	min, max, def int
	field         func(*DNSEntrySettings) *int
}

var dnsEntrySettingsInts = []dnsEntrySettingsInt{
	{"check_interval_seconds", DNSEntryCheckIntervalMin, DNSEntryCheckIntervalMax, DNSEntryCheckIntervalDefault,
		func(s *DNSEntrySettings) *int { return &s.CheckIntervalSeconds }},
	{"min_reload_gap_seconds", DNSEntryMinReloadGapMin, DNSEntryMinReloadGapMax, DNSEntryMinReloadGapDefault,
		func(s *DNSEntrySettings) *int { return &s.MinReloadGapSeconds }},
	{"stale_grace_hours", DNSEntryStaleGraceHoursMin, DNSEntryStaleGraceHoursMax, DNSEntryStaleGraceHoursDefault,
		func(s *DNSEntrySettings) *int { return &s.StaleGraceHours }},
	{"not_found_checks", DNSEntryNotFoundChecksMin, DNSEntryNotFoundChecksMax, DNSEntryNotFoundChecksDefault,
		func(s *DNSEntrySettings) *int { return &s.NotFoundChecks }},
	{"max_changes_per_day", DNSEntryMaxChangesPerDayMin, DNSEntryMaxChangesPerDayMax, DNSEntryMaxChangesPerDayDefault,
		func(s *DNSEntrySettings) *int { return &s.MaxChangesPerDay }},
	{"max_per_list", DNSEntryMaxPerListMin, DNSEntryMaxPerListMax, DNSEntryMaxPerListDefault,
		func(s *DNSEntrySettings) *int { return &s.MaxPerList }},
	{"max_total", DNSEntryMaxTotalMin, DNSEntryMaxTotalMax, DNSEntryMaxTotalDefault,
		func(s *DNSEntrySettings) *int { return &s.MaxTotal }},
	{"max_addresses_per_family", DNSEntryMaxAddressesPerFamilyMin, DNSEntryMaxAddressesPerFamilyMax, DNSEntryMaxAddressesPerFamilyDefault,
		func(s *DNSEntrySettings) *int { return &s.MaxAddressesPerFamily }},
}

// DefaultDNSEntrySettings returns the tunables of an install that never
// changed them: the feature on, every number at its default.
func DefaultDNSEntrySettings() DNSEntrySettings {
	s := DNSEntrySettings{Enabled: true}
	for _, f := range dnsEntrySettingsInts {
		*f.field(&s) = f.def
	}
	return s
}

// ParseDNSEntrySettings reads the stored jsonb value. Empty input, JSON null,
// invalid JSON and anything but an object give the defaults. A missing key,
// or one whose value has the wrong type, takes its default; the other keys
// keep their values, so an unusable value next to "enabled": false never
// turns the feature back on. Unknown keys are ignored. The result is
// normalized.
func ParseDNSEntrySettings(raw []byte) DNSEntrySettings {
	s := DefaultDNSEntrySettings()
	var fields map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil {
		return s
	}
	// A pointer stays nil for a missing key and for null, and is set only
	// when the value has the right type.
	var enabled *bool
	if json.Unmarshal(fields[dnsEntrySettingsEnabledKey], &enabled) == nil && enabled != nil {
		s.Enabled = *enabled
	}
	for _, f := range dnsEntrySettingsInts {
		var n *int
		if json.Unmarshal(fields[f.key], &n) == nil && n != nil {
			*f.field(&s) = *n
		}
	}
	return s.Normalize()
}

// Normalize clamps every number into its range: below the minimum becomes
// the minimum, above the maximum the maximum. It is for values that did not
// pass Validate, such as a hand-edited row.
func (s DNSEntrySettings) Normalize() DNSEntrySettings {
	for _, f := range dnsEntrySettingsInts {
		v := f.field(&s)
		*v = min(max(*v, f.min), f.max)
	}
	return s
}

// Validate refuses a number outside its range, naming the first one in key
// order. It does not compare keys with each other: max_per_list may exceed
// max_total.
func (s DNSEntrySettings) Validate() error {
	for _, f := range dnsEntrySettingsInts {
		if v := *f.field(&s); v < f.min || v > f.max {
			return fmt.Errorf("%w: dns_entry_settings.%s must be between %d and %d (got %d)", ErrInvalidInput, f.key, f.min, f.max, v)
		}
	}
	return nil
}

// MergeDNSEntrySettings applies a PUT's partial object to cur, the stored
// value: keys the request leaves out keep cur's values (an omitted "enabled"
// changes nothing), and a key set to null changes nothing either. cur is
// normalized first, so a hand-edited stored value never blocks a save that
// does not touch it. An unknown key, a value of the wrong type, anything but
// an object, and a number out of range are refused with ErrInvalidInput and
// the key's path; cur is then returned unchanged.
func MergeDNSEntrySettings(cur DNSEntrySettings, raw json.RawMessage) (DNSEntrySettings, error) {
	base := cur.Normalize()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return cur, fmt.Errorf("%w: dns_entry_settings must be a JSON object", ErrInvalidInput)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := base
	for _, k := range keys {
		v := fields[k]
		if k == dnsEntrySettingsEnabledKey {
			if err := json.Unmarshal(v, &out.Enabled); err != nil {
				return cur, fmt.Errorf("%w: dns_entry_settings.%s must be true or false", ErrInvalidInput, k)
			}
			continue
		}
		f, ok := dnsEntrySettingsIntByKey(k)
		if !ok {
			return cur, fmt.Errorf("%w: dns_entry_settings: unknown key %q", ErrInvalidInput, k)
		}
		if err := json.Unmarshal(v, f.field(&out)); err != nil {
			return cur, fmt.Errorf("%w: dns_entry_settings.%s must be a whole number", ErrInvalidInput, k)
		}
	}
	if err := out.Validate(); err != nil {
		return cur, err
	}
	return out, nil
}

func dnsEntrySettingsIntByKey(key string) (dnsEntrySettingsInt, bool) {
	for _, f := range dnsEntrySettingsInts {
		if f.key == key {
			return f, true
		}
	}
	return dnsEntrySettingsInt{}, false
}

// DiffDNSEntrySettings returns {json key: [before, after]} for every key whose
// value differs, for the dns_entry_settings_changed audit entry. It is empty
// when nothing changed.
func DiffDNSEntrySettings(before, after DNSEntrySettings) map[string]interface{} {
	changes := map[string]interface{}{}
	if before.Enabled != after.Enabled {
		changes[dnsEntrySettingsEnabledKey] = []interface{}{before.Enabled, after.Enabled}
	}
	for _, f := range dnsEntrySettingsInts {
		if b, a := *f.field(&before), *f.field(&after); b != a {
			changes[f.key] = []interface{}{b, a}
		}
	}
	return changes
}

// CheckInterval is how often every used name is resolved again.
func (s DNSEntrySettings) CheckInterval() time.Duration {
	return time.Duration(s.CheckIntervalSeconds) * time.Second
}

// MinReloadGap is the least time between two reloads that add addresses.
func (s DNSEntrySettings) MinReloadGap() time.Duration {
	return time.Duration(s.MinReloadGapSeconds) * time.Second
}

// StaleGrace is how long a failing family keeps its last addresses.
func (s DNSEntrySettings) StaleGrace() time.Duration {
	return time.Duration(s.StaleGraceHours) * time.Hour
}
