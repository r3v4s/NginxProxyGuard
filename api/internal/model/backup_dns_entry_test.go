package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// A backup carries domain rows and the per-name state under these keys, and
// the import reads the same keys back. A typo here would drop every name on
// restore without an error.
func TestBackupCarriesDomainEntries(t *testing.T) {
	in := ExportData{
		AccessLists: []AccessListExport{{AccessList: AccessListData{Name: "partners", Items: []AccessListItemData{
			{Directive: "allow", Address: "192.0.2.10", SortOrder: 0},
			{Directive: "deny", Address: "all", SortOrder: 1, Hostname: "partner.example.com"},
		}}}},
		SystemSettings: &SystemSettingsExport{DNSEntrySettings: json.RawMessage(`{"enabled":false}`)},
		DNSEntryStates: []DNSEntryStateExport{{
			Hostname: "partner.example.com", NeedsReview: true, ReviewReason: "cname_changed",
			CanonicalName: "edge.example.com", LastApplied: []string{"100.64.32.10"},
		}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"hostname":"partner.example.com"`, `"dns_entry_states":[`, `"needs_review":true`,
		`"review_reason":"cname_changed"`, `"canonical_name":"edge.example.com"`,
		`"last_applied":["100.64.32.10"]`, `"dns_entry_settings":{"enabled":false}`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("export JSON lacks %s: %s", want, b)
		}
	}
	var out ExportData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.AccessLists, in.AccessLists) || !reflect.DeepEqual(out.DNSEntryStates, in.DNSEntryStates) ||
		string(out.SystemSettings.DNSEntrySettings) != `{"enabled":false}` {
		t.Fatalf("the round trip changed the domain entries: %s", b)
	}

	// A row without a name keeps the old shape.
	plain, _ := json.Marshal(AccessListItemData{Directive: "deny", Address: "all"})
	if strings.Contains(string(plain), "hostname") {
		t.Errorf("a plain row gained a hostname key: %s", plain)
	}

	// The restore summary feeds the audit only, never the API response.
	r := NewRestoreResult()
	r.DNSEntries = DNSRestoreSummary{Names: []string{"partner.example.com"}, NeedsReview: []string{"partner.example.com"}}
	rb, _ := json.Marshal(r)
	if strings.Contains(string(rb), "partner.example.com") {
		t.Errorf("the restore response carries the DNS summary: %s", rb)
	}
}
