package service

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/repository"
)

// evtArg captures one INSERT argument.
type evtArg struct{ v *driver.Value }

func (a evtArg) Match(v driver.Value) bool { *a.v = v; return true }

// evtAuditRow is one audit_logs INSERT as the database would have seen it.
type evtAuditRow struct {
	username, action, resourceType, resourceName interface{}
	details                                      map[string]interface{}
}

// Audit rows: action, resource type and name, and the details keys of the
// seven domain entry helpers. resource_name is one name or a fixed word,
// never a list; "name" is only ever logEntry's copy of resource_name.
func TestDNSEntryAuditHelpers(t *testing.T) {
	names := make([]string, 25)
	for i := range names {
		names[i] = fmt.Sprintf("n%02d.example.com", i)
	}
	changes := map[string]interface{}{"check_interval_seconds": []interface{}{60, 120}}
	for _, c := range []struct {
		action, resourceType string
		resourceName         interface{} // nil = NULL
		call                 func(s *AuditService) error
		details              map[string]interface{}
	}{
		{"dns_entry_confirmed", "dns_entry", "partner.example.com",
			func(s *AuditService) error {
				return s.LogDNSEntryConfirmed(context.Background(), "partner.example.com", []string{"198.51.100.10"},
					"edge.example.com", []string{"acl:3f1d2c4b-5a69-4f7e-8d90-1a2b3c4d5e6f"})
			},
			map[string]interface{}{"name": "partner.example.com", "addresses": []interface{}{"198.51.100.10"},
				"canonical_name": "edge.example.com", "scopes": []interface{}{"acl:3f1d2c4b-5a69-4f7e-8d90-1a2b3c4d5e6f"}}},
		{"dns_entry_apply_requested", "dns_entry", nil,
			func(s *AuditService) error { return s.LogDNSEntryApplyRequested(context.Background(), "rejected") },
			map[string]interface{}{"outcome": "rejected"}},
		{"dns_entry_applied", "dns_entry", "partner.example.com",
			func(s *AuditService) error {
				return s.LogDNSEntryApplied(context.Background(), "partner.example.com", nil, []string{"198.51.100.10"}, 7)
			},
			map[string]interface{}{"name": "partner.example.com", "before": nil, "after": []interface{}{"198.51.100.10"},
				"generation": float64(7)}},
		{"dns_entry_applied", "dns_entry", "partner.example.com",
			func(s *AuditService) error {
				return s.LogDNSEntryApplied(context.Background(), "partner.example.com", []string{"198.51.100.10"}, nil, 8)
			},
			map[string]interface{}{"name": "partner.example.com", "before": []interface{}{"198.51.100.10"},
				"after": []interface{}{}, "generation": float64(8)}},
		{"dns_entry_review_needed", "dns_entry", "partner.example.com",
			func(s *AuditService) error {
				return s.LogDNSEntryReviewNeeded(context.Background(), "partner.example.com", "unstable")
			},
			map[string]interface{}{"name": "partner.example.com", "reason": "unstable"}},
		{"dns_entry_revoke_blocked", "dns_entry", "revoke",
			func(s *AuditService) error {
				return s.LogDNSEntryRevokeBlocked(context.Background(), true, "blocked", "proxy_host_1.conf", names)
			},
			map[string]interface{}{"name": "revoke", "blocked": true, "outcome": "blocked", "file": "proxy_host_1.conf",
				"names": evtStrings(names[:20]), "names_total": float64(25)}},
		{"dns_entries_env_disabled", "dns_entry", nil,
			func(s *AuditService) error { return s.LogDNSEntriesEnvDisabled(context.Background()) },
			map[string]interface{}{}},
		{"dns_entry_settings_changed", "settings", "dns_entry_settings",
			func(s *AuditService) error { return s.LogDNSEntrySettingsChanged(context.Background(), changes) },
			map[string]interface{}{"name": "dns_entry_settings",
				"check_interval_seconds": []interface{}{float64(60), float64(120)}}},
	} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		var args [9]driver.Value
		matchers := make([]driver.Value, len(args))
		for i := range args {
			matchers[i] = evtArg{&args[i]}
		}
		mock.ExpectExec(`INSERT INTO audit_logs`).WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(0, 1))

		if err := c.call(NewAuditService(repository.NewAuditLogRepository(db))); err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		row := evtAuditRow{username: args[1], action: args[2], resourceType: args[3], resourceName: args[5]}
		if b, ok := args[6].([]byte); ok {
			if err := json.Unmarshal(b, &row.details); err != nil {
				t.Fatalf("%s: details %q: %v", c.action, b, err)
			}
		}
		if row.username != "system" || row.action != c.action || row.resourceType != c.resourceType || row.resourceName != c.resourceName {
			t.Errorf("%s: row = %v/%v/%v/%v", c.action, row.username, row.action, row.resourceType, row.resourceName)
		}
		if !reflect.DeepEqual(row.details, c.details) {
			t.Errorf("%s: details = %#v\nwant %#v", c.action, row.details, c.details)
		}
		db.Close()
	}
	if _, ok := changes["name"]; ok {
		t.Error("LogDNSEntrySettingsChanged wrote into the caller's map")
	}
}

func evtStrings(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
