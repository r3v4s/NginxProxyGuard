package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// openSystemSettingsDB returns a database of its own on the server
// NPG_TEST_DATABASE_URL names, holding the system_settings and audit_logs
// tables as a fresh install creates them (001_init.sql). Skipped without the
// variable, as in CI.
func openSystemSettingsDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed system settings test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_ss_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		admin.Close()
		t.Fatalf("create database %s: %v", name, err)
	}
	db, err := sql.Open("postgres", accessListTestDSN(dsn, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Logf("drop database %s: %v", name, err)
		}
		admin.Close()
	})
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"system_settings", "audit_logs"} {
		ddl := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS public\.` + table + ` \(.*?\n\);`).FindString(string(b))
		if ddl == "" {
			t.Fatalf("001_init.sql has no CREATE TABLE for %s", table)
		}
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("create %s: %v", table, err)
		}
	}
	return db
}

// auditDetailsOf returns the details of every audit entry with action.
func auditDetailsOf(t *testing.T, db *sql.DB, action string) []map[string]interface{} {
	t.Helper()
	rows, err := db.Query(`SELECT details FROM audit_logs WHERE action = $1`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var details map[string]interface{}
		if err := json.Unmarshal(raw, &details); err != nil {
			t.Fatal(err)
		}
		out = append(out, details)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The tunables through the real handler, repository and column: a
// partial object is merged over the stored value and saved
// whole, a refused one changes nothing, a change is audited as
// [before, after] and handed to the DNS entry service once, a value edited
// by hand out of range reads clamped and blocks nothing, and a switch of the
// WAF bypass is audited as [before, after].
func TestSystemSettingsDNSEntrySettingsAgainstTheDatabase(t *testing.T) {
	db := openSystemSettingsDB(t)
	svc := &fakeSettingsChanger{}
	h := &SystemSettingsHandler{
		repo:       repository.NewSystemSettingsRepository(db),
		audit:      service.NewAuditService(repository.NewAuditLogRepository(db)),
		dnsEntries: svc,
	}
	admin := permGrants{"settings:read": true, "settings:write": true}
	get := func() *httptest.ResponseRecorder {
		return callWithGrants(t, h.GetSystemSettings, admin, http.MethodGet, "")
	}
	put := func(body string) *httptest.ResponseRecorder {
		return callWithGrants(t, h.UpdateSystemSettings, admin, http.MethodPut, body)
	}
	shown := func(rec *httptest.ResponseRecorder) model.DNSEntrySettings {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d; body %s", rec.Code, rec.Body)
		}
		var resp struct {
			DNSEntrySettings model.DNSEntrySettings `json:"dns_entry_settings"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.DNSEntrySettings
	}
	stored := func() map[string]interface{} {
		t.Helper()
		var raw string
		if err := db.QueryRow(`SELECT dns_entry_settings::text FROM system_settings`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var row map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}

	// A new install: the column default '{}' reads as the defaults.
	defaults := model.DefaultDNSEntrySettings()
	if got := shown(get()); got != defaults {
		t.Fatalf("a new install shows %+v, want the defaults %+v", got, defaults)
	}

	// Two partial saves; the second sends only the interval and keeps the
	// feature off.
	off := defaults
	off.Enabled = false
	offAt90 := off
	offAt90.CheckIntervalSeconds = 90
	if got := shown(put(`{"dns_entry_settings":{"enabled":false}}`)); got != off {
		t.Fatalf("after switching off: %+v, want %+v", got, off)
	}
	if got := shown(put(`{"dns_entry_settings":{"check_interval_seconds":90}}`)); got != offAt90 {
		t.Fatalf("after setting the interval: %+v, want %+v", got, offAt90)
	}
	if row := stored(); len(row) != 9 || row["enabled"] != false || row["check_interval_seconds"] != float64(90) {
		t.Fatalf("the row holds %v, want all nine keys with enabled false and the interval 90", row)
	}
	if want := [][2]model.DNSEntrySettings{{defaults, off}, {off, offAt90}}; !reflect.DeepEqual(svc.calls, want) {
		t.Fatalf("the DNS entry service got %+v, want %+v", svc.calls, want)
	}
	changed := auditDetailsOf(t, db, "dns_entry_settings_changed")
	for _, want := range []map[string]interface{}{
		{"enabled": []interface{}{true, false}, "name": "dns_entry_settings"},
		{"check_interval_seconds": []interface{}{float64(60), float64(90)}, "name": "dns_entry_settings"},
	} {
		found := false
		for _, got := range changed {
			found = found || reflect.DeepEqual(got, want)
		}
		if !found {
			t.Errorf("no dns_entry_settings_changed entry %v among %v", want, changed)
		}
	}
	if len(changed) != 2 {
		t.Fatalf("%d dns_entry_settings_changed entries, want 2: %v", len(changed), changed)
	}

	// The same value again changes nothing: no entry, no call.
	if rec := put(`{"dns_entry_settings":{"check_interval_seconds":90}}`); rec.Code != http.StatusOK {
		t.Fatalf("saving the same value: status %d; body %s", rec.Code, rec.Body)
	}
	if n := len(auditDetailsOf(t, db, "dns_entry_settings_changed")); n != 2 || len(svc.calls) != 2 {
		t.Fatalf("saving the same value: %d entries, %d service calls; want 2 and 2", n, len(svc.calls))
	}

	// Refused objects: 400 naming the key; nothing stored or handed on.
	for body, want := range map[string]string{
		`{"dns_entry_settings":{"check_interval":30}}`: `dns_entry_settings: unknown key "check_interval"`,
		`{"dns_entry_settings":{"max_total":999}}`:     "dns_entry_settings.max_total must be between 1 and 256 (got 999)",
	} {
		rec := put(body)
		var resp map[string]string
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp["error"] != want {
			t.Errorf("%s: status %d; body %s; want 400 %q", body, rec.Code, rec.Body, want)
		}
	}
	if row := stored(); row["max_total"] != float64(64) || row["check_interval_seconds"] != float64(90) || len(svc.calls) != 2 {
		t.Fatalf("after refused saves the row holds %v and the service got %d calls", row, len(svc.calls))
	}

	// A value edited by hand out of range reads clamped and does not block a
	// save that leaves it alone.
	if _, err := db.Exec(`UPDATE system_settings SET dns_entry_settings = '{"enabled": false, "max_total": 999}'`); err != nil {
		t.Fatal(err)
	}
	clamped := off
	clamped.MaxTotal = 256
	if got := shown(get()); got != clamped {
		t.Fatalf("a hand-edited row shows %+v, want %+v", got, clamped)
	}
	shorter := clamped
	shorter.MaxPerList = 8
	if got := shown(put(`{"dns_entry_settings":{"max_per_list":8}}`)); got != shorter {
		t.Fatalf("a save over a hand-edited row: %+v, want %+v", got, shorter)
	}

	// The WAF bypass: a switch is audited as [before, after] once; the
	// stored value sent back adds nothing.
	for i := 0; i < 2; i++ {
		if rec := put(`{"global_trusted_ips_bypass_waf":true}`); rec.Code != http.StatusOK {
			t.Fatalf("bypass save %d: status %d; body %s", i+1, rec.Code, rec.Body)
		}
	}
	switches := 0
	for _, details := range auditDetailsOf(t, db, "settings_updated") {
		if v, ok := details["global_trusted_ips_bypass_waf"]; ok {
			switches++
			if !reflect.DeepEqual(v, []interface{}{false, true}) {
				t.Errorf("settings_updated records the bypass as %v, want [false true]", v)
			}
		}
	}
	if switches != 1 {
		t.Errorf("%d settings_updated entries name the bypass, want 1", switches)
	}
}
