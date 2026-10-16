package repository

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// openBackupTestDB returns a database of its own on the server
// NPG_TEST_DATABASE_URL names, holding the schema of a fresh install:
// 001_init.sql run in one Exec, as RunMigrations does. The server needs the
// timescaledb extension (the timescale/timescaledb image). Skipped without
// the variable, as in CI.
func openBackupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed backup test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_backup_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		admin.Close()
		t.Fatalf("create database %s: %v", name, err)
	}
	db, err := sql.Open("postgres", backupTestDSN(dsn, name))
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
	schema, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("001_init.sql: %v", err)
	}
	return db
}

// backupTestDSN is dsn naming the database name instead.
func backupTestDSN(dsn, name string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		u.Path = "/" + name
		return u.String()
	}
	return dsn + " dbname=" + name // key=value form: the last dbname wins
}

// backupTestRules returns every access list rule as
// "directive|address|hostname|sort_order", in order.
func backupTestRules(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT directive, address, COALESCE(hostname, ''), sort_order FROM access_list_items ORDER BY sort_order`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var directive, address, hostname string
		var sortOrder int
		if err := rows.Scan(&directive, &address, &hostname, &sortOrder); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%d", directive, address, hostname, sortOrder))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// backupTestState is the part of a dns_entry_states row a restore decides.
type backupTestState struct {
	Status, ReviewReason, CanonicalName string
	Published                           []string
	Generation                          int64
	RevokePending                       bool
}

func backupTestStateOf(t *testing.T, db *sql.DB, name string) backupTestState {
	t.Helper()
	var st backupTestState
	var published pq.StringArray
	err := db.QueryRow(`SELECT status, COALESCE(review_reason, ''), COALESCE(canonical_name, ''), published, generation,
		revoke_pending_since IS NOT NULL FROM dns_entry_states WHERE hostname = $1`, name).
		Scan(&st.Status, &st.ReviewReason, &st.CanonicalName, &published, &st.Generation, &st.RevokePending)
	if err != nil {
		t.Fatalf("state of %s: %v", name, err)
	}
	st.Published = []string(published)
	return st
}

// A full backup and restore of an install with domain entries: the rows
// travel as stored and come back after the address rules, the CHECK takes
// them, a name in review stays closed on a new install and over a live row
// that is published, and the tunables come back as the API reads them.
func TestBackupDomainEntriesAgainstTheDatabase(t *testing.T) {
	db := openBackupTestDB(t)
	repo := NewBackupRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var listID string
	if err := db.QueryRowContext(ctx, `INSERT INTO access_lists (name) VALUES ('partners') RETURNING id`).Scan(&listID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO access_list_items (access_list_id, directive, address, sort_order, hostname) VALUES
		($1, 'allow', '192.0.2.10', 0, NULL), ($1, 'deny', 'all', 1, 'partner.example.com'), ($1, 'deny', 'all', 2, 'office.example.com')`,
		listID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db,
		`INSERT INTO dns_entry_states (hostname, status, review_reason, canonical_name, last_applied)
			VALUES ('partner.example.com', 'needs_review', 'cname_changed', 'edge.example.com', '{192.0.2.20}')`,
		`INSERT INTO dns_entry_states (hostname, status, canonical_name, published, last_applied, generation, applied_generation)
			VALUES ('office.example.com', 'ok', 'office.example.com', '{192.0.2.30}', '{192.0.2.30}', 3, 3)`,
		`INSERT INTO system_settings DEFAULT VALUES`,
		`UPDATE system_settings SET dns_entry_settings = '{"enabled": false, "max_total": 999}'`,
	)

	export, err := repo.ExportAllData(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	wantItems := []model.AccessListItemData{
		{Directive: "allow", Address: "192.0.2.10", SortOrder: 0},
		{Directive: "deny", Address: "all", SortOrder: 1, Hostname: "partner.example.com"},
		{Directive: "deny", Address: "all", SortOrder: 2, Hostname: "office.example.com"},
	}
	if len(export.AccessLists) != 1 || !reflect.DeepEqual(export.AccessLists[0].AccessList.Items, wantItems) {
		t.Fatalf("exported lists = %+v, want one list with rules %+v", export.AccessLists, wantItems)
	}
	wantRecords := []model.DNSEntryStateExport{
		{Hostname: "office.example.com", CanonicalName: "office.example.com", LastApplied: []string{"192.0.2.30"}},
		{Hostname: "partner.example.com", NeedsReview: true, ReviewReason: "cname_changed",
			CanonicalName: "edge.example.com", LastApplied: []string{"192.0.2.20"}},
	}
	if !reflect.DeepEqual(export.DNSEntryStates, wantRecords) {
		t.Fatalf("exported records = %+v\nwant                %+v", export.DNSEntryStates, wantRecords)
	}
	wantSettings := model.DefaultDNSEntrySettings()
	wantSettings.Enabled, wantSettings.MaxTotal = false, 256
	if export.SystemSettings == nil || model.ParseDNSEntrySettings(export.SystemSettings.DNSEntrySettings) != wantSettings {
		t.Fatalf("exported system settings = %+v, want tunables %+v", export.SystemSettings, wantSettings)
	}

	restoredSettings := func() model.DNSEntrySettings {
		t.Helper()
		var raw []byte
		if err := db.QueryRowContext(ctx, `SELECT dns_entry_settings FROM system_settings`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return model.ParseDNSEntrySettings(raw)
	}
	wantRules := []string{"allow|192.0.2.10||0", "deny|all|partner.example.com|1", "deny|all|office.example.com|2"}

	// The same install, later: office is published here, and this copy of
	// the backup says it waits for review.
	export.DNSEntryStates[0].NeedsReview, export.DNSEntryStates[0].ReviewReason = true, model.DNSReviewUnstable
	mustExec(t, db, `UPDATE system_settings SET dns_entry_settings = '{}'`)
	if _, err := repo.ImportAllData(ctx, export); err != nil {
		t.Fatalf("import over the live install: %v", err)
	}
	if got := backupTestRules(t, db); !reflect.DeepEqual(got, wantRules) {
		t.Errorf("restored rules = %q, want %q", got, wantRules)
	}
	office := backupTestStateOf(t, db, "office.example.com")
	if office.Status != model.DNSStatusNeedsReview || office.ReviewReason != model.DNSReviewUnstable ||
		len(office.Published) != 0 || office.Generation != 4 || !office.RevokePending {
		t.Errorf("office = %+v, want needs_review (unstable), nothing published, generation 4, a revoke pending", office)
	}
	if partner := backupTestStateOf(t, db, "partner.example.com"); partner.Status != model.DNSStatusNeedsReview ||
		partner.CanonicalName != "edge.example.com" || len(partner.Published) != 0 {
		t.Errorf("partner = %+v, want it still in review with its pin", partner)
	}
	if got := restoredSettings(); got != wantSettings {
		t.Errorf("restored tunables = %+v, want %+v", got, wantSettings)
	}
	summary, err := repo.RestoredDNSEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (model.DNSRestoreSummary{Names: []string{"office.example.com", "partner.example.com"},
		NeedsReview: []string{"office.example.com", "partner.example.com"}}); !reflect.DeepEqual(summary, want) {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}

	// A new install: no state rows. A backup made before the tunables
	// existed keeps the live value.
	mustExec(t, db, `DELETE FROM dns_entry_states`)
	export.DNSEntryStates[0].NeedsReview, export.DNSEntryStates[0].ReviewReason = false, ""
	export.SystemSettings.DNSEntrySettings = nil
	if _, err := repo.ImportAllData(ctx, export); err != nil {
		t.Fatalf("import into a new install: %v", err)
	}
	if partner := backupTestStateOf(t, db, "partner.example.com"); partner.Status != model.DNSStatusNeedsReview ||
		partner.ReviewReason != model.DNSReviewCNAMEChanged || partner.CanonicalName != "edge.example.com" || len(partner.Published) != 0 {
		t.Errorf("partner = %+v, want needs_review (cname_changed) with the backup's pin, nothing published", partner)
	}
	if office := backupTestStateOf(t, db, "office.example.com"); office.Status != model.DNSStatusPending || len(office.Published) != 0 {
		t.Errorf("office = %+v, want pending, nothing published", office)
	}
	if got := restoredSettings(); got != wantSettings {
		t.Errorf("an older backup changed the tunables to %+v, want them kept as %+v", got, wantSettings)
	}
}
