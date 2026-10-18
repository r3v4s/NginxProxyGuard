package repository

import (
	"context"
	"database/sql"
	"encoding/json"
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

// backupFileRoundTrip returns export as a restore reads it from a backup
// file: through its JSON, without the keys strip names at any depth (the
// file a version that did not write them would have made).
func backupFileRoundTrip(t *testing.T, export *model.ExportData, strip ...string) *model.ExportData {
	t.Helper()
	b, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	if len(strip) > 0 {
		drop := make(map[string]bool, len(strip))
		for _, key := range strip {
			drop[key] = true
		}
		var doc interface{}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		var walk func(v interface{})
		walk = func(v interface{}) {
			switch v := v.(type) {
			case map[string]interface{}:
				for key, child := range v {
					if drop[key] {
						delete(v, key)
						continue
					}
					walk(child)
				}
			case []interface{}:
				for _, child := range v {
					walk(child)
				}
			}
		}
		walk(doc)
		if b, err = json.Marshal(doc); err != nil {
			t.Fatal(err)
		}
	}
	var out model.ExportData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// backupTestReferences returns every use of a domain name as "scope name".
func backupTestReferences(t *testing.T, db *sql.DB) []string {
	t.Helper()
	refs, err := NewDNSEntryRepository(db).ListReferences(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range refs {
		out = append(out, r.Scope+" "+r.Name)
	}
	return out
}

// A backup of an install with domain names in every exception list carries
// them, and the state records of the names, a name only the global priority
// allow list uses among them. Restored from the backup file into a new
// install (no state rows), every list has its names again, and the name
// that waited for review still does, with its pinned CNAME target and
// nothing published.
func TestBackupExceptionListDomainsRoundTrip(t *testing.T) {
	db := openBackupTestDB(t)
	repo := NewBackupRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hostID := insertTestProxyHost(t, db, "app.example.com")
	fillExceptionLists(t, db, hostID,
		[]string{"uri.example.com"}, []string{"guri.example.com"},
		[]string{"prio.example.com"}, []string{"gprio.example.com"},
		[]string{"rl.example.com"}, []string{"grl.example.com"},
		[]string{"trusted.example.com"})
	mustExec(t, db,
		`INSERT INTO dns_entry_states (hostname, status, review_reason, canonical_name, last_applied)
			VALUES ('gprio.example.com', 'needs_review', 'cname_changed', 'edge.example.com', '{192.0.2.20}')`,
		`INSERT INTO dns_entry_states (hostname, status, canonical_name, published, last_applied, generation, applied_generation)
			VALUES ('trusted.example.com', 'ok', 'trusted.example.com', '{192.0.2.30}', '{192.0.2.30}', 1, 1)`,
	)

	export, err := repo.ExportAllData(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(export.ProxyHosts) != 1 || export.ProxyHosts[0].GeoRestriction == nil || export.ProxyHosts[0].RateLimit == nil ||
		len(export.URIBlocks) != 1 || export.GlobalURIBlock == nil || export.GlobalGeoRestriction == nil ||
		export.GlobalRateLimit == nil || export.SystemSettings == nil {
		t.Fatalf("the export lacks a list: %+v", export)
	}
	var trusted []string
	if export.SystemSettings.GlobalTrustedHostnames != nil {
		trusted = *export.SystemSettings.GlobalTrustedHostnames
	}
	got := map[string][]string{
		"uri_blocks.exception_hostnames":           export.URIBlocks[0].ExceptionHostnames,
		"global_uri_block.exception_hostnames":     export.GlobalURIBlock.ExceptionHostnames,
		"geo_restriction.allowed_hostnames":        export.ProxyHosts[0].GeoRestriction.AllowedHostnames,
		"global_geo_restriction.allowed_hostnames": export.GlobalGeoRestriction.AllowedHostnames,
		"rate_limit.whitelist_hostnames":           export.ProxyHosts[0].RateLimit.WhitelistHostnames,
		"global_rate_limit.whitelist_hostnames":    export.GlobalRateLimit.WhitelistHostnames,
		"system_settings.global_trusted_hostnames": trusted,
	}
	want := map[string][]string{
		"uri_blocks.exception_hostnames":           {"uri.example.com"},
		"global_uri_block.exception_hostnames":     {"guri.example.com"},
		"geo_restriction.allowed_hostnames":        {"prio.example.com"},
		"global_geo_restriction.allowed_hostnames": {"gprio.example.com"},
		"rate_limit.whitelist_hostnames":           {"rl.example.com"},
		"global_rate_limit.whitelist_hostnames":    {"grl.example.com"},
		"system_settings.global_trusted_hostnames": {"trusted.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("exported names:\n got  %q\n want %q", got, want)
	}
	var recorded []string
	for _, rec := range export.DNSEntryStates {
		recorded = append(recorded, rec.Hostname)
	}
	if want := []string{"gprio.example.com", "trusted.example.com"}; !reflect.DeepEqual(recorded, want) {
		t.Errorf("state records of %q, want %q", recorded, want)
	}

	// A new install: the backup file read back, no state rows.
	restored := backupFileRoundTrip(t, export)
	mustExec(t, db, `DELETE FROM dns_entry_states`)
	if _, err := repo.ImportAllData(ctx, restored); err != nil {
		t.Fatalf("import: %v", err)
	}
	var newHostID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM proxy_hosts`).Scan(&newHostID); err != nil {
		t.Fatal(err)
	}
	wantRefs := []string{
		"prio:" + newHostID + " prio.example.com",
		"prio:global gprio.example.com",
		"rl:" + newHostID + " rl.example.com",
		"rl:global grl.example.com",
		"trusted trusted.example.com",
		"uri:" + newHostID + " uri.example.com",
		"uri:global guri.example.com",
	}
	if refs := backupTestReferences(t, db); !reflect.DeepEqual(refs, wantRefs) {
		t.Errorf("restored lists use:\n got  %q\n want %q", refs, wantRefs)
	}
	if st := backupTestStateOf(t, db, "gprio.example.com"); st.Status != model.DNSStatusNeedsReview ||
		st.ReviewReason != model.DNSReviewCNAMEChanged || st.CanonicalName != "edge.example.com" || len(st.Published) != 0 {
		t.Errorf("gprio = %+v, want needs_review (cname_changed) with the backup's pin, nothing published", st)
	}
	if st := backupTestStateOf(t, db, "trusted.example.com"); st.Status != model.DNSStatusPending || len(st.Published) != 0 {
		t.Errorf("trusted = %+v, want pending, nothing published", st)
	}
}

// A backup made before the exception lists held domain names restores every
// list without names, even where this install has some. The trusted names
// are emptied too, not kept: the backup's trusted IPs replace the live
// ones, and keeping today's names next to them would make a set no install
// ever had. The tunables, which such a backup does not carry either, keep
// their live value.
func TestImportOfAnOlderBackupLeavesNoExceptionDomains(t *testing.T) {
	db := openBackupTestDB(t)
	repo := NewBackupRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hostID := insertTestProxyHost(t, db, "app.example.com")
	fillExceptionLists(t, db, hostID,
		[]string{"uri.example.com"}, []string{"guri.example.com"},
		[]string{"prio.example.com"}, []string{"gprio.example.com"},
		[]string{"rl.example.com"}, []string{"grl.example.com"},
		[]string{"trusted.example.com"})
	mustExec(t, db, `UPDATE system_settings SET global_trusted_ips = '192.0.2.40'`)
	export, err := repo.ExportAllData(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	older := backupFileRoundTrip(t, export, "exception_hostnames", "allowed_hostnames", "whitelist_hostnames",
		"global_trusted_hostnames", "dns_entry_settings", "dns_entry_states")

	// This install, later: other trusted IPs and tunables, the same names.
	const live = `{"enabled": false, "check_interval_seconds": 120}`
	mustExec(t, db, `UPDATE system_settings SET global_trusted_ips = '192.0.2.41', dns_entry_settings = '`+live+`'`)
	if len(backupTestReferences(t, db)) != 7 {
		t.Fatalf("the install should use a name in each of the seven lists: %q", backupTestReferences(t, db))
	}
	if _, err := repo.ImportAllData(ctx, older); err != nil {
		t.Fatalf("import: %v", err)
	}

	if refs := backupTestReferences(t, db); len(refs) != 0 {
		t.Errorf("after the older backup the lists use %q, want no names", refs)
	}
	var trustedIPs string
	var tunables []byte
	if err := db.QueryRowContext(ctx, `SELECT global_trusted_ips, dns_entry_settings FROM system_settings`).Scan(&trustedIPs, &tunables); err != nil {
		t.Fatal(err)
	}
	if trustedIPs != "192.0.2.40" {
		t.Errorf("global_trusted_ips = %q, want the backup's 192.0.2.40", trustedIPs)
	}
	if got, want := model.ParseDNSEntrySettings(tunables), model.ParseDNSEntrySettings([]byte(live)); got != want {
		t.Errorf("tunables = %+v, want the live %+v", got, want)
	}
}

// The restore audit names every domain name the lists use, an access list
// or any exception list, the global trusted IPs too, each once, and those of
// them waiting for review.
func TestRestoredDNSEntriesCoversEveryList(t *testing.T) {
	db := openBackupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	hostID := insertTestProxyHost(t, db, "app.example.com")
	var listID string
	if err := db.QueryRowContext(ctx, `INSERT INTO access_lists (name) VALUES ('partners') RETURNING id`).Scan(&listID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO access_list_items (access_list_id, directive, address, hostname) VALUES ('`+listID+`', 'deny', 'all', 'acl.example.com')`)
	fillExceptionLists(t, db, hostID,
		[]string{"uri.example.com"}, []string{"guri.example.com"},
		[]string{"prio.example.com", "both.example.com"}, []string{"gprio.example.com"},
		[]string{"rl.example.com"}, []string{"grl.example.com"},
		[]string{"trusted.example.com", "both.example.com"})
	mustExec(t, db,
		`INSERT INTO dns_entry_states (hostname, status, review_reason) VALUES ('trusted.example.com', 'needs_review', 'reappeared')`,
		`INSERT INTO dns_entry_states (hostname, status) VALUES ('uri.example.com', 'ok')`,
	)

	got, err := NewBackupRepository(db).RestoredDNSEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := model.DNSRestoreSummary{
		Names: []string{"acl.example.com", "both.example.com", "gprio.example.com", "grl.example.com", "guri.example.com",
			"prio.example.com", "rl.example.com", "trusted.example.com", "uri.example.com"},
		NeedsReview: []string{"trusted.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("summary = %+v\nwant      %+v", got, want)
	}
}
