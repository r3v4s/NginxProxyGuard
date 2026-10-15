package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// Domain entries in access lists (#320) add schema objects that
// TestMigrationStructuralSync does not compare (it compares ADD COLUMN only):
// the CHECK and the partial index on access_list_items.hostname, written in
// the CREATE TABLE and the index block of 001_init.sql and again in
// `upgrades`, and the dns_entry_states table, written at the executable end
// of 001_init.sql and again in `upgrades`. Nothing repairs a copy that
// drifts: CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS and the
// guarded ADD CONSTRAINT leave an existing object as it is, so fresh and
// upgraded installs would enforce different rules. The first two tests hold
// the copies equal; TestDNSEntrySchemaAgainstTheDatabase runs both paths on
// PostgreSQL.

// normalizeSQL collapses every run of white space to one space.
func normalizeSQL(s string) string { return strings.Join(strings.Fields(s), " ") }

// upgradeEntriesContaining returns the `upgrades` entries whose SQL holds needle.
func upgradeEntriesContaining(t *testing.T, needle string) []string {
	t.Helper()
	var found []string
	for _, s := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(s, needle) {
			found = append(found, s)
		}
	}
	return found
}

// initSQLSections returns 001_init.sql split at the UPGRADE SECTION banner.
func initSQLSections(t *testing.T) (beforeBanner, upgradeSection string) {
	t.Helper()
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	banner := regexp.MustCompile(`(?m)^--\s*UPGRADE SECTION`).FindStringIndex(initSQL)
	if banner == nil {
		t.Fatal("001_init.sql has no UPGRADE SECTION banner")
	}
	return initSQL[:banner[0]], initSQL[banner[1]:]
}

func TestDNSEntryStatesTableIsCreatedIdenticallyOnBothPaths(t *testing.T) {
	_, upgradeSection := initSQLSections(t)
	entries := upgradeEntriesContaining(t, "dns_entry_states")
	if len(entries) != 1 {
		t.Fatalf("%d upgrades entries name dns_entry_states, want exactly 1 (the CREATE TABLE)", len(entries))
	}
	fresh := createTableStatement(upgradeSection, "dns_entry_states")
	existing := createTableStatement(entries[0], "dns_entry_states")
	if fresh == "" {
		t.Fatal("no executable CREATE TABLE IF NOT EXISTS public.dns_entry_states in the 001_init.sql UPGRADE SECTION: fresh installs would not get it")
	}
	if existing == "" {
		t.Fatal("the upgrades entry naming dns_entry_states does not create it: existing installs would not get it")
	}
	if fresh != existing {
		t.Errorf("dns_entry_states differs between the two paths:\n001_init.sql: %s\nupgrades:     %s", fresh, existing)
	}
	// One row per name, shared by every list that uses it: a foreign key has
	// nothing to point at, and would make the order of the fresh-install
	// file matter.
	if strings.Contains(strings.ToUpper(fresh), "REFERENCES") {
		t.Error("dns_entry_states declares a foreign key")
	}
	for _, want := range []string{
		// lib/pq cannot scan timestamptz[] into []time.Time, so the
		// repository stores Unix seconds.
		"change_times bigint[] DEFAULT '{}'::bigint[] NOT NULL",
		// A replacement counts once across ticks and restarts.
		"replace_open boolean DEFAULT false NOT NULL",
		"CONSTRAINT dns_entry_states_pkey PRIMARY KEY (hostname)",
	} {
		if !strings.Contains(fresh, want) {
			t.Errorf("dns_entry_states lost %q", want)
		}
	}
}

func TestAccessListHostnameCheckAndIndexMatchOnBothPaths(t *testing.T) {
	beforeBanner, _ := initSQLSections(t)
	const checkAnchor = "CONSTRAINT access_list_items_hostname_check CHECK ("

	// The CHECK: the CREATE TABLE of fresh installs against the upgrades
	// entry of existing installs.
	table := createTableStatement(beforeBanner, "access_list_items")
	if table == "" {
		t.Fatal("no CREATE TABLE IF NOT EXISTS public.access_list_items before the UPGRADE SECTION")
	}
	fresh := balancedBody(t, table, checkAnchor)
	entries := upgradeEntriesContaining(t, "access_list_items_hostname_check")
	if len(entries) != 1 {
		t.Fatalf("%d upgrades entries name access_list_items_hostname_check, want exactly 1", len(entries))
	}
	entry := normalizeSQL(stripLineComments(entries[0]))
	if existing := balancedBody(t, entry, checkAnchor); existing != fresh {
		t.Errorf("access_list_items_hostname_check differs between the two paths:\n001_init.sql: %s\nupgrades:     %s", fresh, existing)
	}
	// The same entry adds the column first, so the column never exists
	// without its CHECK.
	addColumn := strings.Index(entry, "ALTER TABLE public.access_list_items ADD COLUMN IF NOT EXISTS hostname character varying(253);")
	addCheck := strings.Index(entry, "ADD "+checkAnchor)
	if addColumn < 0 || addCheck < 0 || addColumn > addCheck {
		t.Errorf("the upgrades entry must add access_list_items.hostname and then its CHECK:\n%s", entry)
	}
	// A fresh install already has the CHECK from its CREATE TABLE, and ADD
	// CONSTRAINT has no IF NOT EXISTS: unguarded, it would fail on every boot.
	if !strings.Contains(entry, "IF NOT EXISTS ( SELECT 1 FROM pg_constraint WHERE conname = 'access_list_items_hostname_check'") {
		t.Errorf("the upgrades entry does not add the CHECK only while it is missing:\n%s", entry)
	}

	// The partial index: the index block of fresh installs against its
	// upgrades entry, which must run after the column's entry.
	indexRE := regexp.MustCompile(`(?i)CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+idx_access_list_items_hostname\s[^;]*`)
	freshIndexes := indexRE.FindAllString(stripLineComments(beforeBanner), -1)
	if len(freshIndexes) != 1 {
		t.Fatalf("001_init.sql creates idx_access_list_items_hostname %d times before the UPGRADE SECTION, want 1", len(freshIndexes))
	}
	indexEntries := upgradeEntriesContaining(t, "idx_access_list_items_hostname")
	if len(indexEntries) != 1 {
		t.Fatalf("%d upgrades entries name idx_access_list_items_hostname, want exactly 1", len(indexEntries))
	}
	freshIndex, existingIndex := normalizeSQL(freshIndexes[0]), normalizeSQL(indexRE.FindString(indexEntries[0]))
	if freshIndex != existingIndex {
		t.Errorf("idx_access_list_items_hostname differs between the two paths:\n001_init.sql: %s\nupgrades:     %s", freshIndex, existingIndex)
	}
	columnAt, indexAt := -1, -1
	for i, s := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(s, "access_list_items_hostname_check") {
			columnAt = i
		}
		if strings.Contains(s, "idx_access_list_items_hostname") {
			indexAt = i
		}
	}
	if indexAt < columnAt {
		t.Errorf("the index entry (%d) runs before the column's entry (%d): every existing install would log a failed upgrade on its first boot", indexAt, columnAt)
	}
}

// migrationTestDSN returns NPG_TEST_DATABASE_URL for a test that migrates the
// database it names in place. Skipped without the variable (as in CI) and
// for a database whose name does not start with npg_test_: RunMigrations
// changes the schema it runs on, so a real install must never be the target.
func migrationTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed migration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatalf("read the test database's name: %v", err)
	}
	if !strings.HasPrefix(name, "npg_test_") {
		t.Skipf("database %q does not start with npg_test_; this test migrates the database it is given, so it runs only on a throwaway one", name)
	}
	return dsn
}

// bootMigrations does to the schema what an API start does: RunMigrations,
// then the failed-upgrade count the detailed health endpoint reports, which
// must be zero. It waits for the log table conversions RunMigrations starts
// in the background, so the next boot does not race them.
func bootMigrations(t *testing.T, dsn string) *DB {
	t.Helper()
	db, err := New(dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.RunMigrations(); err != nil {
		db.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	if n, last := db.MigrationHealth(); n != 0 {
		db.Close()
		t.Fatalf("RunMigrations recorded %d failed upgrade(s); last: %s", n, last)
	}
	done := make(chan struct{})
	go func() { db.bgWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		t.Fatal("the background log table migrations did not finish within 3 minutes")
	}
	return db
}

// dnsSchemaObjects says which #320 objects a database has, and whether
// RunMigrations takes the upgrade path there (001_init recorded).
type dnsSchemaObjects struct {
	Initialized, HostnameColumn, DNSEntryStates, DNSEntrySettings bool
}

func readDNSSchemaObjects(t *testing.T, db *sql.DB) dnsSchemaObjects {
	t.Helper()
	var o dnsSchemaObjects
	var tracked bool
	if err := db.QueryRow(`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&tracked); err != nil {
		t.Fatalf("look for schema_migrations: %v", err)
	}
	if tracked {
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '001_init')`).Scan(&o.Initialized); err != nil {
			t.Fatalf("read schema_migrations: %v", err)
		}
	}
	err := db.QueryRow(`SELECT
		EXISTS (SELECT 1 FROM information_schema.columns
		         WHERE table_schema = 'public' AND table_name = 'access_list_items' AND column_name = 'hostname'),
		to_regclass('public.dns_entry_states') IS NOT NULL,
		EXISTS (SELECT 1 FROM information_schema.columns
		         WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'dns_entry_settings')`).
		Scan(&o.HostnameColumn, &o.DNSEntryStates, &o.DNSEntrySettings)
	if err != nil {
		t.Fatalf("look for the #320 objects: %v", err)
	}
	return o
}

// columnDefinitions returns "<name> <type>[ NOT NULL]" for every column of
// the schema-qualified table, in column order.
func columnDefinitions(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT attname, format_type(atttypid, atttypmod), attnotnull
		FROM pg_attribute
		WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
		ORDER BY attnum`, table)
	if err != nil {
		t.Fatalf("read the columns of %s: %v", table, err)
	}
	defer rows.Close()
	var defs []string
	for rows.Next() {
		var name, typ string
		var notNull bool
		if err := rows.Scan(&name, &typ, &notNull); err != nil {
			t.Fatal(err)
		}
		def := name + " " + typ
		if notNull {
			def += " NOT NULL"
		}
		defs = append(defs, def)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return defs
}

// execInSavepoint runs one statement in tx behind a savepoint, so a statement
// PostgreSQL refuses does not abort the rest of the transaction.
func execInSavepoint(tx *sql.Tx, query string, args ...interface{}) error {
	if _, err := tx.Exec(`SAVEPOINT npg_test_case`); err != nil {
		return err
	}
	if _, err := tx.Exec(query, args...); err != nil {
		if _, rbErr := tx.Exec(`ROLLBACK TO SAVEPOINT npg_test_case`); rbErr != nil {
			return fmt.Errorf("%w (rolling back to the savepoint failed too: %v)", err, rbErr)
		}
		return err
	}
	_, err := tx.Exec(`RELEASE SAVEPOINT npg_test_case`)
	return err
}

// expectConstraint fails the test unless err is PostgreSQL refusing the row
// for the named constraint; with want == "" the row must have been taken.
func expectConstraint(t *testing.T, desc string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("%s: refused: %v", desc, err)
		}
		return
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Constraint != want {
		t.Errorf("%s: err = %v, want a refusal by %s", desc, err, want)
	}
}

// Both migration paths on PostgreSQL. The test migrates the database
// NPG_TEST_DATABASE_URL names in place: an empty database takes the fresh
// install path (001_init.sql, then every upgrade), one holding an older
// version's schema with 001_init recorded takes the upgrade path. A second
// boot then runs every upgrade again. Neither boot may record a failed
// upgrade, and both paths must end with the same columns, CHECKs, index and
// key. The rows the test inserts are rolled back.
func TestDNSEntrySchemaAgainstTheDatabase(t *testing.T) {
	dsn := migrationTestDSN(t)

	probe, err := New(dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	before := readDNSSchemaObjects(t, probe.DB)
	probe.Close()
	path := "fresh install"
	if before.Initialized {
		path = "upgrade"
	}
	t.Logf("%s; before: access_list_items.hostname=%v dns_entry_states=%v system_settings.dns_entry_settings=%v",
		path, before.HostnameColumn, before.DNSEntryStates, before.DNSEntrySettings)

	bootMigrations(t, dsn).Close()
	db := bootMigrations(t, dsn) // the next start runs every upgrade again
	t.Cleanup(func() { db.Close() })

	if after := readDNSSchemaObjects(t, db.DB); after != (dnsSchemaObjects{true, true, true, true}) {
		t.Fatalf("after the migrations: %+v, want every object", after)
	}
	for table, want := range map[string]string{
		"public.access_list_items": "hostname character varying(253)",
		"public.system_settings":   "dns_entry_settings jsonb NOT NULL",
	} {
		column := strings.Fields(want)[0]
		got := ""
		for _, def := range columnDefinitions(t, db.DB, table) {
			if strings.HasPrefix(def, column+" ") {
				got = def
			}
		}
		if got != want {
			t.Errorf("%s.%s is %q, want %q", table, column, got, want)
		}
	}
	wantStates := []string{
		"hostname character varying(253) NOT NULL",
		"status character varying(20) NOT NULL",
		"review_reason character varying(20)",
		"disabled boolean NOT NULL",
		"unused_since timestamp with time zone",
		"published text[] NOT NULL",
		"last_applied text[] NOT NULL",
		"empty_cause character varying(12)",
		"generation bigint NOT NULL",
		"applied_generation bigint NOT NULL",
		"revoke_pending_since timestamp with time zone",
		"candidate text[]",
		"candidate_seen smallint NOT NULL",
		"replace_open boolean NOT NULL",
		"v4_state character varying(16)",
		"v6_state character varying(16)",
		"v4_code character varying(32)",
		"v6_code character varying(32)",
		"v4_observed text[]",
		"v6_observed text[]",
		"v4_answer_at timestamp with time zone",
		"v6_answer_at timestamp with time zone",
		"v4_notfound smallint NOT NULL",
		"v6_notfound smallint NOT NULL",
		"canonical_name character varying(253)",
		"canonical_seen character varying(253)",
		"warnings text[] NOT NULL",
		"change_times bigint[] NOT NULL",
		"last_checked_at timestamp with time zone",
		"last_changed_at timestamp with time zone",
		"created_at timestamp with time zone NOT NULL",
		"updated_at timestamp with time zone NOT NULL",
	}
	if got := columnDefinitions(t, db.DB, "public.dns_entry_states"); !reflect.DeepEqual(got, wantStates) {
		t.Errorf("dns_entry_states columns:\n got  %q\n want %q", got, wantStates)
	}
	var indexDef string
	if err := db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_access_list_items_hostname'`).Scan(&indexDef); err != nil {
		t.Errorf("idx_access_list_items_hostname: %v", err)
	} else if !strings.HasSuffix(indexDef, "ON public.access_list_items USING btree (hostname) WHERE (hostname IS NOT NULL)") {
		t.Errorf("idx_access_list_items_hostname = %q, want a btree on hostname WHERE (hostname IS NOT NULL)", indexDef)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// access_list_items: a name only ever sits on a (deny, all) placeholder
	// row, in the characters of a normalized name. Rows without a name,
	// older rows with a name in the address among them, are left alone.
	var listID string
	if err := tx.QueryRow(`INSERT INTO access_lists (name) VALUES ('npg-test-dns-schema') RETURNING id`).Scan(&listID); err != nil {
		t.Fatal(err)
	}
	name := func(s string) *string { return &s }
	for _, c := range []struct {
		desc               string
		directive, address string
		hostname           *string
		refusedBy          string
	}{
		{"a domain placeholder row", "deny", "all", name("partner.example.com"), ""},
		{"an address row", "allow", "192.0.2.10", nil, ""},
		{"an older row with a name in the address", "allow", "partner.example.com", nil, ""},
		{"a name on an allow row", "allow", "all", name("partner.example.com"), "access_list_items_hostname_check"},
		{"a name on a row with an address", "deny", "192.0.2.1", name("partner.example.com"), "access_list_items_hostname_check"},
		{"a name in upper case", "deny", "all", name("Partner.Example.com"), "access_list_items_hostname_check"},
		{"a name with an underscore", "deny", "all", name("partner_one.example.com"), "access_list_items_hostname_check"},
		{"a name with a semicolon", "deny", "all", name("partner.example.com;"), "access_list_items_hostname_check"},
		{"an empty name", "deny", "all", name(""), "access_list_items_hostname_check"},
	} {
		err := execInSavepoint(tx, `INSERT INTO access_list_items (access_list_id, directive, address, hostname) VALUES ($1, $2, $3, $4)`,
			listID, c.directive, c.address, c.hostname)
		expectConstraint(t, c.desc, err, c.refusedBy)
	}

	// dns_entry_states: a new row starts as "nothing published, nothing
	// applied, never checked".
	var (
		status                              string
		published, lastApplied, warnings    pq.StringArray
		changeTimes                         pq.Int64Array
		generation, appliedGeneration       int64
		candidateSeen, v4Missing, v6Missing int
		noCandidate, replaceOpen, disabled  bool
	)
	err = tx.QueryRow(`INSERT INTO dns_entry_states (hostname) VALUES ('partner.example.com')
		RETURNING status, published, last_applied, warnings, change_times, generation, applied_generation,
		          candidate_seen, v4_notfound, v6_notfound, candidate IS NULL, replace_open, disabled`).
		Scan(&status, &published, &lastApplied, &warnings, &changeTimes, &generation, &appliedGeneration,
			&candidateSeen, &v4Missing, &v6Missing, &noCandidate, &replaceOpen, &disabled)
	if err != nil {
		t.Fatalf("insert a dns_entry_states row: %v", err)
	}
	if status != "pending" || len(published) != 0 || len(lastApplied) != 0 || len(warnings) != 0 || len(changeTimes) != 0 ||
		generation != 0 || appliedGeneration != 0 || candidateSeen != 0 || v4Missing != 0 || v6Missing != 0 ||
		!noCandidate || replaceOpen || disabled {
		t.Errorf("a new row: status %q, published %v, last_applied %v, warnings %v, change_times %v, generation %d, applied_generation %d, candidate_seen %d, notfound %d/%d, candidate NULL %v, replace_open %v, disabled %v",
			status, published, lastApplied, warnings, changeTimes, generation, appliedGeneration, candidateSeen, v4Missing, v6Missing, noCandidate, replaceOpen, disabled)
	}
	for _, c := range []struct{ desc, query, refusedBy string }{
		{"a second row for the name", `INSERT INTO dns_entry_states (hostname) VALUES ('partner.example.com')`, "dns_entry_states_pkey"},
		{"an unknown status", `INSERT INTO dns_entry_states (hostname, status) VALUES ('a.example.com', 'deleted')`, "chk_dns_entry_states_status"},
		{"an unknown empty cause", `INSERT INTO dns_entry_states (hostname, empty_cause) VALUES ('b.example.com', 'gone')`, "chk_dns_entry_states_empty_cause"},
		{"a known empty cause", `INSERT INTO dns_entry_states (hostname, empty_cause) VALUES ('c.example.com', 'restored')`, ""},
		{"a name in upper case", `INSERT INTO dns_entry_states (hostname) VALUES ('Partner.Example.com')`, "chk_dns_entry_states_hostname"},
	} {
		expectConstraint(t, c.desc, execInSavepoint(tx, c.query), c.refusedBy)
	}

	// system_settings: the row the API creates on its first start names no
	// tunables; '{}' reads as every default.
	var settings string
	if err := tx.QueryRow(`INSERT INTO system_settings DEFAULT VALUES RETURNING dns_entry_settings::text`).Scan(&settings); err != nil {
		t.Errorf("insert a system_settings row: %v", err)
	} else if settings != "{}" {
		t.Errorf("a new system_settings row has dns_entry_settings %s, want {}", settings)
	}
}
