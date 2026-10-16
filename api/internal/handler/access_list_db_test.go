package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
)

// openAccessListDB returns a database of its own on the server
// NPG_TEST_DATABASE_URL names, holding the access list tables as a fresh
// install creates them (001_init.sql). Skipped without the variable, as in
// CI.
func openAccessListDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed access list test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_al_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		admin.Close()
		t.Skipf("cannot create a test database: %v", err)
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
	for _, re := range []string{
		`(?s)CREATE TABLE IF NOT EXISTS public\.access_lists \(.*?\n\);`,
		`(?s)CREATE TABLE IF NOT EXISTS public\.access_list_items \(.*?\n\);`,
	} {
		ddl := regexp.MustCompile(re).FindString(string(b))
		if ddl == "" {
			t.Fatalf("001_init.sql has no %s", re)
		}
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("exec %q: %v", ddl, err)
		}
	}
	return db
}

// accessListTestDSN is dsn naming the database name instead.
func accessListTestDSN(dsn, name string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		u.Path = "/" + name
		return u.String()
	}
	return dsn + " dbname=" + name // key=value: the last dbname wins
}

// storedRules returns the rules of list id as "directive|address|hostname|sort_order".
func storedRules(t *testing.T, db *sql.DB, id string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT directive, address, COALESCE(hostname, ''), sort_order FROM access_list_items WHERE access_list_id = $1 ORDER BY sort_order`, id)
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

// A domain rule goes through the real repository and the column's CHECK as
// (deny, all, hostname), after the address rules, and comes back as allow
// <name>. An older client that sends the list back without kind keeps the
// domain, and a name an older version saved stays a legacy rule.
func TestAccessListDomainRulesAgainstTheDatabase(t *testing.T) {
	db := openAccessListDB(t)
	calls := &callLog{}
	h := &AccessListHandler{
		repo:       repository.NewAccessListRepository(&database.DB{DB: db}),
		proxyHosts: &fakeAccessListHosts{log: calls},
		audit:      &fakeAccessListAudit{log: calls},
		dns:        &fakeAccessListDNS{log: calls},
	}

	rec := callWithGrants(t, h.Create, listWriter, http.MethodPost,
		`{"name":"partners","items":[{"directive":"allow","address":"Partner.Example.COM.","kind":"hostname"},{"directive":"allow","address":"192.0.2.10"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d; body %s", rec.Code, rec.Body)
	}
	var created struct {
		ID    string `json:"id"`
		Items []struct {
			Directive string `json:"directive"`
			Address   string `json:"address"`
			Kind      string `json:"kind"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if got, want := storedRules(t, db, created.ID), []string{"allow|192.0.2.10||0", "deny|all|partner.example.com|1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stored rules = %v, want %v", got, want)
	}
	if len(created.Items) != 2 || created.Items[1].Kind != "hostname" || created.Items[1].Directive != "allow" || created.Items[1].Address != "partner.example.com" {
		t.Errorf("the created list shows %+v, want the domain as allow partner.example.com", created.Items)
	}

	// A name an older version saved as a plain rule.
	if _, err := db.Exec(`INSERT INTO access_list_items (access_list_id, directive, address, sort_order) VALUES ($1, 'allow', 'old.example.com', 2)`, created.ID); err != nil {
		t.Fatal(err)
	}
	// An older client renames the list and sends back what it read, without kind.
	rec = callWithGrants(t, h.Update, listWriter, http.MethodPut,
		`{"name":"partners-2","items":[{"directive":"allow","address":"192.0.2.10"},{"directive":"allow","address":"partner.example.com"},{"directive":"allow","address":"old.example.com"}]}`,
		"id", created.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: status %d; body %s", rec.Code, rec.Body)
	}
	if got, want := storedRules(t, db, created.ID), []string{"allow|192.0.2.10||0", "allow|old.example.com||1", "deny|all|partner.example.com|2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stored rules after the update = %v, want %v", got, want)
	}
}
