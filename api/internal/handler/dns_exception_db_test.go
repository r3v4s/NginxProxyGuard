package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// openExceptionDNSDB returns a database of its own on the server
// NPG_TEST_DATABASE_URL names, holding the schema of a fresh install:
// 001_init.sql in one Exec, as RunMigrations does. The server needs the
// timescaledb extension (the timescale/timescaledb image). Skipped without
// the variable, as in CI.
func openExceptionDNSDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set — skipping DB-backed exception list domain test")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping test database: %v", err)
	}
	name := fmt.Sprintf("npg_test_exdns_%d_%d", os.Getpid(), time.Now().UnixNano())
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
	schema, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("001_init.sql: %v", err)
	}
	return db
}

// noLookups is a resolver that answers nothing. The paths tested here never
// ask it, and no test may reach a real DNS server.
type noLookups struct{}

func (noLookups) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("no lookups in tests")
}

func (noLookups) LookupCNAME(context.Context, string) (string, error) {
	return "", errors.New("no lookups in tests")
}

// The confirm routes and the GETs over the schema of a fresh install, with
// the real repositories and DNS entry service: the scopes the database gives
// a name's uses are the ones the routes look for, the URI block list reads
// each host's Advanced Config, and each name shows its state. Skipped
// without NPG_TEST_DATABASE_URL, as in CI.
func TestExceptionListDomainsAgainstTheDatabase(t *testing.T) {
	db := openExceptionDNSDB(t)
	ctx := context.Background()
	var login, plain string
	if err := db.QueryRow(`INSERT INTO proxy_hosts (domain_names, forward_host, advanced_config)
		VALUES ('{login.example.com}', '192.0.2.20', 'auth_basic "Restricted";') RETURNING id`).Scan(&login); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO proxy_hosts (domain_names, forward_host) VALUES ('{plain.example.com}', '192.0.2.21') RETURNING id`).Scan(&plain); err != nil {
		t.Fatal(err)
	}
	settings := repository.NewSystemSettingsRepository(db)
	if _, err := settings.Get(ctx); err != nil { // creates the row
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO uri_blocks (proxy_host_id, exception_hostnames) VALUES ('` + login + `', '{partner.example.com,shared.example.com}')`,
		`INSERT INTO geo_restrictions (proxy_host_id, mode, countries, allowed_hostnames) VALUES ('` + plain + `', 'whitelist', '{KR}', '{other.example.com}')`,
		`UPDATE system_settings SET global_trusted_hostnames = '{shared.example.com}'`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	dbw := &database.DB{DB: db}
	hosts := repository.NewProxyHostRepository(dbw)
	dns := service.NewDNSEntryService(service.DNSEntryDeps{States: repository.NewDNSEntryRepository(db), Settings: settings},
		service.DNSEntryOptions{Lookuper: noLookups{}})
	security := NewSecurityHandler(service.NewSecurityService(repository.NewRateLimitRepository(db), nil, nil, nil, hosts, nil, nil,
		repository.NewURIBlockRepository(dbw), nil, nil), nil)
	security.SetDNSEntries(dns)
	confirm := NewExceptionDNSHandler(hosts, dns, nil)

	// The URI block screen's list: the login host skips its domains, and
	// each has its state (pending: never checked).
	rec := callWithGrants(t, security.ListAllURIBlocks, permGrants{"waf:read": true}, http.MethodGet, "")
	expectStatus(t, rec, http.StatusOK)
	var list []struct {
		ProxyHostID string                 `json:"proxy_host_id"`
		Skipped     bool                   `json:"exception_hostnames_skipped"`
		Status      []model.DNSEntryStatus `json:"exception_hostname_status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("GET /uri-blocks = %s (%v)", rec.Body, err)
	}
	var got []string
	for _, st := range list[0].Status {
		got = append(got, st.Hostname+" "+st.Status)
	}
	if list[0].ProxyHostID != login || !list[0].Skipped ||
		!reflect.DeepEqual(got, []string{"partner.example.com pending", "shared.example.com pending"}) {
		t.Errorf("GET /uri-blocks entry = %+v", list[0])
	}
	for host, want := range map[string]bool{login: true, plain: false} {
		rec := callWithGrants(t, security.GetURIBlock, permGrants{"proxy:read": true}, http.MethodGet, "", "proxyHostId", host)
		if fields := responseFields(t, rec); string(fields["exception_hostnames_skipped"]) != fmt.Sprint(want) {
			t.Errorf("host %s: exception_hostnames_skipped = %s, want %v", host, fields["exception_hostnames_skipped"], want)
		}
	}

	// A name none of a route's lists holds is not in its list; one they
	// hold passes the list and the permissions, and is refused only because
	// it does not wait for review.
	body := func(name string) string { return `{"hostname":"` + name + `","expected_addresses":[]}` }
	proxyWriter := permGrants{"proxy:write": true}
	both := permGrants{"proxy:write": true, "settings:write": true}
	for _, tc := range []struct {
		name     string
		call     echo.HandlerFunc
		params   []string
		grants   permGrants
		hostname string
		status   int
		code     string
		required []string
	}{
		{"the login host's URI exception", confirm.ConfirmHost, []string{"id", login}, proxyWriter, "partner.example.com", http.StatusBadRequest, "not_in_review", nil},
		{"another host's priority allow", confirm.ConfirmHost, []string{"id", login}, proxyWriter, "other.example.com", http.StatusBadRequest, "not_in_list", nil},
		{"the plain host's priority allow", confirm.ConfirmHost, []string{"id", plain}, proxyWriter, "other.example.com", http.StatusBadRequest, "not_in_review", nil},
		{"a host's name on the global geo route", confirm.ConfirmGlobalGeo, nil, permGrants{"waf:write": true}, "other.example.com", http.StatusBadRequest, "not_in_list", nil},
		{"shared with the trusted list, without settings:write", confirm.ConfirmHost, []string{"id", login}, proxyWriter, "shared.example.com", http.StatusForbidden, "", []string{"settings:write"}},
		{"shared with a host, without proxy:write", confirm.ConfirmTrusted, nil, permGrants{"settings:write": true}, "shared.example.com", http.StatusForbidden, "", []string{"proxy:write"}},
		{"shared, with both", confirm.ConfirmTrusted, nil, both, "shared.example.com", http.StatusBadRequest, "not_in_review", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := callWithGrants(t, tc.call, tc.grants, http.MethodPost, body(tc.hostname), tc.params...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tc.status, rec.Body)
			}
			var answer confirmAnswer
			if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
				t.Fatal(err)
			}
			if answer.Code != tc.code || !reflect.DeepEqual(answer.Required, tc.required) {
				t.Errorf("code %q required %v, want %q %v", answer.Code, answer.Required, tc.code, tc.required)
			}
		})
	}
}
