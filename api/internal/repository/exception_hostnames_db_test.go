package repository

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// Domain names in the exception lists (#320) against the schema a fresh
// install creates: every write keeps the names when the request leaves the
// field out, empties them on [] and replaces them on a value, and the
// domain references read every list.

// createDNSReferenceTables creates in schema every table the domain
// references read: the access lists and the seven exception list tables
// from the DDL a fresh install runs, and a proxy_hosts with the columns the
// references read (its own DDL needs the uuid-ossp extension).
func createDNSReferenceTables(t *testing.T, db *sql.DB, schema string) {
	t.Helper()
	createTablesFrom001(t, db, schema, "access_lists", "access_list_items", "uri_blocks", "global_uri_blocks",
		"geo_restrictions", "global_geo_restrictions", "rate_limits", "global_rate_limits", "system_settings")
	mustExec(t, db, `CREATE TABLE `+schema+`.proxy_hosts (id uuid DEFAULT gen_random_uuid() PRIMARY KEY, domain_names text[] NOT NULL)`)
}

// insertTestProxyHost adds a proxy host with the domain names and returns
// its id.
func insertTestProxyHost(t *testing.T, db *sql.DB, domains ...string) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`INSERT INTO proxy_hosts (domain_names, forward_host) VALUES ($1, '192.0.2.10') RETURNING id`,
		pq.Array(domains)).Scan(&id); err != nil {
		t.Fatalf("insert a proxy host: %v", err)
	}
	return id
}

func TestHostnameColumnsKeepWhenOmittedAndClearOnEmpty(t *testing.T) {
	db := openBackupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	hostID := insertTestProxyHost(t, db, "app.example.com")
	uri := NewURIBlockRepository(&database.DB{DB: db})
	geo := NewGeoRepository(&database.DB{DB: db})
	globalGeo := NewGlobalGeoRepository(&database.DB{DB: db})
	rateLimits := NewRateLimitRepository(db)
	globalRateLimits := NewGlobalRateLimitRepository(db)
	settings := NewSystemSettingsRepository(db)
	yes := true

	// Each write saves another field too, so the row is written even when
	// the names are left out, and returns the names it read back.
	type writeSite struct {
		name  string
		write func(names *[]string) ([]string, error)
		read  func() ([]string, error)
	}
	sites := []writeSite{
		{"uri_blocks (URIBlockRepository.Upsert)",
			func(n *[]string) ([]string, error) {
				b, err := uri.Upsert(ctx, hostID, &model.CreateURIBlockRequest{ExceptionIPs: []string{"192.0.2.30"}, ExceptionHostnames: n})
				if err != nil || b == nil {
					return nil, err
				}
				return b.ExceptionHostnames, nil
			},
			func() ([]string, error) {
				b, err := uri.GetByProxyHostID(ctx, hostID)
				if err != nil || b == nil {
					return nil, err
				}
				return b.ExceptionHostnames, nil
			}},
		{"global_uri_blocks (URIBlockRepository.UpsertGlobalURIBlock)",
			func(n *[]string) ([]string, error) {
				b, err := uri.UpsertGlobalURIBlock(ctx, &model.CreateGlobalURIBlockRequest{Enabled: &yes, ExceptionHostnames: n})
				if err != nil || b == nil {
					return nil, err
				}
				return b.ExceptionHostnames, nil
			},
			func() ([]string, error) {
				b, err := uri.GetGlobalURIBlock(ctx)
				if err != nil || b == nil {
					return nil, err
				}
				return b.ExceptionHostnames, nil
			}},
		{"geo_restrictions (GeoRepository.Upsert)",
			func(n *[]string) ([]string, error) {
				g, err := geo.Upsert(ctx, hostID, &model.CreateGeoRestrictionRequest{Mode: "blacklist", Countries: []string{"KR"}, AllowedHostnames: n})
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			},
			func() ([]string, error) {
				g, err := geo.GetByProxyHostID(ctx, hostID)
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			}},
		{"geo_restrictions (GeoRepository.Update)",
			func(n *[]string) ([]string, error) {
				g, err := geo.Update(ctx, hostID, &model.UpdateGeoRestrictionRequest{Enabled: &yes, AllowedHostnames: n})
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			},
			func() ([]string, error) {
				g, err := geo.GetByProxyHostID(ctx, hostID)
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			}},
		{"global_geo_restrictions (GlobalGeoRepository.Upsert)",
			func(n *[]string) ([]string, error) {
				g, err := globalGeo.Upsert(ctx, &model.UpdateGlobalGeoRestrictionRequest{Enabled: &yes, AllowedHostnames: n})
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			},
			func() ([]string, error) {
				g, err := globalGeo.GetGlobal(ctx)
				if err != nil || g == nil {
					return nil, err
				}
				return g.AllowedHostnames, nil
			}},
		{"rate_limits (RateLimitRepository.Upsert)",
			func(n *[]string) ([]string, error) {
				r, err := rateLimits.Upsert(ctx, hostID, &model.CreateRateLimitRequest{Enabled: &yes, WhitelistHostnames: n})
				if err != nil || r == nil {
					return nil, err
				}
				return r.WhitelistHostnames, nil
			},
			func() ([]string, error) {
				r, err := rateLimits.GetByProxyHostID(ctx, hostID)
				if err != nil || r == nil {
					return nil, err
				}
				return r.WhitelistHostnames, nil
			}},
		{"global_rate_limits (GlobalRateLimitRepository.Upsert)",
			func(n *[]string) ([]string, error) {
				r, err := globalRateLimits.Upsert(ctx, &model.UpdateGlobalRateLimitRequest{Enabled: &yes, WhitelistHostnames: n})
				if err != nil || r == nil {
					return nil, err
				}
				return r.WhitelistHostnames, nil
			},
			func() ([]string, error) {
				r, err := globalRateLimits.GetGlobal(ctx)
				if err != nil || r == nil {
					return nil, err
				}
				return r.WhitelistHostnames, nil
			}},
		{"system_settings (SystemSettingsRepository.Update)",
			func(n *[]string) ([]string, error) {
				ips := "192.0.2.31"
				s, err := settings.Update(ctx, &model.UpdateSystemSettingsRequest{GlobalTrustedIPs: &ips, GlobalTrustedHostnames: n})
				if err != nil || s == nil {
					return nil, err
				}
				return s.GlobalTrustedHostnames, nil
			},
			func() ([]string, error) {
				s, err := settings.Get(ctx)
				if err != nil || s == nil {
					return nil, err
				}
				return s.GlobalTrustedHostnames, nil
			}},
	}

	set := func(names ...string) *[]string { s := append([]string{}, names...); return &s }
	var unset []string
	steps := []struct {
		desc  string
		names *[]string
		want  []string
	}{
		{"a new row, the field left out", nil, []string{}},
		{"a value", set("partner.example.com", "office.example.com"), []string{"partner.example.com", "office.example.com"}},
		{"the field left out", nil, []string{"partner.example.com", "office.example.com"}},
		{"another value", set("branch.example.com"), []string{"branch.example.com"}},
		{"[]", set(), []string{}},
		{"a value again", set("branch.example.com"), []string{"branch.example.com"}},
		{"a nil list", &unset, []string{}},
	}
	for _, site := range sites {
		if site.name == "geo_restrictions (GeoRepository.Update)" {
			// Update changes an existing row only: start from a row without
			// names.
			if _, err := geo.Upsert(ctx, hostID, &model.CreateGeoRestrictionRequest{Mode: "blacklist", Countries: []string{"KR"}, AllowedHostnames: set()}); err != nil {
				t.Fatalf("%s: create the row: %v", site.name, err)
			}
		}
		for _, step := range steps {
			got, err := site.write(step.names)
			if err != nil {
				t.Errorf("%s, %s: write: %v", site.name, step.desc, err)
				break
			}
			read, err := site.read()
			if err != nil {
				t.Errorf("%s, %s: read: %v", site.name, step.desc, err)
				break
			}
			if !reflect.DeepEqual(got, step.want) || !reflect.DeepEqual(read, step.want) {
				t.Errorf("%s, %s: the write returned %#v and a read gives %#v, want %#v", site.name, step.desc, got, read, step.want)
			}
		}
	}

	// The URI block list of every host carries the names too.
	if _, err := uri.Upsert(ctx, hostID, &model.CreateURIBlockRequest{ExceptionHostnames: set("partner.example.com")}); err != nil {
		t.Fatal(err)
	}
	all, err := uri.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || !reflect.DeepEqual(all[0].ExceptionHostnames, []string{"partner.example.com"}) {
		t.Errorf("ListAll = %+v, want one block with exception_hostnames [partner.example.com]", all)
	}
}

// fillExceptionLists writes one array into each exception list of the host
// (and the global ones) straight into the tables.
func fillExceptionLists(t *testing.T, db *sql.DB, hostID string, uri, globalURI, prio, globalPrio, rl, globalRL, trusted []string) {
	t.Helper()
	for _, s := range []struct {
		query string
		args  []interface{}
	}{
		{`INSERT INTO uri_blocks (proxy_host_id, exception_hostnames) VALUES ($1, $2)`, []interface{}{hostID, pq.Array(uri)}},
		{`INSERT INTO global_uri_blocks (exception_hostnames) VALUES ($1)`, []interface{}{pq.Array(globalURI)}},
		{`INSERT INTO geo_restrictions (proxy_host_id, countries, allowed_hostnames) VALUES ($1, '{KR}', $2)`, []interface{}{hostID, pq.Array(prio)}},
		{`INSERT INTO global_geo_restrictions (allowed_hostnames) VALUES ($1)`, []interface{}{pq.Array(globalPrio)}},
		{`INSERT INTO rate_limits (proxy_host_id, whitelist_hostnames) VALUES ($1, $2)`, []interface{}{hostID, pq.Array(rl)}},
		{`INSERT INTO global_rate_limits (whitelist_hostnames) VALUES ($1)`, []interface{}{pq.Array(globalRL)}},
		{`INSERT INTO system_settings (global_trusted_hostnames) VALUES ($1)`, []interface{}{pq.Array(trusted)}},
	} {
		if _, err := db.Exec(s.query, s.args...); err != nil {
			t.Fatalf("%s: %v", s.query, err)
		}
	}
}

// Every list that can hold a domain name is a source of references: an
// access list is owned by the list, a host's exception list by the host
// (its first domain), a global list by "global" and the trusted list by no
// one. Ordered by scope and name.
func TestListReferencesReadsEveryList(t *testing.T) {
	db := openBackupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hostID := insertTestProxyHost(t, db, "app.example.com", "www.example.com")
	var listID string
	if err := db.QueryRow(`INSERT INTO access_lists (name) VALUES ('partners') RETURNING id`).Scan(&listID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO access_list_items (access_list_id, directive, address, hostname) VALUES ('`+listID+`', 'deny', 'all', 'acl.example.com')`)
	fillExceptionLists(t, db, hostID,
		[]string{"uri.example.com"}, []string{"guri.example.com"},
		[]string{"prio.example.com", "both.example.com"}, []string{"gprio.example.com"},
		[]string{"rl.example.com"}, []string{"grl.example.com"},
		[]string{"trusted.example.com", "both.example.com"})

	refs, err := NewDNSEntryRepository(db).ListReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.DNSReference{
		{Scope: "acl:" + listID, Name: "acl.example.com", OwnerID: listID, OwnerName: "partners"},
		{Scope: "prio:" + hostID, Name: "both.example.com", OwnerID: hostID, OwnerName: "app.example.com"},
		{Scope: "prio:" + hostID, Name: "prio.example.com", OwnerID: hostID, OwnerName: "app.example.com"},
		{Scope: "prio:global", Name: "gprio.example.com", OwnerID: "global", OwnerName: ""},
		{Scope: "rl:" + hostID, Name: "rl.example.com", OwnerID: hostID, OwnerName: "app.example.com"},
		{Scope: "rl:global", Name: "grl.example.com", OwnerID: "global", OwnerName: ""},
		{Scope: "trusted", Name: "both.example.com", OwnerID: "", OwnerName: ""},
		{Scope: "trusted", Name: "trusted.example.com", OwnerID: "", OwnerName: ""},
		{Scope: "uri:" + hostID, Name: "uri.example.com", OwnerID: hostID, OwnerName: "app.example.com"},
		{Scope: "uri:global", Name: "guri.example.com", OwnerID: "global", OwnerName: ""},
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("references:\n got  %+v\n want %+v", refs, want)
	}
	// Inside a transaction too (the DNS checks read them there).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if txRefs, err := newDNSEntryTx(tx).ListReferences(ctx); err != nil || !reflect.DeepEqual(txRefs, want) {
		t.Errorf("references in a transaction = %+v, %v", txRefs, err)
	}
}

// The arrays have no CHECK: an element the name rules refuse is left out,
// and only that element. A name that fails the CHECK on
// dns_entry_states.hostname would otherwise fail the transaction of every
// check.
func TestListReferencesSkipsNamesTheRulesRefuse(t *testing.T) {
	db := openBackupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hostID := insertTestProxyHost(t, db, "app.example.com")
	fillExceptionLists(t, db, hostID,
		[]string{"bad_name", "uri.example.com"},
		[]string{"Upper.Example.com", "guri.example.com"},
		[]string{"192.0.2.1", "prio.example.com"},
		[]string{"gprio.example.com", "nodot"},
		[]string{"printer.local", "rl.example.com", ""},
		[]string{"grl.example.com", "-bad.example.com"},
		[]string{"trusted.example.com", "partner.example.com;"})

	refs, err := NewDNSEntryRepository(db).ListReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		got = append(got, r.Scope+" "+r.Name)
	}
	want := []string{
		"prio:" + hostID + " prio.example.com",
		"prio:global gprio.example.com",
		"rl:" + hostID + " rl.example.com",
		"rl:global grl.example.com",
		"trusted trusted.example.com",
		"uri:" + hostID + " uri.example.com",
		"uri:global guri.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("references:\n got  %q\n want %q", got, want)
	}
}
