package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// createTablesFrom001 creates tables in schema from the DDL a fresh install
// runs (001_init.sql), so the test exercises the shipped columns, types and
// CHECKs.
func createTablesFrom001(t *testing.T, db *sql.DB, schema string, tables ...string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "database", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		m := regexp.MustCompile(`(?ms)^CREATE TABLE IF NOT EXISTS public\.` + table + ` \(.*?\n\);`).FindString(string(b))
		if m == "" {
			t.Fatalf("no CREATE TABLE for %s in 001_init.sql", table)
		}
		mustExec(t, db, strings.Replace(m, "public."+table, schema+"."+table, 1))
	}
}

// dnsStateUTC returns st with every time in UTC and without the times the
// database sets, so a row read back compares with the state written.
func dnsStateUTC(st model.DNSEntryState) model.DNSEntryState {
	utc := func(p *time.Time) *time.Time {
		if p == nil {
			return nil
		}
		v := p.UTC()
		return &v
	}
	st.UnusedSince, st.RevokePendingSince = utc(st.UnusedSince), utc(st.RevokePendingSince)
	st.V4.AnswerAt, st.V6.AnswerAt = utc(st.V4.AnswerAt), utc(st.V6.AnswerAt)
	st.LastCheckedAt, st.LastChangedAt = utc(st.LastCheckedAt), utc(st.LastChangedAt)
	st.CreatedAt, st.UpdatedAt = time.Time{}, time.Time{}
	return st
}

// The state repository against the shipped table: references from access
// lists, a full row written and read back, an update that replaces every
// column but created_at, NULL and '{}' where they belong, saturated
// counters, FOR UPDATE inside a transaction, a rollback, MarkApplied and a
// delete.
func TestDNSEntryRepositoryAgainstTheDatabase(t *testing.T) {
	db, schema := openSchemaTestDB(t)
	createTablesFrom001(t, db, schema, "access_lists", "access_list_items", "dns_entry_states")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := NewDNSEntryRepository(db)
	lists := NewAccessListRepository(&database.DB{DB: db})

	partners, err := lists.Create(ctx, &model.CreateAccessListRequest{Name: "partners", Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "192.0.2.10", SortOrder: 0},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com", SortOrder: 1},
		{Directive: "deny", Address: "all", Hostname: "office.example.com", SortOrder: 2},
	}})
	if err != nil {
		t.Fatalf("create partners: %v", err)
	}
	branch, err := lists.Create(ctx, &model.CreateAccessListRequest{Name: "branch office", Items: []model.CreateAccessListItemRequest{
		{Directive: "deny", Address: "all", Hostname: "office.example.com", SortOrder: 0},
	}})
	if err != nil {
		t.Fatalf("create branch office: %v", err)
	}
	refs, err := repo.ListReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantRefs := []model.DNSReference{
		{Scope: model.AccessListDNSScope(partners.ID), Name: "office.example.com", OwnerID: partners.ID, OwnerName: "partners"},
		{Scope: model.AccessListDNSScope(partners.ID), Name: "partner.example.com", OwnerID: partners.ID, OwnerName: "partners"},
		{Scope: model.AccessListDNSScope(branch.ID), Name: "office.example.com", OwnerID: branch.ID, OwnerName: "branch office"},
	}
	// List ids are random: order the two scopes as the query does.
	sort.SliceStable(wantRefs, func(i, j int) bool { return wantRefs[i].Scope < wantRefs[j].Scope })
	if !reflect.DeepEqual(refs, wantRefs) {
		t.Fatalf("references = %+v\nwant %+v", refs, wantRefs)
	}

	full := model.DNSEntryState{
		Hostname:           "partner.example.com",
		Status:             model.DNSStatusStale,
		Disabled:           true,
		UnusedSince:        dnsTime("2026-10-01T01:00:00Z"),
		Published:          []string{"192.0.2.20", "2001:db8::20"},
		LastApplied:        []string{"192.0.2.20"},
		Generation:         4,
		AppliedGeneration:  3,
		RevokePendingSince: dnsTime("2026-10-01T02:00:00Z"),
		Candidate:          []string{"192.0.2.21"},
		CandidateSeen:      1,
		ReplaceOpen:        true,
		V4:                 model.DNSFamilyState{State: "ok", Observed: []string{"192.0.2.21"}, AnswerAt: dnsTime("2026-10-01T03:00:00Z")},
		V6:                 model.DNSFamilyState{State: "transient", Code: "timeout", AnswerAt: dnsTime("2026-10-01T04:00:00Z"), NotFound: 1},
		CanonicalName:      "edge.example.com",
		CanonicalSeen:      "edge.example.com",
		Warnings:           []string{model.DNSWarnPartialRejected},
		ChangeTimes:        []time.Time{time.Unix(1790000000, 0).UTC()},
		LastCheckedAt:      dnsTime("2026-10-01T05:00:00Z"),
		LastChangedAt:      dnsTime("2026-10-01T06:00:00Z"),
	}
	// The NOT NULL arrays empty, candidate NULL, the counters out of range.
	bare := model.DNSEntryState{Hostname: "office.example.com", Status: model.DNSStatusNotFound, CandidateSeen: 70000}
	bare.V4.NotFound = 40000
	if err := repo.WithTx(ctx, func(tx DNSEntryTx) error {
		if _, err := tx.GetStates(ctx, nil); err != nil {
			return err
		}
		if _, err := tx.GetStates(ctx, []string{full.Hostname, bare.Hostname}); err != nil {
			return err
		}
		if err := tx.UpsertState(ctx, full); err != nil {
			return err
		}
		return tx.UpsertState(ctx, bare)
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	got, err := repo.GetStates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g := dnsStateUTC(got[full.Hostname]); !reflect.DeepEqual(g, full) {
		t.Errorf("read back\n %+v\nwant\n %+v", g, full)
	}
	wantBare := bare
	wantBare.CandidateSeen, wantBare.V4.NotFound = 32767, 32767
	if g := dnsStateUTC(got[bare.Hostname]); !reflect.DeepEqual(g, wantBare) {
		t.Errorf("read back\n %+v\nwant\n %+v", g, wantBare)
	}
	var candidateNull, publishedEmpty bool
	if err := db.QueryRowContext(ctx, `SELECT candidate IS NULL, published = '{}' FROM dns_entry_states WHERE hostname = $1`,
		bare.Hostname).Scan(&candidateNull, &publishedEmpty); err != nil {
		t.Fatal(err)
	}
	if !candidateNull || !publishedEmpty {
		t.Errorf("candidate IS NULL = %v, published = '{}' = %v; want both", candidateNull, publishedEmpty)
	}

	// An update replaces the row and keeps created_at.
	created := got[full.Hostname].CreatedAt
	next := full
	next.Status, next.Published, next.Candidate, next.ChangeTimes = model.DNSStatusOK, []string{"192.0.2.21"}, []string{}, nil
	next.Generation, next.RevokePendingSince = 5, nil
	if err := repo.WithTx(ctx, func(tx DNSEntryTx) error { return tx.UpsertState(ctx, next) }); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = repo.GetStates(ctx, []string{full.Hostname})
	if err != nil {
		t.Fatal(err)
	}
	if g := dnsStateUTC(got[full.Hostname]); !reflect.DeepEqual(g, next) {
		t.Errorf("after the update\n %+v\nwant\n %+v", g, next)
	}
	if !got[full.Hostname].CreatedAt.Equal(created) {
		t.Errorf("created_at moved from %v to %v", created, got[full.Hostname].CreatedAt)
	}

	// MarkApplied raises, never lowers, and clears the revocation only at
	// the row's generation.
	revoking := next
	revoking.Generation, revoking.AppliedGeneration, revoking.RevokePendingSince = 7, 5, dnsTime("2026-10-01T07:00:00Z")
	if err := repo.WithTx(ctx, func(tx DNSEntryTx) error { return tx.UpsertState(ctx, revoking) }); err != nil {
		t.Fatal(err)
	}
	applied := func() (int64, bool) {
		t.Helper()
		var gen int64
		var pending bool
		if err := db.QueryRowContext(ctx, `SELECT applied_generation, revoke_pending_since IS NOT NULL FROM dns_entry_states WHERE hostname = $1`,
			revoking.Hostname).Scan(&gen, &pending); err != nil {
			t.Fatal(err)
		}
		return gen, pending
	}
	for _, step := range []struct {
		mark        int64
		wantGen     int64
		wantPending bool
	}{{6, 6, true}, {4, 6, true}, {7, 7, false}, {3, 7, false}} {
		if err := repo.MarkApplied(ctx, map[string]int64{revoking.Hostname: step.mark, "missing.example.com": step.mark}); err != nil {
			t.Fatalf("MarkApplied(%d): %v", step.mark, err)
		}
		if gen, pending := applied(); gen != step.wantGen || pending != step.wantPending {
			t.Errorf("after MarkApplied(%d): applied %d, revoke pending %v; want %d, %v", step.mark, gen, pending, step.wantGen, step.wantPending)
		}
	}

	// A failed transaction leaves nothing behind; a delete removes the row.
	errStop := errors.New("stop")
	err = repo.WithTx(ctx, func(tx DNSEntryTx) error {
		if err := tx.UpsertState(ctx, model.DNSEntryState{Hostname: "new.example.com", Status: model.DNSStatusPending}); err != nil {
			return err
		}
		return errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("WithTx = %v, want errStop", err)
	}
	if err := repo.WithTx(ctx, func(tx DNSEntryTx) error { return tx.DeleteState(ctx, bare.Hostname) }); err != nil {
		t.Fatal(err)
	}
	got, err = repo.GetStates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["new.example.com"]; ok || len(got) != 1 {
		t.Errorf("rows after the rollback and the delete: %v, want only %s", dnsMapKeys(got), full.Hostname)
	}
}

// A domain rule goes through the shipped CHECK as (deny, all, hostname) even
// when the item says allow and the name, and both reads return the name.
func TestAccessListDomainRowsAgainstTheDatabase(t *testing.T) {
	db, schema := openSchemaTestDB(t)
	createTablesFrom001(t, db, schema, "access_lists", "access_list_items")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := NewAccessListRepository(&database.DB{DB: db})

	list, err := repo.Create(ctx, &model.CreateAccessListRequest{Name: "partners", Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "192.0.2.10", SortOrder: 0},
		{Directive: "allow", Address: "partner.example.com", Hostname: "partner.example.com", SortOrder: 1},
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(list.Items) != 2 || list.Items[0].Hostname != "" || list.Items[1].Hostname != "partner.example.com" ||
		list.Items[1].Directive != "deny" || list.Items[1].Address != "all" {
		t.Fatalf("items = %+v", list.Items)
	}
	all, _, err := repo.List(ctx, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || len(all[0].Items) != 2 || all[0].Items[1].Hostname != "partner.example.com" {
		t.Fatalf("List = %+v", all)
	}

	// The CHECK refuses an allow row with a hostname: the repository's
	// placeholder is the only shape it takes.
	_, err = db.ExecContext(ctx, `INSERT INTO access_list_items (access_list_id, directive, address, hostname) VALUES ($1, 'allow', 'all', 'partner.example.com')`, list.ID)
	if err == nil {
		t.Fatal("the hostname CHECK took an allow row")
	}
}

func dnsMapKeys(m map[string]model.DNSEntryState) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
