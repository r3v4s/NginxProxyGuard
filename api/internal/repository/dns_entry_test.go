package repository

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

func newDNSEntryMock(t *testing.T) (*DNSEntryRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	return NewDNSEntryRepository(db), mock
}

// dnsStateColumnNames are the columns UpsertState writes, in argument order.
func dnsStateColumnNames() []string {
	var cols []string
	for _, c := range strings.Split(dnsEntryStateColumns, ",") {
		cols = append(cols, strings.TrimSpace(c))
	}
	return cols
}

// dnsArgAt is a sqlmock argument matcher that matches anything and records
// the driver value of argument i.
type dnsArgAt struct {
	i    int
	into []driver.Value
}

func (a dnsArgAt) Match(v driver.Value) bool {
	a.into[a.i] = v
	return true
}

// saveDNSState runs UpsertState(st) in WithTx against mock and returns the
// arguments it bound, in column order.
func saveDNSState(t *testing.T, repo *DNSEntryRepository, mock sqlmock.Sqlmock, st model.DNSEntryState) []driver.Value {
	t.Helper()
	args := make([]driver.Value, len(dnsStateColumnNames()))
	matchers := make([]driver.Value, len(args))
	for i := range args {
		matchers[i] = dnsArgAt{i: i, into: args}
	}
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO dns_entry_states`).WithArgs(matchers...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := repo.WithTx(context.Background(), func(tx DNSEntryTx) error { return tx.UpsertState(context.Background(), st) }); err != nil {
		t.Fatalf("UpsertState: %v", err)
	}
	return args
}

// readDNSState feeds written back as a row, with created and updated, and
// reads it through GetStates.
func readDNSState(t *testing.T, repo *DNSEntryRepository, mock sqlmock.Sqlmock, written []driver.Value, created, updated time.Time) model.DNSEntryState {
	t.Helper()
	row := append(append([]driver.Value{}, written...), created, updated)
	mock.ExpectQuery(`FROM dns_entry_states`).
		WillReturnRows(sqlmock.NewRows(append(dnsStateColumnNames(), "created_at", "updated_at")).AddRow(row...))
	got, err := repo.GetStates(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetStates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetStates returned %d rows, want 1", len(got))
	}
	for _, st := range got {
		return st
	}
	return model.DNSEntryState{}
}

// dnsWritten is the value written to column name.
func dnsWritten(t *testing.T, written []driver.Value, name string) driver.Value {
	t.Helper()
	for i, c := range dnsStateColumnNames() {
		if c == name {
			return written[i]
		}
	}
	t.Fatalf("UpsertState writes no column %s", name)
	return nil
}

func dnsTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// What UpsertState writes, GetStates reads back unchanged: every field goes
// to its own column and comes back from it. A swapped pair of arguments, or
// a SELECT out of step with the INSERT, shows up here as a field that
// changed.
func TestDNSEntryStateRoundTrip(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	st := model.DNSEntryState{
		Hostname:           "partner.example.com",
		Status:             model.DNSStatusNeedsReview,
		ReviewReason:       model.DNSReviewCNAMEChanged,
		Disabled:           true,
		UnusedSince:        dnsTime("2026-10-01T01:00:00Z"),
		Published:          []string{"192.0.2.10", "2001:db8::10"},
		LastApplied:        []string{"192.0.2.11"},
		EmptyCause:         model.DNSEmptyLapse,
		Generation:         7,
		AppliedGeneration:  5,
		RevokePendingSince: dnsTime("2026-10-01T02:00:00Z"),
		Candidate:          []string{"203.0.113.12"},
		CandidateSeen:      2,
		ReplaceOpen:        true,
		V4:                 model.DNSFamilyState{State: "ok", Observed: []string{"203.0.113.12"}, AnswerAt: dnsTime("2026-10-01T03:00:00Z")},
		V6:                 model.DNSFamilyState{State: "notfound", Code: "not_found", AnswerAt: dnsTime("2026-10-01T04:00:00Z"), NotFound: 3},
		CanonicalName:      "edge.example.com",
		CanonicalSeen:      "edge2.example.com",
		Warnings:           []string{model.DNSWarnCGNAT, model.DNSWarnPartialRejected},
		ChangeTimes:        []time.Time{time.Unix(1790000000, 0).UTC(), time.Unix(1790003600, 0).UTC()},
		LastCheckedAt:      dnsTime("2026-10-01T05:00:00Z"),
		LastChangedAt:      dnsTime("2026-10-01T06:00:00Z"),
	}
	written := saveDNSState(t, repo, mock, st)

	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 10, 1, 7, 0, 0, 0, time.UTC)
	got := readDNSState(t, repo, mock, written, created, updated)
	want := st
	want.CreatedAt, want.UpdatedAt = created, updated
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read back\n %+v\nwant\n %+v", got, want)
	}
}

// A new name's row: NULL where the model has "" or nil, '{}' in the NOT
// NULL arrays (NULL there would abort the whole transaction). candidate
// keeps the difference between NULL and empty.
func TestDNSEntryStateWritesNullsAndEmptyArrays(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	st := model.DNSEntryState{Hostname: "partner.example.com", Status: model.DNSStatusPending}
	written := saveDNSState(t, repo, mock, st)

	for _, name := range []string{"published", "last_applied", "warnings", "change_times"} {
		if got := dnsWritten(t, written, name); got != "{}" {
			t.Errorf("%s = %#v, want '{}' (the column is NOT NULL)", name, got)
		}
	}
	for _, name := range []string{"review_reason", "unused_since", "empty_cause", "revoke_pending_since", "candidate",
		"v4_state", "v4_code", "v4_observed", "v4_answer_at", "v6_state", "v6_code", "v6_observed", "v6_answer_at",
		"canonical_name", "canonical_seen", "last_checked_at", "last_changed_at"} {
		if got := dnsWritten(t, written, name); got != nil {
			t.Errorf("%s = %#v, want NULL", name, got)
		}
	}

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	got := readDNSState(t, repo, mock, written, at, at)
	want := st
	want.CreatedAt, want.UpdatedAt = at, at
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read back\n %+v\nwant\n %+v", got, want)
	}

	st.Candidate = []string{}
	written = saveDNSState(t, repo, mock, st)
	if got := readDNSState(t, repo, mock, written, at, at); got.Candidate == nil || len(got.Candidate) != 0 {
		t.Errorf("an empty candidate came back as %#v, want an empty, non-nil slice", got.Candidate)
	}
}

// The counters are smallint columns. A name that stays not found counts up
// at every check; past 32767 the write would fail, and with it every other
// name's transition in the same transaction. They saturate instead.
func TestDNSEntryStateCountersSaturate(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	st := model.DNSEntryState{Hostname: "partner.example.com", Status: model.DNSStatusNotFound, CandidateSeen: 70000}
	st.V4.NotFound, st.V6.NotFound = 40000, -1
	written := saveDNSState(t, repo, mock, st)
	for name, want := range map[string]int64{"candidate_seen": 32767, "v4_notfound": 32767, "v6_notfound": 0} {
		if got := dnsWritten(t, written, name); got != want {
			t.Errorf("%s = %#v, want %d", name, got, want)
		}
	}
}

// An update replaces every column the insert writes except the key and
// created_at. A column missing from the SET list would keep its old value on
// every later save: a revoked address would stay published.
func TestDNSEntryUpsertReplacesEveryColumn(t *testing.T) {
	stmt := strings.Join(strings.Fields(dnsEntryStateUpsert), " ")
	i := strings.Index(stmt, "ON CONFLICT (hostname) DO UPDATE SET ")
	if i < 0 {
		t.Fatalf("the upsert has no ON CONFLICT (hostname) DO UPDATE SET: %s", stmt)
	}
	set := stmt[i:]
	for _, c := range dnsStateColumnNames()[1:] {
		if !strings.Contains(set, c+" = EXCLUDED."+c) {
			t.Errorf("the update does not set %s", c)
		}
	}
	if strings.Contains(set, "created_at") {
		t.Error("the update must keep created_at")
	}
	if !strings.Contains(set, "updated_at = now()") {
		t.Error("the update must set updated_at")
	}
	if got := strings.Count(stmt[:i], "$"); got != len(dnsStateColumnNames()) {
		t.Errorf("the insert binds %d parameters for %d columns", got, len(dnsStateColumnNames()))
	}
}

// The references are the hostname rows of every access list, as (scope,
// name, list id, list name), ordered by scope and name.
func TestDNSEntryListReferences(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	const listA = "0b5e0c3a-8f2d-4c1e-9a7b-6d5e4f3a2b1c"
	const listB = "7f1d2c3b-4a5e-4f60-8b9a-0c1d2e3f4a5b"
	mock.ExpectQuery("^" + regexp.QuoteMeta(`SELECT 'acl:' || i.access_list_id::text, i.hostname, l.id::text, l.name
		FROM access_list_items i JOIN access_lists l ON l.id = i.access_list_id
		WHERE i.hostname IS NOT NULL ORDER BY 1, 2`) + "$").
		WillReturnRows(sqlmock.NewRows([]string{"scope", "hostname", "id", "name"}).
			AddRow("acl:"+listA, "office.example.com", listA, "partners").
			AddRow("acl:"+listA, "partner.example.com", listA, "partners").
			AddRow("acl:"+listB, "partner.example.com", listB, "branch office"))

	refs, err := repo.ListReferences(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []model.DNSReference{
		{Scope: "acl:" + listA, Name: "office.example.com", OwnerID: listA, OwnerName: "partners"},
		{Scope: "acl:" + listA, Name: "partner.example.com", OwnerID: listA, OwnerName: "partners"},
		{Scope: "acl:" + listB, Name: "partner.example.com", OwnerID: listB, OwnerName: "branch office"},
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("references = %+v\nwant %+v", refs, want)
	}
}

// Only the transaction view locks rows. nil reads every row, an empty list
// reads nothing and sends no query.
func TestDNSEntryGetStatesLocksOnlyInATransaction(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	sel := regexp.QuoteMeta(dnsEntryStateSelect)
	cols := append(dnsStateColumnNames(), "created_at", "updated_at")
	names := []string{"partner.example.com", "office.example.com"}
	ctx := context.Background()

	mock.ExpectQuery("^" + sel + ` ORDER BY hostname$`).WillReturnRows(sqlmock.NewRows(cols))
	mock.ExpectQuery("^" + sel + regexp.QuoteMeta(` WHERE hostname = ANY($1) ORDER BY hostname`) + "$").
		WithArgs(pq.StringArray(names)).WillReturnRows(sqlmock.NewRows(cols))
	if _, err := repo.GetStates(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetStates(ctx, names); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.GetStates(ctx, []string{}); err != nil || len(got) != 0 {
		t.Fatalf("GetStates(empty) = %v, %v", got, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("^" + sel + ` ORDER BY hostname FOR UPDATE$`).WillReturnRows(sqlmock.NewRows(cols))
	mock.ExpectQuery("^" + sel + regexp.QuoteMeta(` WHERE hostname = ANY($1) ORDER BY hostname FOR UPDATE`) + "$").
		WithArgs(pq.StringArray(names)).WillReturnRows(sqlmock.NewRows(cols))
	mock.ExpectCommit()
	err := repo.WithTx(ctx, func(tx DNSEntryTx) error {
		if _, err := tx.GetStates(ctx, nil); err != nil {
			return err
		}
		if _, err := tx.GetStates(ctx, names); err != nil {
			return err
		}
		_, err := tx.GetStates(ctx, []string{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// WithTx commits what fn did, and rolls back on an error or a panic: a
// transaction left open would keep its rows locked FOR UPDATE and every
// later transition would wait on them.
func TestDNSEntryWithTx(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectQuery(`FROM access_list_items i JOIN access_lists l`).
		WillReturnRows(sqlmock.NewRows([]string{"scope", "hostname", "id", "name"}))
	mock.ExpectExec("^" + regexp.QuoteMeta(`DELETE FROM dns_entry_states WHERE hostname = $1`) + "$").
		WithArgs("old.example.com").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	err := repo.WithTx(ctx, func(tx DNSEntryTx) error {
		if _, err := tx.ListReferences(ctx); err != nil {
			return err
		}
		return tx.DeleteState(ctx, "old.example.com")
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	errStop := errors.New("stop")
	mock.ExpectBegin()
	mock.ExpectRollback()
	if err := repo.WithTx(ctx, func(DNSEntryTx) error { return errStop }); !errors.Is(err, errStop) {
		t.Fatalf("WithTx = %v, want fn's error", err)
	}

	mock.ExpectBegin()
	mock.ExpectRollback()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not reach the caller")
			}
		}()
		_ = repo.WithTx(ctx, func(DNSEntryTx) error { panic("boom") })
	}()
}

// MarkApplied sends one statement per name, in name order, outside a
// transaction. The statement never lowers applied_generation and clears the
// pending revocation only once the applied generation reaches the row's.
func TestDNSEntryMarkApplied(t *testing.T) {
	repo, mock := newDNSEntryMock(t)
	stmt := "^" + regexp.QuoteMeta(`UPDATE dns_entry_states SET
		applied_generation = GREATEST(applied_generation, $2),
		revoke_pending_since = CASE WHEN GREATEST(applied_generation, $2) >= generation THEN NULL ELSE revoke_pending_since END,
		updated_at = now()
		WHERE hostname = $1 AND (applied_generation < $2 OR revoke_pending_since IS NOT NULL)`) + "$"
	mock.ExpectExec(stmt).WithArgs("office.example.com", int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(stmt).WithArgs("partner.example.com", int64(7)).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repo.MarkApplied(context.Background(), map[string]int64{"partner.example.com": 7, "office.example.com": 3}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkApplied(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	errDown := errors.New("connection refused")
	mock.ExpectExec(stmt).WithArgs("office.example.com", int64(3)).WillReturnError(errDown)
	if err := repo.MarkApplied(context.Background(), map[string]int64{"partner.example.com": 7, "office.example.com": 3}); !errors.Is(err, errDown) {
		t.Fatalf("MarkApplied = %v, want the database error", err)
	}
}
