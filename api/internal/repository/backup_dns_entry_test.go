package repository

// Backup and restore of domain entries (#320): the rows of an access list
// travel as stored, (deny, all, hostname), and restore closed; the state of
// each name travels as a small record that a restore merges, never
// publishes.

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
)

// backupTestPolicy is the production address policy without the
// documentation rows, so 192.0.2.x and friends pass as public addresses.
func backupTestPolicy() *model.AddressPolicy {
	docs := map[string]bool{"192.0.2.0/24": true, "198.51.100.0/24": true, "203.0.113.0/24": true, "2001:db8::/32": true}
	var rules []model.AddressPolicyRule
	for _, r := range model.DefaultAddressPolicyRules() {
		if !docs[r.Prefix.String()] {
			rules = append(rules, r)
		}
	}
	return model.NewAddressPolicy(rules)
}

// newBackupRepoMock returns a BackupRepository on sqlmock that checks, when
// the test ends, that every expected query ran.
func newBackupRepoMock(t *testing.T) (*BackupRepository, sqlmock.Sqlmock) {
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
	return NewBackupRepository(db), mock
}

// A domain row is restored as (deny, all, hostname) whatever the file says
// around the name, after the address rules; a refused name keeps the list
// closed as a plain deny all; a name twice keeps its first row.
func TestImportAccessListRestoresDomainRowsClosed(t *testing.T) {
	repo, tx, mock := beginMockTx(t)
	const listID = "00000000-0000-0000-0000-0000000000a2"
	mock.ExpectQuery(`INSERT INTO access_lists`).
		WithArgs("partners", "", false, false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(listID))
	for _, args := range [][]driver.Value{
		{listID, "allow", "192.0.2.10", "", 0, nil},
		{listID, "deny", "198.51.100.0/24", "", 1, nil},
		{listID, "deny", "all", "partner west", 2, "partner.example.com"},
		{listID, "deny", "all", "", 3, "office.example.com"},
		{listID, "deny", "all", "", 4, nil}, // "intranet": refused, still closed
	} {
		mock.ExpectExec(`INSERT INTO access_list_items \(access_list_id, directive, address, description, sort_order, hostname\)`).
			WithArgs(args...).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}

	_, names, err := repo.importAccessList(context.Background(), tx, &model.AccessListExport{AccessList: model.AccessListData{
		Name: "partners",
		Items: []model.AccessListItemData{
			{Directive: "deny", Address: "all", Hostname: "Partner.Example.COM.", Description: "partner\nwest", SortOrder: 0},
			{Directive: "allow", Address: "192.0.2.10", SortOrder: 1},
			// The API's shape of a domain row, as a hand-edited file may hold it.
			{Directive: "allow", Address: "office.example.com", Hostname: "office.example.com", SortOrder: 2},
			{Directive: "deny", Address: "all", Hostname: "intranet", SortOrder: 3},
			{Directive: "deny", Address: "all", Hostname: "partner.example.com", SortOrder: 4},
			{Directive: "deny", Address: "198.51.100.0/24", SortOrder: 5},
			// A name an older version saved as a plain rule is still skipped.
			{Directive: "allow", Address: "legacy.example.com", SortOrder: 6},
		},
	}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if want := []string{"partner.example.com", "office.example.com"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
}

// backupStateStore is an in-memory DNSEntryTx.
type backupStateStore struct {
	rows     map[string]model.DNSEntryState
	asked    [][]string
	upserted []string
}

func (f *backupStateStore) ListReferences(context.Context) ([]model.DNSReference, error) {
	return nil, nil
}

func (f *backupStateStore) GetStates(_ context.Context, names []string) (map[string]model.DNSEntryState, error) {
	f.asked = append(f.asked, append([]string(nil), names...))
	out := make(map[string]model.DNSEntryState)
	for _, name := range names {
		if st, ok := f.rows[name]; ok {
			out[name] = st
		}
	}
	return out, nil
}

func (f *backupStateStore) UpsertState(_ context.Context, st model.DNSEntryState) error {
	f.rows[st.Hostname] = st
	f.upserted = append(f.upserted, st.Hostname)
	return nil
}

func (f *backupStateStore) DeleteState(context.Context, string) error { return nil }

// The backup's records merge into the live rows of the names the restored
// lists use: a name in review in the backup is closed and stays in review,
// whether its row is new or already published here; records of other names
// are ignored.
func TestMergeRestoredDNSEntryStates(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	store := &backupStateStore{rows: map[string]model.DNSEntryState{
		"office.example.com": {
			Hostname: "office.example.com", Status: model.DNSStatusOK, CanonicalName: "office.example.com",
			Published: []string{"192.0.2.30"}, LastApplied: []string{"192.0.2.30"}, Generation: 3, AppliedGeneration: 3,
		},
	}}
	states := []model.DNSEntryStateExport{
		{Hostname: "PARTNER.example.com", NeedsReview: true, ReviewReason: model.DNSReviewCNAMEChanged,
			CanonicalName: "edge.example.com", LastApplied: []string{"192.0.2.20"}},
		{Hostname: "office.example.com", NeedsReview: true, ReviewReason: model.DNSReviewUnstable},
		{Hostname: "elsewhere.example.com", NeedsReview: true, ReviewReason: model.DNSReviewReappeared},
	}
	names := []string{"partner.example.com", "office.example.com", "partner.example.com"}
	if err := mergeRestoredDNSEntryStates(context.Background(), store, states, names, backupTestPolicy(), now); err != nil {
		t.Fatalf("merge: %v", err)
	}

	if want := [][]string{{"office.example.com", "partner.example.com"}}; !reflect.DeepEqual(store.asked, want) {
		t.Errorf("rows read = %q, want %q", store.asked, want)
	}
	if want := []string{"office.example.com", "partner.example.com"}; !reflect.DeepEqual(store.upserted, want) {
		t.Errorf("rows written = %q, want %q", store.upserted, want)
	}
	if _, ok := store.rows["elsewhere.example.com"]; ok {
		t.Error("a record of a name no restored list uses was written")
	}

	partner := store.rows["partner.example.com"]
	if partner.Status != model.DNSStatusNeedsReview || partner.ReviewReason != model.DNSReviewCNAMEChanged ||
		len(partner.Published) != 0 || partner.CanonicalName != "edge.example.com" ||
		!reflect.DeepEqual(partner.LastApplied, []string{"192.0.2.20"}) {
		t.Errorf("new row = %+v, want needs_review (cname_changed), nothing published, the backup's pin and last_applied", partner)
	}
	office := store.rows["office.example.com"]
	if office.Status != model.DNSStatusNeedsReview || len(office.Published) != 0 ||
		office.Generation != 4 || office.RevokePendingSince == nil {
		t.Errorf("live row = %+v, want it closed for review: nothing published, generation 4, a revoke pending", office)
	}

	// Nothing to merge: no query, no write.
	for _, tc := range []struct {
		states []model.DNSEntryStateExport
		names  []string
	}{
		{nil, []string{"partner.example.com"}},
		{states, nil},
	} {
		empty := &backupStateStore{rows: map[string]model.DNSEntryState{}}
		if err := mergeRestoredDNSEntryStates(context.Background(), empty, tc.states, tc.names, backupTestPolicy(), now); err != nil {
			t.Fatal(err)
		}
		if len(empty.asked) != 0 || len(empty.upserted) != 0 {
			t.Errorf("states %d, names %q: read %q, wrote %q; want nothing", len(tc.states), tc.names, empty.asked, empty.upserted)
		}
	}
}

// A list's rules are exported as stored: a domain row stays (deny, all,
// hostname) in the backup, so a version without domain rows restores it
// closed.
func TestExportAccessListsKeepsDomainRowsAsStored(t *testing.T) {
	repo, mock := newBackupRepoMock(t)
	const listID = "00000000-0000-0000-0000-0000000000a3"
	mock.ExpectQuery(`FROM access_lists ORDER BY created_at`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "satisfy_any", "pass_auth"}).
			AddRow(listID, "partners", nil, true, false))
	mock.ExpectQuery(`SELECT directive, address, description, sort_order, hostname FROM access_list_items`).
		WithArgs(listID).
		WillReturnRows(sqlmock.NewRows([]string{"directive", "address", "description", "sort_order", "hostname"}).
			AddRow("allow", "192.0.2.10", "office", 0, nil).
			AddRow("deny", "all", nil, 1, "partner.example.com"))

	lists, err := repo.exportAccessLists(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	want := []model.AccessListItemData{
		{Directive: "allow", Address: "192.0.2.10", Description: "office", SortOrder: 0},
		{Directive: "deny", Address: "all", SortOrder: 1, Hostname: "partner.example.com"},
	}
	if len(lists) != 1 || !reflect.DeepEqual(lists[0].AccessList.Items, want) {
		t.Fatalf("exported lists = %+v, want one list with rules %+v", lists, want)
	}
	if got := exportedDNSNames(lists); !reflect.DeepEqual(got, []string{"partner.example.com"}) {
		t.Errorf("exportedDNSNames = %q, want [partner.example.com]", got)
	}
}

// A list whose rules cannot be read fails the backup, and so does a read of
// the lists or of a list's rules that breaks off part way. Exported without
// its rules a list would restore with none, which leaves its hosts open; a
// list missing from the backup leaves its hosts pointing at no list, which
// opens them too.
func TestExportAccessListsFailsWhenRulesCannotBeRead(t *testing.T) {
	const listID, otherID = "00000000-0000-0000-0000-0000000000a4", "00000000-0000-0000-0000-0000000000a5"
	lists := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"id", "name", "description", "satisfy_any", "pass_auth"}).
			AddRow(listID, "partners", nil, true, false)
	}
	rules := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"directive", "address", "description", "sort_order", "hostname"}).
			AddRow("allow", "192.0.2.10", nil, 0, nil)
	}
	brokenOff := errors.New("driver: bad connection")
	for _, tc := range []struct {
		name   string
		expect func(mock sqlmock.Sqlmock)
	}{
		{"rules cannot be read", func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(`FROM access_lists ORDER BY created_at`).WillReturnRows(lists())
			mock.ExpectQuery(`FROM access_list_items`).WithArgs(listID).
				WillReturnError(errors.New(`pq: column "hostname" does not exist`))
		}},
		{"read of the rules breaks off", func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(`FROM access_lists ORDER BY created_at`).WillReturnRows(lists())
			mock.ExpectQuery(`FROM access_list_items`).WithArgs(listID).
				WillReturnRows(rules().AddRow("deny", "all", nil, 1, "partner.example.com").RowError(1, brokenOff))
		}},
		{"read of the lists breaks off", func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(`FROM access_lists ORDER BY created_at`).
				WillReturnRows(lists().AddRow(otherID, "office", nil, false, false).RowError(1, brokenOff))
			mock.ExpectQuery(`FROM access_list_items`).WithArgs(listID).WillReturnRows(rules())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, mock := newBackupRepoMock(t)
			tc.expect(mock)
			if got, err := repo.exportAccessLists(context.Background()); err == nil {
				t.Fatalf("export = %+v, want an error", got)
			}
		})
	}
}

// The state records carry the review flag (and its reason only while in
// review), the pin and the last published addresses of the names asked for.
func TestExportDNSEntryStates(t *testing.T) {
	repo, mock := newBackupRepoMock(t)

	if recs, err := repo.exportDNSEntryStates(context.Background(), nil); err != nil || recs != nil {
		t.Fatalf("no names: %+v, %v; want nothing and no query", recs, err)
	}

	mock.ExpectQuery(`FROM dns_entry_states WHERE hostname = ANY\(\$1\)`).
		WithArgs(`{"office.example.com","partner.example.com","stale.example.com"}`).
		WillReturnRows(sqlmock.NewRows([]string{"hostname", "status", "review_reason", "canonical_name", "last_applied"}).
			AddRow("office.example.com", "ok", "", "office.example.com", "{192.0.2.30}").
			AddRow("partner.example.com", "needs_review", "cname_changed", "edge.example.com", "{192.0.2.20}").
			AddRow("stale.example.com", "stale", "unstable", "", "{}"))
	recs, err := repo.exportDNSEntryStates(context.Background(),
		[]string{"office.example.com", "partner.example.com", "stale.example.com"})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	want := []model.DNSEntryStateExport{
		{Hostname: "office.example.com", CanonicalName: "office.example.com", LastApplied: []string{"192.0.2.30"}},
		{Hostname: "partner.example.com", NeedsReview: true, ReviewReason: "cname_changed",
			CanonicalName: "edge.example.com", LastApplied: []string{"192.0.2.20"}},
		{Hostname: "stale.example.com"},
	}
	if !reflect.DeepEqual(recs, want) {
		t.Errorf("records = %+v\nwant      %+v", recs, want)
	}
}

// A backup's tunables are written as the API reads them; a backup without
// them, or with null there, keeps the live value.
func TestDNSEntrySettingsFromBackup(t *testing.T) {
	marshal := func(s model.DNSEntrySettings) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	defaults := marshal(model.DefaultDNSEntrySettings())

	for _, raw := range []json.RawMessage{nil, {}, json.RawMessage(`null`)} {
		if got := dnsEntrySettingsFromBackup(raw); got != nil {
			t.Errorf("absent or null %q: got %v, want nil (keep the live value)", raw, got)
		}
	}
	for _, raw := range []string{`{}`, `not json`} {
		if got := dnsEntrySettingsFromBackup(json.RawMessage(raw)); got != defaults {
			t.Errorf("%s: got %v, want the defaults %s", raw, got, defaults)
		}
	}
	want := model.DefaultDNSEntrySettings()
	want.Enabled = false
	want.CheckIntervalSeconds = 120
	want.MaxTotal = 256 // clamped
	got := dnsEntrySettingsFromBackup(json.RawMessage(`{"enabled": false, "check_interval_seconds": 120, "max_total": 999}`))
	if got != marshal(want) {
		t.Errorf("got %v, want %s", got, marshal(want))
	}
}

// The UPDATE writes the tunables as $62, a JSON string. An older backup, or
// one with null there, passes nil so COALESCE keeps the live value.
func TestImportSystemSettingsRestoresDNSEntrySettings(t *testing.T) {
	want := model.DefaultDNSEntrySettings()
	want.Enabled = false
	wantJSON, _ := json.Marshal(want)

	for _, tc := range []struct {
		raw  json.RawMessage
		want string
	}{
		{json.RawMessage(`{"enabled":false}`), string(wantJSON)},
		{nil, "<nil>"},
		{json.RawMessage(`null`), "<nil>"},
	} {
		repo, tx, mock := beginMockTx(t)
		var got string
		args := make([]driver.Value, 62)
		for i := range args {
			args[i] = sqlmock.AnyArg()
		}
		args[61] = capture{&got}
		mock.ExpectQuery(`SELECT created_at FROM system_settings`).
			WillReturnRows(sqlmock.NewRows([]string{"created_at"}).AddRow(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)))
		mock.ExpectExec(`dns_entry_settings = COALESCE\(\$62::jsonb, dns_entry_settings\)`).
			WithArgs(args...).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := repo.importSystemSettings(context.Background(), tx, &model.SystemSettingsExport{DNSEntrySettings: tc.raw}); err != nil {
			t.Fatalf("import %q: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("backup %q wrote $62 = %s, want %s", tc.raw, got, tc.want)
		}
	}
}

// The restore audit reads back every name the restored lists use and which
// of them wait for review.
func TestRestoredDNSEntries(t *testing.T) {
	repo, mock := newBackupRepoMock(t)
	mock.ExpectQuery(`LEFT JOIN dns_entry_states`).
		WithArgs(model.DNSStatusNeedsReview).
		WillReturnRows(sqlmock.NewRows([]string{"hostname", "needs_review"}).
			AddRow("office.example.com", false).
			AddRow("partner.example.com", true))
	got, err := repo.RestoredDNSEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := model.DNSRestoreSummary{
		Names:       []string{"office.example.com", "partner.example.com"},
		NeedsReview: []string{"partner.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
}
