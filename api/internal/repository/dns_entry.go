package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// Domain entries (#320). dns_entry_states holds one row per domain name, shared
// by every list that uses the name; the references say where each name is
// used. The DNS entry service reads and writes the rows only through this
// file, and the backup import merges restored records through the same
// transaction view (newDNSEntryTx).

// DNSEntryTx is the transaction-scoped view the DNS service uses; the service
// tests fake it. GetStates reads the rows FOR UPDATE, so a state transition
// holds its names until it commits: MarkApplied waits for it and then raises
// what the transition committed.
type DNSEntryTx interface {
	ListReferences(ctx context.Context) ([]model.DNSReference, error)
	GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) // nil = all rows; SELECT … FOR UPDATE
	UpsertState(ctx context.Context, st model.DNSEntryState) error
	DeleteState(ctx context.Context, hostname string) error
}

// DNSEntryRepository reads and writes dns_entry_states.
type DNSEntryRepository struct {
	db *sql.DB
}

func NewDNSEntryRepository(db *sql.DB) *DNSEntryRepository {
	return &DNSEntryRepository{db: db}
}

// dnsEntryQuerier is what the reads need: *sql.DB outside a transaction,
// *sql.Tx inside one.
type dnsEntryQuerier interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// dnsReferenceSources selects one row per use of a domain name: scope, name,
// owner id, owner name. A name in a row is in use whether or not the list,
// its host or the feature is enabled. The owner of an access list is the
// list; of a host's exception list the host, named by its first domain; of
// a global exception list "global"; the trusted list has none. The
// exception lists keep their names in text[] columns without a CHECK, so
// those branches take only elements in the characters of a stored name,
// and listDNSReferences checks the rest.
const dnsReferenceSources = `
	SELECT 'acl:' || i.access_list_id::text, i.hostname, l.id::text, l.name
	FROM access_list_items i JOIN access_lists l ON l.id = i.access_list_id
	WHERE i.hostname IS NOT NULL
	UNION ALL
	SELECT 'uri:' || u.proxy_host_id::text, n.name, u.proxy_host_id::text, COALESCE(h.domain_names[1], '')
	FROM uri_blocks u LEFT JOIN proxy_hosts h ON h.id = u.proxy_host_id
	CROSS JOIN LATERAL unnest(u.exception_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'uri:global', n.name, 'global', ''
	FROM global_uri_blocks g CROSS JOIN LATERAL unnest(g.exception_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'prio:' || r.proxy_host_id::text, n.name, r.proxy_host_id::text, COALESCE(h.domain_names[1], '')
	FROM geo_restrictions r LEFT JOIN proxy_hosts h ON h.id = r.proxy_host_id
	CROSS JOIN LATERAL unnest(r.allowed_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'prio:global', n.name, 'global', ''
	FROM global_geo_restrictions g CROSS JOIN LATERAL unnest(g.allowed_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'rl:' || r.proxy_host_id::text, n.name, r.proxy_host_id::text, COALESCE(h.domain_names[1], '')
	FROM rate_limits r LEFT JOIN proxy_hosts h ON h.id = r.proxy_host_id
	CROSS JOIN LATERAL unnest(r.whitelist_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'rl:global', n.name, 'global', ''
	FROM global_rate_limits g CROSS JOIN LATERAL unnest(g.whitelist_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'
	UNION ALL
	SELECT 'trusted', n.name, '', ''
	FROM system_settings s CROSS JOIN LATERAL unnest(s.global_trusted_hostnames) AS n(name)
	WHERE n.name ~ '^[a-z0-9.-]{1,253}$'`

const dnsReferencesQuery = dnsReferenceSources + `
	ORDER BY 1, 2`

// dnsEntryStateColumns are the columns UpsertState writes, in the order of
// dnsEntryStateArgs. dnsEntryStateSelect reads the same columns in the same
// order, then created_at and updated_at, which only the database sets.
const dnsEntryStateColumns = `hostname, status, review_reason, disabled, unused_since,
	published, last_applied, empty_cause, generation, applied_generation, revoke_pending_since,
	candidate, candidate_seen, replace_open,
	v4_state, v4_code, v4_observed, v4_answer_at, v4_notfound,
	v6_state, v6_code, v6_observed, v6_answer_at, v6_notfound,
	canonical_name, canonical_seen, warnings, change_times, last_checked_at, last_changed_at`

const dnsEntryStateSelect = `SELECT ` + dnsEntryStateColumns + `, created_at, updated_at FROM dns_entry_states`

// dnsEntryStateUpsert writes a whole row: a new name is inserted, a known one
// has every column but its key and created_at replaced.
const dnsEntryStateUpsert = `
	INSERT INTO dns_entry_states (` + dnsEntryStateColumns + `)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
		$16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
	ON CONFLICT (hostname) DO UPDATE SET
		status = EXCLUDED.status, review_reason = EXCLUDED.review_reason, disabled = EXCLUDED.disabled,
		unused_since = EXCLUDED.unused_since, published = EXCLUDED.published,
		last_applied = EXCLUDED.last_applied, empty_cause = EXCLUDED.empty_cause,
		generation = EXCLUDED.generation, applied_generation = EXCLUDED.applied_generation,
		revoke_pending_since = EXCLUDED.revoke_pending_since,
		candidate = EXCLUDED.candidate, candidate_seen = EXCLUDED.candidate_seen,
		replace_open = EXCLUDED.replace_open,
		v4_state = EXCLUDED.v4_state, v4_code = EXCLUDED.v4_code, v4_observed = EXCLUDED.v4_observed,
		v4_answer_at = EXCLUDED.v4_answer_at, v4_notfound = EXCLUDED.v4_notfound,
		v6_state = EXCLUDED.v6_state, v6_code = EXCLUDED.v6_code, v6_observed = EXCLUDED.v6_observed,
		v6_answer_at = EXCLUDED.v6_answer_at, v6_notfound = EXCLUDED.v6_notfound,
		canonical_name = EXCLUDED.canonical_name, canonical_seen = EXCLUDED.canonical_seen,
		warnings = EXCLUDED.warnings, change_times = EXCLUDED.change_times,
		last_checked_at = EXCLUDED.last_checked_at, last_changed_at = EXCLUDED.last_changed_at,
		updated_at = now()`

// dnsEntryMarkApplied raises one name's applied generation, never past the
// row's generation, and once it reaches the row's generation clears the
// pending revocation. A row it would not change is left alone.
const dnsEntryMarkApplied = `
	UPDATE dns_entry_states SET
		applied_generation = LEAST(GREATEST(applied_generation, $2), generation),
		revoke_pending_since = CASE WHEN LEAST(GREATEST(applied_generation, $2), generation) >= generation THEN NULL ELSE revoke_pending_since END,
		updated_at = now()
	WHERE hostname = $1 AND (applied_generation < LEAST($2, generation) OR revoke_pending_since IS NOT NULL)`

// dnsSmallintMax is the largest value of the smallint counters
// (candidate_seen, v4_notfound, v6_notfound).
const dnsSmallintMax = 32767

// ListReferences returns every use of a domain name, ordered by scope and
// name. A name in a list no host uses is still a use.
func (r *DNSEntryRepository) ListReferences(ctx context.Context) ([]model.DNSReference, error) {
	return listDNSReferences(ctx, r.db)
}

// GetStates returns the rows of names (nil: every row; empty: none), keyed by
// name, without locking them. A name without a row is absent from the map.
func (r *DNSEntryRepository) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	return getDNSEntryStates(ctx, r.db, names, false)
}

// WithTx runs fn in one transaction and commits when fn returns nil. An error
// from fn, or a panic, rolls it back, so no row lock outlives the call.
func (r *DNSEntryRepository) WithTx(ctx context.Context, fn func(tx DNSEntryTx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(newDNSEntryTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit domain entry states: %w", err)
	}
	return nil
}

// MarkApplied records, per name, the generation a reload nginx accepted has
// read. It never lowers applied_generation and never raises it past the
// row's generation: files an earlier row of the same name left can carry
// higher generations, and a reload that read them says nothing about this
// row. It clears revoke_pending_since once the applied generation reaches
// the row's generation: nginx no longer allows any revoked address of that
// name. Names without a row are skipped. Each name is one statement outside a
// transaction, so it holds one row lock at a time and cannot deadlock with a
// state transaction holding rows FOR UPDATE: it waits for that transaction
// and then applies GREATEST to what it committed.
func (r *DNSEntryRepository) MarkApplied(ctx context.Context, applied map[string]int64) error {
	names := make([]string, 0, len(applied))
	for name := range applied {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := r.db.ExecContext(ctx, dnsEntryMarkApplied, name, applied[name]); err != nil {
			return fmt.Errorf("failed to record the applied generation of %s: %w", name, err)
		}
	}
	return nil
}

// dnsEntryTx is the DNSEntryTx of one *sql.Tx.
type dnsEntryTx struct {
	tx *sql.Tx
}

// newDNSEntryTx returns the state view of tx. WithTx hands it to its
// callback; the backup import uses it inside ImportAllData's transaction.
func newDNSEntryTx(tx *sql.Tx) DNSEntryTx {
	return &dnsEntryTx{tx: tx}
}

func (t *dnsEntryTx) ListReferences(ctx context.Context) ([]model.DNSReference, error) {
	return listDNSReferences(ctx, t.tx)
}

// GetStates is the repository's GetStates with the rows locked FOR UPDATE
// until the transaction ends.
func (t *dnsEntryTx) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	return getDNSEntryStates(ctx, t.tx, names, true)
}

// UpsertState writes st whole: every column takes st's value. created_at is
// set by the database on insert and kept on update, updated_at is the time
// of the write; st.CreatedAt and st.UpdatedAt are not written.
func (t *dnsEntryTx) UpsertState(ctx context.Context, st model.DNSEntryState) error {
	if _, err := t.tx.ExecContext(ctx, dnsEntryStateUpsert, dnsEntryStateArgs(st)...); err != nil {
		return fmt.Errorf("failed to save the domain entry state of %s: %w", st.Hostname, err)
	}
	return nil
}

func (t *dnsEntryTx) DeleteState(ctx context.Context, hostname string) error {
	if _, err := t.tx.ExecContext(ctx, `DELETE FROM dns_entry_states WHERE hostname = $1`, hostname); err != nil {
		return fmt.Errorf("failed to delete the domain entry state of %s: %w", hostname, err)
	}
	return nil
}

func listDNSReferences(ctx context.Context, q dnsEntryQuerier) ([]model.DNSReference, error) {
	rows, err := q.QueryContext(ctx, dnsReferencesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to read domain entry references: %w", err)
	}
	defer rows.Close()
	var refs []model.DNSReference
	for rows.Next() {
		var ref model.DNSReference
		if err := rows.Scan(&ref.Scope, &ref.Name, &ref.OwnerID, &ref.OwnerName); err != nil {
			return nil, fmt.Errorf("failed to read a domain entry reference: %w", err)
		}
		if usableDNSReference(ref) {
			refs = append(refs, ref)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate domain entry references: %w", err)
	}
	return refs, nil
}

// dnsReferencesSkipped holds the references usableDNSReference has logged,
// so each is logged once per process, not at every check.
var dnsReferencesSkipped sync.Map

// usableDNSReference reports whether a reference has a scope ParseDNSScope
// reads and a name ValidateDNSName accepts, and logs one it leaves out. The
// saves refuse other names, but a row can come from elsewhere (an older
// version, a hand-edited backup, SQL), and a name outside the CHECK on
// dns_entry_states.hostname would fail the transaction of every check.
func usableDNSReference(ref model.DNSReference) bool {
	reason := "its list is not one domain entries know"
	if _, _, ok := model.ParseDNSScope(ref.Scope); ok {
		err := model.ValidateDNSName(ref.Name)
		if err == nil {
			return true
		}
		reason = err.Error()
	}
	if _, seen := dnsReferencesSkipped.LoadOrStore(ref.Scope+"\x00"+ref.Name, struct{}{}); !seen {
		log.Printf("[DNSEntries] WARN: %.80q in %.80q is left out of the domain entries: %s", ref.Name, ref.Scope, reason)
	}
	return false
}

// getDNSEntryStates reads the rows of names, or every row when names is nil;
// an empty, non-nil names reads nothing and sends no query. lock adds FOR
// UPDATE (inside a transaction only).
func getDNSEntryStates(ctx context.Context, q dnsEntryQuerier, names []string, lock bool) (map[string]model.DNSEntryState, error) {
	out := make(map[string]model.DNSEntryState)
	if names != nil && len(names) == 0 {
		return out, nil
	}
	query := dnsEntryStateSelect
	var args []interface{}
	if names != nil {
		query += ` WHERE hostname = ANY($1)`
		args = append(args, pq.StringArray(names))
	}
	query += ` ORDER BY hostname`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to read domain entry states: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		st, err := scanDNSEntryState(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to read a domain entry state: %w", err)
		}
		out[st.Hostname] = st
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate domain entry states: %w", err)
	}
	return out, nil
}

// dnsEntryStateArgs returns st as the arguments of dnsEntryStateUpsert, in
// the order of dnsEntryStateColumns. "" and nil are NULL in the nullable
// columns. The NOT NULL arrays (published, last_applied, warnings,
// change_times) are written as '{}' when empty; candidate and the observed
// sets keep nil as NULL and an empty slice as '{}'. The smallint counters
// saturate: a name that stays not found for weeks must not fail every save.
func dnsEntryStateArgs(st model.DNSEntryState) []interface{} {
	return []interface{}{
		st.Hostname,
		st.Status,
		nullString(st.ReviewReason),
		st.Disabled,
		dnsTimeArg(st.UnusedSince),
		dnsTextArray(st.Published),
		dnsTextArray(st.LastApplied),
		nullString(st.EmptyCause),
		st.Generation,
		st.AppliedGeneration,
		dnsTimeArg(st.RevokePendingSince),
		pq.StringArray(st.Candidate),
		dnsSmallint(st.CandidateSeen),
		st.ReplaceOpen,
		nullString(st.V4.State),
		nullString(st.V4.Code),
		pq.StringArray(st.V4.Observed),
		dnsTimeArg(st.V4.AnswerAt),
		dnsSmallint(st.V4.NotFound),
		nullString(st.V6.State),
		nullString(st.V6.Code),
		pq.StringArray(st.V6.Observed),
		dnsTimeArg(st.V6.AnswerAt),
		dnsSmallint(st.V6.NotFound),
		nullString(st.CanonicalName),
		nullString(st.CanonicalSeen),
		dnsTextArray(st.Warnings),
		dnsUnixSeconds(st.ChangeTimes),
		dnsTimeArg(st.LastCheckedAt),
		dnsTimeArg(st.LastChangedAt),
	}
}

// scanDNSEntryState reads one dnsEntryStateSelect row. NULL is "" or nil.
// An empty NOT NULL array comes back nil; candidate and the observed sets
// come back as they were written (NULL nil, '{}' empty).
func scanDNSEntryState(s interface {
	Scan(dest ...interface{}) error
}) (model.DNSEntryState, error) {
	var st model.DNSEntryState
	var reviewReason, emptyCause, v4State, v4Code, v6State, v6Code, canonicalName, canonicalSeen sql.NullString
	var unusedSince, revokePendingSince, v4AnswerAt, v6AnswerAt, lastCheckedAt, lastChangedAt sql.NullTime
	var published, lastApplied, candidate, v4Observed, v6Observed, warnings pq.StringArray
	var changeTimes pq.Int64Array
	if err := s.Scan(
		&st.Hostname, &st.Status, &reviewReason, &st.Disabled, &unusedSince,
		&published, &lastApplied, &emptyCause, &st.Generation, &st.AppliedGeneration, &revokePendingSince,
		&candidate, &st.CandidateSeen, &st.ReplaceOpen,
		&v4State, &v4Code, &v4Observed, &v4AnswerAt, &st.V4.NotFound,
		&v6State, &v6Code, &v6Observed, &v6AnswerAt, &st.V6.NotFound,
		&canonicalName, &canonicalSeen, &warnings, &changeTimes, &lastCheckedAt, &lastChangedAt,
		&st.CreatedAt, &st.UpdatedAt,
	); err != nil {
		return model.DNSEntryState{}, err
	}
	st.ReviewReason = reviewReason.String
	st.UnusedSince = nullTimePtr(unusedSince)
	st.Published = dnsNilIfEmpty(published)
	st.LastApplied = dnsNilIfEmpty(lastApplied)
	st.EmptyCause = emptyCause.String
	st.RevokePendingSince = nullTimePtr(revokePendingSince)
	st.Candidate = []string(candidate)
	st.V4.State, st.V4.Code = v4State.String, v4Code.String
	st.V4.Observed = []string(v4Observed)
	st.V4.AnswerAt = nullTimePtr(v4AnswerAt)
	st.V6.State, st.V6.Code = v6State.String, v6Code.String
	st.V6.Observed = []string(v6Observed)
	st.V6.AnswerAt = nullTimePtr(v6AnswerAt)
	st.CanonicalName = canonicalName.String
	st.CanonicalSeen = canonicalSeen.String
	st.Warnings = dnsNilIfEmpty(warnings)
	st.ChangeTimes = dnsTimesFromUnix(changeTimes)
	st.LastCheckedAt = nullTimePtr(lastCheckedAt)
	st.LastChangedAt = nullTimePtr(lastChangedAt)
	return st, nil
}

// dnsTimeArg is t as a statement argument: NULL when nil.
func dnsTimeArg(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

// dnsTextArray is a as the value of a NOT NULL text[] column: '{}' when
// empty, never NULL.
func dnsTextArray(a []string) pq.StringArray {
	if a == nil {
		return pq.StringArray{}
	}
	return pq.StringArray(a)
}

func dnsNilIfEmpty(a pq.StringArray) []string {
	if len(a) == 0 {
		return nil
	}
	return []string(a)
}

// dnsSmallint clamps n into a smallint column's range (no counter is
// negative).
func dnsSmallint(n int) int {
	return min(max(n, 0), dnsSmallintMax)
}

// dnsUnixSeconds is change_times as stored: bigint[] of Unix seconds, since
// lib/pq cannot scan a timestamptz[] into []time.Time. Never NULL.
func dnsUnixSeconds(ts []time.Time) pq.Int64Array {
	out := make(pq.Int64Array, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Unix())
	}
	return out
}

// dnsTimesFromUnix reads change_times back, in UTC; empty is nil.
func dnsTimesFromUnix(secs pq.Int64Array) []time.Time {
	if len(secs) == 0 {
		return nil
	}
	out := make([]time.Time, 0, len(secs))
	for _, s := range secs {
		out = append(out, time.Unix(s, 0).UTC())
	}
	return out
}
