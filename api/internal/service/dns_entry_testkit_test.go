package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// Fakes shared by the DNS entry service tests. No database,
// no nginx, no network: names resolve from dnsTestLookuper only.

const (
	dnsTestListA = "11111111-1111-4111-8111-111111111111"
	dnsTestListB = "22222222-2222-4222-8222-222222222222"
)

var dnsTestStart = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// dnsTestClock is a settable clock.
type dnsTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *dnsTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *dnsTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// dnsCopyState deep-copies a row so a fake never shares slices with the service.
func dnsCopyState(st model.DNSEntryState) model.DNSEntryState {
	cp := func(in []string) []string {
		if in == nil {
			return nil
		}
		return append([]string{}, in...)
	}
	st.Published = cp(st.Published)
	st.LastApplied = cp(st.LastApplied)
	st.Candidate = cp(st.Candidate)
	st.Warnings = cp(st.Warnings)
	st.V4.Observed = cp(st.V4.Observed)
	st.V6.Observed = cp(st.V6.Observed)
	if st.ChangeTimes != nil {
		st.ChangeTimes = append([]time.Time{}, st.ChangeTimes...)
	}
	return st
}

// dnsTestStore is an in-memory dnsStateStore. WithTx holds the store for the
// whole transaction and works on a copy it commits only when fn succeeds:
// like the repository's SELECT … FOR UPDATE, MarkApplied waits for it.
type dnsTestStore struct {
	mu     sync.Mutex
	rows   map[string]model.DNSEntryState
	refs   []model.DNSReference
	marked []map[string]int64
	// beforeTx runs (unlocked) when a transaction starts: a test changes the
	// references there to race a save against a tick.
	beforeTx func(f *dnsTestStore)
}

func newDNSTestStore() *dnsTestStore {
	return &dnsTestStore{rows: make(map[string]model.DNSEntryState)}
}

func (f *dnsTestStore) setRefs(refs ...model.DNSReference) {
	f.mu.Lock()
	f.refs = append([]model.DNSReference(nil), refs...)
	f.mu.Unlock()
}

func (f *dnsTestStore) put(st model.DNSEntryState) {
	f.mu.Lock()
	f.rows[st.Hostname] = dnsCopyState(st)
	f.mu.Unlock()
}

func (f *dnsTestStore) row(name string) (model.DNSEntryState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.rows[name]
	return dnsCopyState(st), ok
}

func (f *dnsTestStore) ListReferences(ctx context.Context) ([]model.DNSReference, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.DNSReference(nil), f.refs...), nil
}

func (f *dnsTestStore) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return dnsTestSelect(f.rows, names), nil
}

func (f *dnsTestStore) WithTx(ctx context.Context, fn func(tx repository.DNSEntryTx) error) error {
	if f.beforeTx != nil {
		f.beforeTx(f)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	work := make(map[string]model.DNSEntryState, len(f.rows))
	for k, v := range f.rows {
		work[k] = dnsCopyState(v)
	}
	tx := &dnsTestTx{rows: work, refs: append([]model.DNSReference(nil), f.refs...)}
	if err := fn(tx); err != nil {
		return err
	}
	f.rows = tx.rows
	return nil
}

// MarkApplied does what the repository's statement does: it raises the
// applied generation, never past the row's generation, and clears the
// revocation once that reaches the row's generation; a row it would not
// change is left alone.
func (f *dnsTestStore) MarkApplied(ctx context.Context, applied map[string]int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]int64, len(applied))
	for name, gen := range applied {
		cp[name] = gen
		st, ok := f.rows[name]
		if !ok || (st.AppliedGeneration >= min(gen, st.Generation) && st.RevokePendingSince == nil) {
			continue
		}
		st.AppliedGeneration = min(max(st.AppliedGeneration, gen), st.Generation)
		if st.AppliedGeneration >= st.Generation {
			st.RevokePendingSince = nil
		}
		f.rows[name] = st
	}
	f.marked = append(f.marked, cp)
	return nil
}

func dnsTestSelect(rows map[string]model.DNSEntryState, names []string) map[string]model.DNSEntryState {
	out := make(map[string]model.DNSEntryState)
	if names == nil {
		for k, v := range rows {
			out[k] = dnsCopyState(v)
		}
		return out
	}
	for _, n := range names {
		if v, ok := rows[n]; ok {
			out[n] = dnsCopyState(v)
		}
	}
	return out
}

type dnsTestTx struct {
	rows map[string]model.DNSEntryState
	refs []model.DNSReference
}

func (t *dnsTestTx) ListReferences(ctx context.Context) ([]model.DNSReference, error) {
	return append([]model.DNSReference(nil), t.refs...), nil
}

func (t *dnsTestTx) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	return dnsTestSelect(t.rows, names), nil
}

func (t *dnsTestTx) UpsertState(ctx context.Context, st model.DNSEntryState) error {
	t.rows[st.Hostname] = dnsCopyState(st)
	return nil
}

func (t *dnsTestTx) DeleteState(ctx context.Context, hostname string) error {
	delete(t.rows, hostname)
	return nil
}

// dnsTestFile is one fake include file.
type dnsTestFile struct {
	scope, name string
	gen         int64
	addrs       []string
	header      bool
	mod         time.Time
}

// dnsTestNginx is a fake dnsNginx. Files live in memory, keyed like the real
// directory ("<key><ext>"). ApplyDNSIncludes returns the scripted results in
// order (the last one repeats; none = accepted) and, with hooks set, runs
// BeforeDNSApply (Before when unset) and After the way Manager's applier
// reload does.
type dnsTestNginx struct {
	mu        sync.Mutex
	clock     *dnsTestClock
	files     map[string]dnsTestFile
	ensured   []string
	diskRefs  map[string]bool
	results   []nginx.DNSApplyResult
	applies   int
	hooks     *nginx.ReloadHooks
	taken     bool
	takenCall int
	writeErr  error
	// takenSnaps answers ReloadTakenSince per snapshot; one it does not
	// hold answers taken.
	takenSnaps map[*nginx.ReloadSnapshot]bool
}

func newDNSTestNginx(clock *dnsTestClock) *dnsTestNginx {
	return &dnsTestNginx{clock: clock, files: make(map[string]dnsTestFile)}
}

func (n *dnsTestNginx) WriteDNSIncludeFiles(scope, name string, gen int64, addrs []string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.writeErr != nil {
		return false, n.writeErr
	}
	if _, _, ok := model.ParseDNSScope(scope); !ok || model.ValidateDNSName(name) != nil {
		return false, errors.New("invalid segment")
	}
	changed := false
	for _, ext := range nginx.DNSIncludeExts(scope) {
		k := nginx.DNSIncludeKey(scope, name) + ext
		old, ok := n.files[k]
		if ok && old.header && old.scope == scope && old.name == name && old.gen == gen && dnsSameSet(old.addrs, addrs) {
			continue
		}
		n.files[k] = dnsTestFile{scope: scope, name: name, gen: gen, addrs: dnsSortedUnique(addrs), header: true, mod: n.clock.Now()}
		changed = true
	}
	return changed, nil
}

func (n *dnsTestNginx) ReadDNSIncludeDir() ([]nginx.DNSIncludeFile, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	keys := make([]string, 0, len(n.files))
	for k := range n.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]nginx.DNSIncludeFile, 0, len(keys))
	for _, k := range keys {
		f := n.files[k]
		key, ext := splitDNSIncludeName(k)
		out = append(out, nginx.DNSIncludeFile{Key: key, Ext: ext, Name: f.name, Scope: f.scope, Gen: f.gen,
			HasHeader: f.header, Empty: len(f.addrs) == 0, ModTime: f.mod, Addrs: append([]string(nil), f.addrs...)})
	}
	return out, nil
}

func (n *dnsTestNginx) ScanDNSIncludeReferences() (map[string]bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string]bool, len(n.diskRefs))
	for k, v := range n.diskRefs {
		out[k] = v
	}
	return out, nil
}

func (n *dnsTestNginx) EnsureDNSIncludeFile(key, ext string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.files[key+ext]; !ok {
		n.files[key+ext] = dnsTestFile{mod: n.clock.Now()}
	}
	n.ensured = append(n.ensured, key+ext)
	return nil
}

func (n *dnsTestNginx) ApplyDNSIncludes(ctx context.Context) nginx.DNSApplyResult {
	n.mu.Lock()
	res := nginx.DNSApplyResult{Outcome: "accepted"}
	if len(n.results) > 0 {
		i := n.applies
		if i >= len(n.results) {
			i = len(n.results) - 1
		}
		res = n.results[i]
	}
	n.applies++
	hooks := n.hooks
	n.mu.Unlock()
	if hooks != nil {
		var outcome nginx.ReloadOutcome
		switch res.Outcome {
		case "accepted":
			outcome = nginx.ReloadAccepted
		case "signalled":
			outcome = nginx.ReloadSignalled
		case "unconfirmed":
			outcome = nginx.ReloadUnconfirmed
		case "rejected":
			outcome = nginx.ReloadRejected
		}
		if outcome != "" {
			before := hooks.Before
			if hooks.BeforeDNSApply != nil {
				before = hooks.BeforeDNSApply // the applier's own reload, as Manager signals it
			}
			hooks.After(before(), outcome, res.Snapshot)
		}
	}
	return res
}

func (n *dnsTestNginx) ReloadTakenSince(ctx context.Context, snap *nginx.ReloadSnapshot) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.takenCall++
	if v, ok := n.takenSnaps[snap]; ok {
		return v, nil
	}
	return n.taken, nil
}

func (n *dnsTestNginx) GCDNSIncludeFiles(ctx context.Context, referenced func(scope, name string) bool, minEmptyAge time.Duration) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	removed := 0
	for k, f := range n.files {
		if f.header && len(f.addrs) == 0 && !referenced(f.scope, f.name) && n.clock.Now().Sub(f.mod) > minEmptyAge {
			delete(n.files, k)
			removed++
		}
	}
	return removed, nil
}

// file returns the addresses of a segment's .allow file; ok is false when the
// file does not exist.
func (n *dnsTestNginx) file(scope, name string) ([]string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f, ok := n.files[nginx.DNSIncludeKey(scope, name)+".allow"]
	return append([]string(nil), f.addrs...), ok
}

func (n *dnsTestNginx) putFile(scope, name string, gen int64, addrs ...string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.files[nginx.DNSIncludeKey(scope, name)+".allow"] = dnsTestFile{scope: scope, name: name, gen: gen, addrs: addrs, header: true, mod: n.clock.Now()}
}

func (n *dnsTestNginx) applyCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.applies
}

// dnsTestSettings answers the system settings row (dns_entry_settings and
// global_trusted_ips only).
type dnsTestSettings struct {
	mu      sync.Mutex
	raw     string
	err     error
	trusted string
}

func (f *dnsTestSettings) Get(ctx context.Context) (*model.SystemSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &model.SystemSettings{DNSEntrySettings: json.RawMessage(f.raw), GlobalTrustedIPs: f.trusted}, nil
}

func (f *dnsTestSettings) set(raw string, err error) {
	f.mu.Lock()
	f.raw, f.err = raw, err
	f.mu.Unlock()
}

// dnsTestLookuper answers from maps; a name with no entry is NXDOMAIN. CNAME
// answers the name itself unless cname says otherwise; cnameSeq answers the
// next CNAME lookups in order (before, after) to make them disagree.
type dnsTestLookuper struct {
	mu       sync.Mutex
	v4, v6   map[string][]string
	err4     map[string]error
	err6     map[string]error
	cname    map[string]string
	cnameSeq map[string][]string
	lookups  int
}

func newDNSTestLookuper() *dnsTestLookuper {
	return &dnsTestLookuper{v4: map[string][]string{}, v6: map[string][]string{}, err4: map[string]error{},
		err6: map[string]error{}, cname: map[string]string{}, cnameSeq: map[string][]string{}}
}

func (l *dnsTestLookuper) set(name string, addrs ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.v4[name], l.v6[name] = nil, nil
	delete(l.err4, name)
	delete(l.err6, name)
	for _, a := range addrs {
		if netip.MustParseAddr(a).Is4() {
			l.v4[name] = append(l.v4[name], a)
		} else {
			l.v6[name] = append(l.v6[name], a)
		}
	}
}

func (l *dnsTestLookuper) fail(name string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err4[name], l.err6[name] = err, err
}

func (l *dnsTestLookuper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lookups++
	name := strings.TrimSuffix(host, ".")
	errs, addrs := l.err4, l.v4
	if network == "ip6" {
		errs, addrs = l.err6, l.v6
	}
	if err := errs[name]; err != nil {
		return nil, err
	}
	list := addrs[name]
	if len(list) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, 0, len(list))
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func (l *dnsTestLookuper) LookupCNAME(ctx context.Context, host string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	name := strings.TrimSuffix(host, ".")
	if seq := l.cnameSeq[name]; len(seq) > 0 {
		l.cnameSeq[name] = seq[1:]
		return seq[0] + ".", nil
	}
	if c, ok := l.cname[name]; ok {
		return c + ".", nil
	}
	return host, nil
}

// dnsTestEvents records every event.
type dnsTestEvents struct {
	mu       sync.Mutex
	changes  []string // "name from>to" or "name from>to review:<reason>"
	reviews  []string
	closed   []string // "name confirmed" / "name quiet"
	applies  []dnsAppliedChange
	failing  []string // "true:<outcome>" / "false:<outcome>"
	alerts   []dnsApplyAlert
	closeErr error
}

func (e *dnsTestEvents) nameChanged(ctx context.Context, name string, eff dnsentry.Effects, st model.DNSEntryState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := name + " " + eff.FromStatus + ">" + eff.ToStatus
	if eff.EnteredReview != "" {
		v += " review:" + eff.EnteredReview
	}
	e.changes = append(e.changes, v)
}

func (e *dnsTestEvents) reviewAlert(ctx context.Context, name string, st model.DNSEntryState, scopes int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reviews = append(e.reviews, name)
	return nil
}

func (e *dnsTestEvents) reviewClosed(ctx context.Context, name string, confirmed bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closeErr != nil {
		return e.closeErr
	}
	how := "quiet"
	if confirmed {
		how = "confirmed"
	}
	e.closed = append(e.closed, name+" "+how)
	return nil
}

func (e *dnsTestEvents) applied(ctx context.Context, name string, before, after []string, gen int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applies = append(e.applies, dnsAppliedChange{name: name, before: before, after: after, gen: gen})
}

func (e *dnsTestEvents) applyFailing(ctx context.Context, failing bool, res nginx.DNSApplyResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if failing {
		e.failing = append(e.failing, "true:"+res.Outcome)
	} else {
		e.failing = append(e.failing, "false:"+res.Outcome)
	}
}

func (e *dnsTestEvents) applyAlert(ctx context.Context, a dnsApplyAlert) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = append(e.alerts, a)
	return nil
}

func (e *dnsTestEvents) snapshot() dnsTestEvents {
	e.mu.Lock()
	defer e.mu.Unlock()
	return dnsTestEvents{
		changes: append([]string(nil), e.changes...),
		reviews: append([]string(nil), e.reviews...),
		closed:  append([]string(nil), e.closed...),
		applies: append([]dnsAppliedChange(nil), e.applies...),
		failing: append([]string(nil), e.failing...),
		alerts:  append([]dnsApplyAlert(nil), e.alerts...),
	}
}

// dnsTestPolicy is the address policy without the documentation rows, so
// 192.0.2.x, 198.51.100.x, 203.0.113.x and 2001:db8:: pass as public here.
// Production refuses them as reserved.
func dnsTestPolicy() *model.AddressPolicy {
	docs := map[string]bool{"192.0.2.0/24": true, "198.51.100.0/24": true, "203.0.113.0/24": true, "2001:db8::/32": true}
	var rules []model.AddressPolicyRule
	for _, r := range model.DefaultAddressPolicyRules() {
		if !docs[r.Prefix.String()] {
			rules = append(rules, r)
		}
	}
	return model.NewAddressPolicy(rules)
}

// dnsTestRig is one service with its fakes.
type dnsTestRig struct {
	svc      *DNSEntryService
	store    *dnsTestStore
	nginx    *dnsTestNginx
	settings *dnsTestSettings
	lookup   *dnsTestLookuper
	events   *dnsTestEvents
	clock    *dnsTestClock
}

// newDNSTestRig builds the service with the default settings, the test
// policy and hooks that run like Manager's (every scripted apply calls them).
func newDNSTestRig(t *testing.T) *dnsTestRig {
	t.Helper()
	clock := &dnsTestClock{t: dnsTestStart}
	r := &dnsTestRig{
		store:    newDNSTestStore(),
		nginx:    newDNSTestNginx(clock),
		settings: &dnsTestSettings{raw: `{}`},
		lookup:   newDNSTestLookuper(),
		events:   &dnsTestEvents{},
		clock:    clock,
	}
	r.svc = NewDNSEntryService(DNSEntryDeps{States: r.store, Settings: r.settings, Nginx: r.nginx},
		DNSEntryOptions{Policy: dnsTestPolicy(), Lookuper: r.lookup, Now: clock.Now,
			PerLookupTimeout: time.Second, SaveResolveTimeout: time.Second})
	r.svc.events = r.events
	hooks := r.svc.ReloadHooks()
	r.nginx.hooks = &hooks
	t.Cleanup(r.svc.bg.Wait)
	return r
}

// settle waits for the work the reload hooks handed to goroutines.
func (r *dnsTestRig) settle() { r.svc.bg.Wait() }

func dnsACL(list string) string { return model.AccessListDNSScope(list) }

func dnsRef(list, name string) model.DNSReference {
	return model.DNSReference{Scope: dnsACL(list), Name: name, OwnerID: list, OwnerName: "list " + list[:4]}
}

// dnsOKRow is a used name published with addrs and applied.
func dnsOKRow(name string, gen int64, addrs ...string) model.DNSEntryState {
	at := dnsTestStart.Add(-time.Minute)
	st := model.DNSEntryState{
		Hostname: name, Status: model.DNSStatusOK, Published: addrs, LastApplied: addrs,
		Generation: gen, AppliedGeneration: gen, Candidate: addrs, CanonicalName: name, CanonicalSeen: name,
		LastCheckedAt: &at, LastChangedAt: &at, CreatedAt: at, UpdatedAt: at,
	}
	var v4, v6 []string
	for _, a := range addrs {
		if netip.MustParseAddr(a).Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	if len(v4) > 0 {
		st.V4 = model.DNSFamilyState{State: "ok", Observed: v4, AnswerAt: &at}
	} else {
		st.V4 = model.DNSFamilyState{State: "notfound", Code: "not_found", AnswerAt: &at, NotFound: 1}
	}
	if len(v6) > 0 {
		st.V6 = model.DNSFamilyState{State: "ok", Observed: v6, AnswerAt: &at}
	} else {
		st.V6 = model.DNSFamilyState{State: "notfound", Code: "not_found", AnswerAt: &at, NotFound: 1}
	}
	return st
}

func dnsEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return dnsSameSet(a, b) && len(a) == len(b)
}

// dnsAllows reports whether the bookkeeping says nginx may allow addr through
// a file of scope: an address a file holds now — published, maybe not yet
// taken by nginx — or one removed that nginx may not have dropped yet. The
// reload tokens, and with them the record the fail2ban gate reads, are made
// from it.
func (s *DNSEntryService) dnsAllows(scope, addr string) bool {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	for _, e := range s.disk {
		if e.Scope == scope {
			for _, a := range e.Addrs {
				if a == addr {
					return true
				}
			}
		}
	}
	for _, e := range s.pendingRevoke {
		if e.Scope == scope {
			for _, a := range e.Addrs {
				if a == addr {
					return true
				}
			}
		}
	}
	return false
}
