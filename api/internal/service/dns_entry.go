package service

import (
	"context"
	"log"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// DNSEntryService keeps the domain names in access lists (#320) applied. It
// resolves them (Tick), runs each name through the state machine in
// internal/dnsentry, writes one include file per (scope, name) holding the
// addresses the name may use, and has nginx read them
// (Manager.ApplyDNSIncludes). The database decides what a file holds and a
// file never holds more than that: a failed apply leaves the
// files as they are and is retried.
//
// Locks, taken only in this order:
//   - dnsMu: state transitions, file writes, disk-table updates. Never held
//     while resolving, while applying or while nginx's lock is taken.
//   - applyMu: one apply run at a time and the retry state. Never taken while
//     dnsMu is held. Held while ApplyDNSIncludes takes nginx's lock.
//   - diskMu: a leaf. disk, pendingRevoke, nginxView, postHocs, applyView and
//     lastReload. The reload hooks take it inside nginx's lock.
//
// alertMu and reviewMu guard the alert mirrors; nothing but the event calls
// runs under them, and under alertMu the read of the rows the apply alerts
// are decided from.
type DNSEntryService struct {
	states   dnsStateStore // a dnsFloorStore around DNSEntryDeps.States
	settings dnsSettingsReader
	global   dnsGlobalReader
	hosts    dnsHostReader
	builder  dnsConfigBuilder
	selfIPs  dnsSelfIPReader
	bans     dnsBanReader
	nginx    dnsNginx
	audit    dnsAuditor
	syslog   dnsSystemLogWriter
	notifier dnsNotifier
	events   dnsEvents

	envDisabled bool
	envInterval time.Duration
	policy      *model.AddressPolicy
	lookuper    dnsentry.Lookuper
	now         func() time.Time
	perLookup   time.Duration
	saveResolve time.Duration

	wake chan struct{}
	bg   sync.WaitGroup // work the reload hooks hand off; tests wait on it
	logs dnsLogOnce

	settingsMu sync.Mutex
	lastGood   *model.DNSEntrySettings

	tickMu sync.Mutex // one Tick at a time
	lastGC time.Time  // under tickMu

	dnsMu sync.Mutex

	applyMu sync.Mutex
	retry   dnsRetryState // under applyMu

	diskMu        sync.Mutex
	disk          map[string]dnsDiskEntry   // segment key → what this process last wrote, or found when its first write failed
	pendingRevoke map[string]dnsRevokeEntry // segment key → addresses removed that nginx may still allow
	nginxView     map[string]dnsViewEntry   // name → the addresses nginx is known to run (absent = unknown)
	viewSeeded    bool
	postHocs      []*dnsPostHoc // reloads whose acceptance is still to be seen, oldest first
	takenSeq      int64         // the newest reload token nginx is known to have read
	applyView     dnsApplyView  // the retry state as readers see it
	lastReload    time.Time     // last reload the applier signalled; zero = none since start
	tokenSeq      int64

	alertMu      sync.Mutex
	revokeMirror dnsAlertMirror
	applyMirror  dnsAlertMirror

	reviewMu        sync.Mutex
	reviewAnnounced map[string]bool // names in review already announced (empty after a restart)
	reviewClosing   map[string]bool // closes that failed, retried each tick (value: confirmed)

	hostIdx         atomic.Pointer[dnsHostIndex] // rebuilt by Tick, SyncScope and every mark, read lock-free
	hostIdxMarks    atomic.Int64                 // marks so far: an index whose build began before the latest is stale
	hostIdxBuilding atomic.Bool                  // a background rebuild runs
}

// DNSEntryOptions are the service's settings that do not come from the
// database. Zero values select the defaults.
type DNSEntryOptions struct {
	EnvDisabled        bool                 // NPG_DNS_ENTRIES_DISABLED parsed once in bootstrap
	EnvInterval        time.Duration        // NPG_DNS_ENTRIES_INTERVAL, 0 = unset, already clamped to [5s, 1h]
	Policy             *model.AddressPolicy // nil → model.DefaultAddressPolicy()
	Lookuper           dnsentry.Lookuper    // nil → dnsentry.SystemLookuper()
	Now                func() time.Time     // nil → time.Now
	PerLookupTimeout   time.Duration        // 0 → 5s
	SaveResolveTimeout time.Duration        // 0 → 3s (SyncScope new names, Confirm)
}

// DNSEntryDeps are the service's collaborators. Bootstrap passes the concrete
// repositories and services named on each field.
type DNSEntryDeps struct {
	States    dnsStateStore      // *repository.DNSEntryRepository
	Settings  dnsSettingsReader  // *repository.SystemSettingsRepository
	Global    dnsGlobalReader    // *repository.GlobalSettingsRepository (enable_ipv6, the ipv6_listen warning)
	Hosts     dnsHostReader      // *repository.ProxyHostRepository
	Builder   dnsConfigBuilder   // *ProxyHostService
	SelfIPs   dnsSelfIPReader    // *repository.DDNSRepository (the self_ip warning)
	Bans      dnsBanReader       // *repository.RateLimitRepository (the banned warning)
	Nginx     dnsNginx           // *nginx.Manager
	Audit     dnsAuditor         // *AuditService
	SystemLog dnsSystemLogWriter // *repository.SystemLogRepository
}

type dnsStateStore interface {
	ListReferences(ctx context.Context) ([]model.DNSReference, error)
	GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) // nil = all rows
	WithTx(ctx context.Context, fn func(tx repository.DNSEntryTx) error) error
	MarkApplied(ctx context.Context, applied map[string]int64) error
}

type dnsSettingsReader interface {
	Get(ctx context.Context) (*model.SystemSettings, error)
}

type dnsGlobalReader interface {
	Get(ctx context.Context) (*model.GlobalSettings, error)
}

type dnsHostReader interface {
	GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error)
}

type dnsConfigBuilder interface {
	BuildConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error)
}

type dnsSelfIPReader interface {
	ListEnabled(ctx context.Context) ([]model.DDNSRecord, error)
}

type dnsBanReader interface {
	GetActiveGlobalBans(ctx context.Context) ([]model.BannedIP, error)
	GetActiveBansForHost(ctx context.Context, proxyHostID string) ([]model.BannedIP, error)
}

// dnsNginx is what the service needs from nginx.Manager. It is its own narrow
// interface: methods added to NginxManager would panic in the fakes that
// embed it.
type dnsNginx interface {
	WriteDNSIncludeFiles(scope, name string, gen int64, addrs []string) (bool, error)
	ReadDNSIncludeDir() ([]nginx.DNSIncludeFile, error)
	ScanDNSIncludeReferences() (map[string]bool, error)
	EnsureDNSIncludeFile(key, ext string) error
	ApplyDNSIncludes(ctx context.Context) nginx.DNSApplyResult
	ReloadTakenSince(ctx context.Context, snap *nginx.ReloadSnapshot) (bool, error)
	GCDNSIncludeFiles(ctx context.Context, referenced func(scope, name string) bool, minEmptyAge time.Duration) (int, error)
}

// dnsAuditor holds the system audit helpers the service's events use.
// The user-facing ones (confirm, apply now, settings) are
// called by the handlers.
type dnsAuditor interface {
	LogDNSEntryApplied(ctx context.Context, name string, before, after []string, gen int64) error
	LogDNSEntryReviewNeeded(ctx context.Context, name, reason string) error
	LogDNSEntryRevokeBlocked(ctx context.Context, blocked bool, outcome, file string, names []string) error
}

type dnsSystemLogWriter interface {
	Create(ctx context.Context, log *repository.SystemLog) error
}

// dnsNotifier has the shape of diskNotifier (disk_guard.go).
type dnsNotifier interface {
	EmitTransition(ctx context.Context, eventKey, subject string, failing bool, detail string, fields map[string]string) error
	ResolveQuietly(ctx context.Context, eventKey, subject string) error
}

// dnsEvents is where the service reports what operators must hear about:
// the dns_entry.review and dns_entry.apply_failed alerts, the
// system audit rows and the system-log and container lines. The service
// decides when — it holds the state that says something changed; the
// implementation decides how: sentences, fields and delivery through
// s.notifier, s.audit and s.syslog. No address goes into an alert and
// no error text of a lookup goes anywhere.
//
// The service never calls it under dnsMu or diskMu (applyFailing and
// applyAlert may run under applyMu or alertMu); an implementation must not
// call back into the service. A returned error means the alert was not
// recorded: the service asks again at a later check.
type dnsEvents interface {
	// nameChanged: a name's status changed (eff.FromStatus != eff.ToStatus)
	// or it entered review (eff.EnteredReview != ""). st is the new state.
	nameChanged(ctx context.Context, name string, eff dnsentry.Effects, st model.DNSEntryState)
	// reviewAlert asserts dns_entry.review failing for a used name in review:
	// when it entered review, and once after a restart. scopes is the
	// number of scopes using the name.
	reviewAlert(ctx context.Context, name string, st model.DNSEntryState, scopes int) error
	// reviewClosed ends dns_entry.review for name: recovered after a confirm,
	// quietly when the name stopped being used or its row is deleted.
	reviewClosed(ctx context.Context, name string, confirmed bool) error
	// applied: nginx took a file set in which name's addresses differ from
	// what it ran before (dns_entry_applied). before == nil means unknown.
	applied(ctx context.Context, name string, before, after []string, gen int64)
	// applyFailing: the apply loop went from working to failing or back.
	// res is the failed result, or the one that worked again.
	applyFailing(ctx context.Context, failing bool, res nginx.DNSApplyResult)
	// applyAlert: dns_entry.apply_failed changes for one subject.
	applyAlert(ctx context.Context, a dnsApplyAlert) error
}

// dnsApplyAlert is one change of dns_entry.apply_failed.
type dnsApplyAlert struct {
	Subject string // "revoke" or "apply"
	Failing bool
	// Quiet: recovered at the first look since this process started. The
	// failing state may predate the process; close it, but write no audit row.
	Quiet   bool
	Outcome string   // revoke, failing: the failed apply's outcome
	File    string   // revoke, failing: the file nginx -t named, when known
	Names   []string // revoke: names with a revocation waiting; apply: names with an addition waiting
}

// nopDNSEvents drops every event. NewDNSEntryService starts with it; the
// events implementation (dns_entry_events.go) replaces it.
type nopDNSEvents struct{}

func (nopDNSEvents) nameChanged(context.Context, string, dnsentry.Effects, model.DNSEntryState) {}
func (nopDNSEvents) reviewAlert(context.Context, string, model.DNSEntryState, int) error        { return nil }
func (nopDNSEvents) reviewClosed(context.Context, string, bool) error                           { return nil }
func (nopDNSEvents) applied(context.Context, string, []string, []string, int64)                 {}
func (nopDNSEvents) applyFailing(context.Context, bool, nginx.DNSApplyResult)                   {}
func (nopDNSEvents) applyAlert(context.Context, dnsApplyAlert) error                            { return nil }

// NewDNSEntryService builds the service. It starts nothing: the scheduler
// calls Tick, bootstrap calls ReconcileFiles and wires ReloadHooks.
func NewDNSEntryService(deps DNSEntryDeps, opts DNSEntryOptions) *DNSEntryService {
	s := &DNSEntryService{
		states:          deps.States,
		settings:        deps.Settings,
		global:          deps.Global,
		hosts:           deps.Hosts,
		builder:         deps.Builder,
		selfIPs:         deps.SelfIPs,
		bans:            deps.Bans,
		nginx:           deps.Nginx,
		audit:           deps.Audit,
		syslog:          deps.SystemLog,
		events:          nopDNSEvents{},
		envDisabled:     opts.EnvDisabled,
		envInterval:     opts.EnvInterval,
		policy:          opts.Policy,
		lookuper:        opts.Lookuper,
		now:             opts.Now,
		perLookup:       opts.PerLookupTimeout,
		saveResolve:     opts.SaveResolveTimeout,
		wake:            make(chan struct{}, 1),
		disk:            make(map[string]dnsDiskEntry),
		pendingRevoke:   make(map[string]dnsRevokeEntry),
		nginxView:       make(map[string]dnsViewEntry),
		reviewAnnounced: make(map[string]bool),
		reviewClosing:   make(map[string]bool),
	}
	if deps.States != nil {
		s.states = &dnsFloorStore{dnsStateStore: deps.States, svc: s}
	}
	if s.policy == nil {
		s.policy = model.DefaultAddressPolicy()
	}
	if s.lookuper == nil {
		s.lookuper = dnsentry.SystemLookuper()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.perLookup <= 0 {
		s.perLookup = 5 * time.Second
	}
	if s.saveResolve <= 0 {
		s.saveResolve = 3 * time.Second
	}
	return s
}

// SetNotificationService wires the alerts (bootstrap wireServiceCallbacks).
func (s *DNSEntryService) SetNotificationService(n dnsNotifier) {
	s.notifier = n
}

// EnvDisabled reports whether NPG_DNS_ENTRIES_DISABLED turned the feature off.
func (s *DNSEntryService) EnvDisabled() bool { return s.envDisabled }

// EnvInterval is NPG_DNS_ENTRIES_INTERVAL, 0 when unset.
func (s *DNSEntryService) EnvInterval() time.Duration { return s.envInterval }

// Settings returns the effective settings: the stored value normalized, the
// last value read when a read fails, and the feature off under
// NPG_DNS_ENTRIES_DISABLED.
func (s *DNSEntryService) Settings(ctx context.Context) model.DNSEntrySettings {
	st, _ := s.currentSettings(ctx)
	return st
}

// dnsSwitch is the feature switch as the transitions see it. known is false
// when the settings could not be read and none were read before: then no
// switch transition happens, because the fallback (off) is a guess.
type dnsSwitch struct {
	known   bool
	enabled bool
}

// currentSettings returns the effective settings and whether they are known.
// A failed read answers the last value read before it. With none (the first
// read failed) it answers the defaults with the feature off: falling back to
// the default "on" would trust names an operator turned off.
func (s *DNSEntryService) currentSettings(ctx context.Context) (model.DNSEntrySettings, bool) {
	var cur *model.SystemSettings
	var err error
	if s.settings != nil {
		cur, err = s.settings.Get(ctx)
	}
	s.settingsMu.Lock()
	var st model.DNSEntrySettings
	known := true
	switch {
	case s.settings == nil:
		st = model.DefaultDNSEntrySettings()
	case err == nil && cur != nil:
		st = model.ParseDNSEntrySettings(cur.DNSEntrySettings)
		good := st
		s.lastGood = &good
	case s.lastGood != nil:
		st = *s.lastGood
	default:
		st = model.DefaultDNSEntrySettings()
		st.Enabled = false
		known = false
	}
	s.settingsMu.Unlock()
	if s.envDisabled {
		st.Enabled = false
		known = true
	}
	return st, known
}

// RunExclusive runs fn while no state transition or file write can start
// (backup restore's ImportAllData).
func (s *DNSEntryService) RunExclusive(fn func() error) error {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	return fn()
}

// dnsLogOnce logs a problem that repeats at every check once, and again only
// after it cleared: container lines are for transitions.
type dnsLogOnce struct {
	mu     sync.Mutex
	failed map[string]bool
}

func (l *dnsLogOnce) fail(key, format string, args ...any) {
	l.mu.Lock()
	seen := l.failed[key]
	if l.failed == nil {
		l.failed = make(map[string]bool)
	}
	l.failed[key] = true
	l.mu.Unlock()
	if !seen {
		log.Printf(format, args...)
	}
}

func (l *dnsLogOnce) ok(key string) {
	l.mu.Lock()
	delete(l.failed, key)
	l.mu.Unlock()
}

// dnsSegKey keys one (scope, name) file set.
func dnsSegKey(scope, name string) string { return scope + "\x00" + name }

// dnsNewState is the row of a name seen for the first time: pending, and off
// when the feature is (or might be) off.
func dnsNewState(name string, now time.Time, sw dnsSwitch) model.DNSEntryState {
	return model.DNSEntryState{
		Hostname:  name,
		Status:    model.DNSStatusPending,
		Disabled:  !sw.enabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// dnsUseCounts counts the scopes using each name.
func dnsUseCounts(refs []model.DNSReference) map[string]int {
	out := make(map[string]int)
	seen := make(map[string]bool)
	for _, r := range refs {
		k := dnsSegKey(r.Scope, r.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		out[r.Name]++
	}
	return out
}

// dnsCleanNames normalizes names, drops the ones the name rules refuse
// (the handlers have refused them already) and duplicates, and sorts.
func dnsCleanNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = model.NormalizeDNSName(n)
		if seen[n] || model.ValidateDNSName(n) != nil {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// dnsSortedUnique returns the distinct values of in, sorted; nil when empty.
func dnsSortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// dnsMinus returns the values of a not in b, sorted; nil when none.
func dnsMinus(a, b []string) []string {
	drop := make(map[string]bool, len(b))
	for _, v := range b {
		drop[v] = true
	}
	var out []string
	for _, v := range a {
		if !drop[v] {
			out = append(out, v)
		}
	}
	return dnsSortedUnique(out)
}

// dnsUnion returns the values of a and b, sorted; nil when none.
func dnsUnion(a, b []string) []string {
	return dnsSortedUnique(append(append([]string(nil), a...), b...))
}

// dnsSameSet compares two address lists as sets.
func dnsSameSet(a, b []string) bool {
	a, b = dnsSortedUnique(a), dnsSortedUnique(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dnsCanonicalAddrs writes addresses the way the files and the state rows do
// (netip.Addr.String() of the Unmap()ed address). A value that is not an
// address is kept as it is, so it can never match one.
func dnsCanonicalAddrs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if a, err := netip.ParseAddr(v); err == nil {
			v = a.Unmap().String()
		}
		out = append(out, v)
	}
	return dnsSortedUnique(out)
}
