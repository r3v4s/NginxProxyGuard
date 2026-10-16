package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// evtAudit records the audit rows the reporter writes.
type evtAudit struct {
	reviews []string // "name/reason"
	revokes []evtRevokeRow
	applied []string // "name gen"
	before  [][]string
}

type evtRevokeRow struct {
	blocked       bool
	outcome, file string
	names         []string
}

func (a *evtAudit) LogDNSEntryApplied(_ context.Context, name string, before, after []string, gen int64) error {
	a.applied = append(a.applied, name+" "+strconv.FormatInt(gen, 10))
	a.before = append(a.before, before)
	return nil
}

func (a *evtAudit) LogDNSEntryReviewNeeded(_ context.Context, name, reason string) error {
	a.reviews = append(a.reviews, name+"/"+reason)
	return nil
}

func (a *evtAudit) LogDNSEntryRevokeBlocked(_ context.Context, blocked bool, outcome, file string, names []string) error {
	a.revokes = append(a.revokes, evtRevokeRow{blocked: blocked, outcome: outcome, file: file, names: names})
	return nil
}

// evtSystemLog records the system log rows the reporter writes.
type evtSystemLog struct{ rows []repository.SystemLog }

func (l *evtSystemLog) Create(_ context.Context, row *repository.SystemLog) error {
	l.rows = append(l.rows, *row)
	return nil
}

// evtFlakyNotifier fails EmitTransition while fail is set and passes every
// other call to next.
type evtFlakyNotifier struct {
	next dnsNotifier
	fail bool
}

func (n *evtFlakyNotifier) EmitTransition(ctx context.Context, key, subject string, failing bool, detail string, fields map[string]string) error {
	if n.fail {
		return errors.New("database unreachable")
	}
	return n.next.EmitTransition(ctx, key, subject, failing, detail, fields)
}

func (n *evtFlakyNotifier) ResolveQuietly(ctx context.Context, key, subject string) error {
	return n.next.ResolveQuietly(ctx, key, subject)
}

// evtHarness is the reporter over a real NotificationService whose store is
// the in-memory fakeStore, so edge triggering is the production rule.
type evtHarness struct {
	rep   *dnsEventReporter
	store *fakeStore
	audit *evtAudit
	logs  *evtSystemLog
}

func newEvtHarness() *evtHarness {
	h := &evtHarness{
		store: newFakeStore(dnsEventKeyReview, dnsEventKeyApplyFailed),
		audit: &evtAudit{},
		logs:  &evtSystemLog{},
	}
	svc := &DNSEntryService{audit: h.audit, syslog: h.logs, notifier: NewNotificationServiceWithStore(h.store)}
	h.rep = &dnsEventReporter{svc: svc}
	return h
}

const evtName = "partner.example.com"

// evtReviewState is a row that entered review because its CNAME target moved.
// It holds addresses, which no notification may carry.
func evtReviewState() model.DNSEntryState {
	return model.DNSEntryState{
		Hostname:      evtName,
		Status:        model.DNSStatusNeedsReview,
		ReviewReason:  model.DNSReviewCNAMEChanged,
		LastApplied:   []string{"198.51.100.10"},
		Candidate:     []string{"198.51.100.11"},
		CanonicalName: "home.example.com",
		CanonicalSeen: "edge.example.com",
		V4:            model.DNSFamilyState{State: "ok", Observed: []string{"198.51.100.11"}},
	}
}

var evtEnteredReview = dnsentry.Effects{FromStatus: model.DNSStatusOK, ToStatus: model.DNSStatusNeedsReview,
	EnteredReview: model.DNSReviewCNAMEChanged, Revoked: []string{"198.51.100.10"}}

// The service builds its reporter itself, and the notifier wired later by
// SetNotificationService is the one the reporter uses.
func TestDNSEventReporterIsWiredByTheConstructor(t *testing.T) {
	s := NewDNSEntryService(DNSEntryDeps{}, DNSEntryOptions{})
	rep, ok := s.events.(*dnsEventReporter)
	if !ok || rep.svc != s {
		t.Fatalf("events = %T, want the service's *dnsEventReporter", s.events)
	}
	store := newFakeStore(dnsEventKeyReview)
	s.SetNotificationService(NewNotificationServiceWithStore(store))
	if err := s.events.reviewAlert(context.Background(), evtName, evtReviewState(), 1); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 1 {
		t.Fatalf("messages = %d, want 1 through the notifier wired after construction", len(store.enqueued))
	}
}

func TestDNSEventReviewEntryIsLoggedAndAudited(t *testing.T) {
	h := newEvtHarness()
	h.rep.nameChanged(context.Background(), evtName, evtEnteredReview, evtReviewState())

	if len(h.audit.reviews) != 1 || h.audit.reviews[0] != evtName+"/cname_changed" {
		t.Fatalf("review audit rows = %v", h.audit.reviews)
	}
	if len(h.logs.rows) != 1 {
		t.Fatalf("system log rows = %d, want 1", len(h.logs.rows))
	}
	row := h.logs.rows[0]
	want := evtName + " needs review (cname_changed): its CNAME target changed from home.example.com to edge.example.com"
	if row.Level != repository.LevelWarn || row.Source != repository.SourceScheduler || row.Component != "dns_entries" ||
		!strings.HasPrefix(row.Message, want) {
		t.Errorf("system log row = %+v, want a warn row starting %q", row, want)
	}
	if len(h.store.enqueued) != 0 {
		t.Error("nameChanged sent the review alert; that is reviewAlert's")
	}
}

func TestDNSEventReviewAlertAndItsClose(t *testing.T) {
	h := newEvtHarness()
	ctx := context.Background()
	if err := h.rep.reviewAlert(ctx, evtName, evtReviewState(), 2); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 1 {
		t.Fatalf("messages = %d, want 1", len(h.store.enqueued))
	}
	msg := h.store.enqueued[0]
	if msg.Event != dnsEventKeyReview || msg.Severity != "warning" {
		t.Errorf("message = %s/%s, want dns_entry.review/warning", msg.Event, msg.Severity)
	}
	if msg.Fields["subject"] != evtName || msg.Fields["reason"] != "cname_changed" || msg.Fields["count"] != "2" {
		t.Errorf("fields = %v", msg.Fields)
	}
	if d := msg.Fields["detail"]; !strings.Contains(d, "from home.example.com to edge.example.com") {
		t.Errorf("detail %q does not name the pinned and the new CNAME target", d)
	}

	// A restart asserts it again; the failing state already stored
	// keeps that silent.
	_ = h.rep.reviewAlert(ctx, evtName, evtReviewState(), 2)
	if len(h.store.enqueued) != 1 {
		t.Fatalf("the alert was sent twice: %d messages", len(h.store.enqueued))
	}

	// A confirm closes it with a message.
	if err := h.rep.reviewClosed(ctx, evtName, true); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 2 || h.store.enqueued[1].Severity != "resolved" || h.store.enqueued[1].Event != dnsEventKeyReview {
		t.Fatalf("no recovery message: %+v", h.store.enqueued)
	}

	// A name that stopped being used closes without one.
	_ = h.rep.reviewAlert(ctx, "office.example.com", evtReviewState(), 1)
	if err := h.rep.reviewClosed(ctx, "office.example.com", false); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 3 {
		t.Fatalf("closing an unused name sent a message: %d messages", len(h.store.enqueued))
	}
	if rec, _ := h.store.StateRecord(ctx, dnsEventKeyReview, "office.example.com"); !isQuietlyResolved(rec) {
		t.Fatalf("state = %+v, want closed quietly", rec)
	}
}

// Names, codes and file names leave the box, addresses do not.
func TestDNSEventNotificationsCarryNoAddress(t *testing.T) {
	h := newEvtHarness()
	ctx := context.Background()
	_ = h.rep.reviewAlert(ctx, evtName, evtReviewState(), 1)
	_ = h.rep.applyAlert(ctx, dnsApplyAlert{Subject: "revoke", Failing: true, Outcome: "blocked",
		File: "proxy_host_1.conf", Names: []string{evtName}})
	if len(h.store.enqueued) != 2 {
		t.Fatalf("messages = %d, want 2", len(h.store.enqueued))
	}
	for _, msg := range h.store.enqueued {
		parts := []string{msg.Text}
		for _, v := range msg.Fields {
			parts = append(parts, v)
		}
		if all := strings.Join(parts, " "); strings.Contains(all, "198.51.100.") {
			t.Errorf("%s carries an address: %q", msg.Event, all)
		}
	}
}

func TestDNSEventStatusLogOnlyOnEntry(t *testing.T) {
	failing := model.DNSEntryState{Hostname: evtName,
		V4: model.DNSFamilyState{State: "transient", Code: "timeout"},
		V6: model.DNSFamilyState{State: "notfound", Code: "not_found"}}
	for _, c := range []struct {
		from, to string
		want     string // "" = no row
	}{
		{model.DNSStatusOK, model.DNSStatusStale, evtName + ": lookups are failing (ipv4 timeout, ipv6 not_found)"},
		{model.DNSStatusStale, model.DNSStatusExpired, evtName + ": lookups failed for longer than the grace period (ipv4 timeout, ipv6 not_found)"},
		{model.DNSStatusOK, model.DNSStatusRejected, evtName + ": the address policy refused the answer"},
		{model.DNSStatusPending, model.DNSStatusNotFound, evtName + ": DNS has no address for it"},
		{model.DNSStatusStale, model.DNSStatusStale, ""},
		{model.DNSStatusStale, model.DNSStatusOK, ""},
		{model.DNSStatusNeedsReview, model.DNSStatusOK, ""},
	} {
		h := newEvtHarness()
		h.rep.nameChanged(context.Background(), evtName, dnsentry.Effects{FromStatus: c.from, ToStatus: c.to}, failing)
		if c.want == "" {
			if len(h.logs.rows) != 0 {
				t.Errorf("%s -> %s logged %q", c.from, c.to, h.logs.rows[0].Message)
			}
			continue
		}
		if len(h.logs.rows) != 1 || !strings.HasPrefix(h.logs.rows[0].Message, c.want) || h.logs.rows[0].Level != repository.LevelWarn {
			t.Errorf("%s -> %s logged %+v, want one warn row starting %q", c.from, c.to, h.logs.rows, c.want)
		}
		if len(h.store.enqueued) != 0 || len(h.audit.reviews) != 0 {
			t.Errorf("%s -> %s sent a notification or an audit row", c.from, c.to)
		}
	}
}

// The collector files container lines by "WARN:" and "ERROR:"; a line
// written as "[WARN] …" would land as info with "WARN" as its component.
func TestDNSEventLinesAreFiledAtTheirLevel(t *testing.T) {
	c := &DockerLogCollector{config: defaultSystemLogConfig, startupGrace: map[string]time.Time{}}
	api := ContainerConfig{Name: "npg-api", Source: repository.SourceDockerAPI}
	for _, level := range []repository.SystemLogLevel{repository.LevelWarn, repository.LevelError, repository.LevelInfo} {
		entry := dnsEventLogEntry{Level: level, Message: evtName + ": lookups are failing (ipv4 timeout)"}
		got := c.parseLogLine(api, "2026/10/15 09:00:00 "+entry.line(), false)
		if got == nil {
			t.Fatalf("%s line was dropped: %q", level, entry.line())
		}
		if got.Level != level || got.Component != "DNSEntries" {
			t.Errorf("%q filed as %s/%s, want %s/DNSEntries", entry.line(), got.Level, got.Component, level)
		}
	}
}

// A CNAME target comes from whoever answers DNS. A forged one cannot start a
// new line in the container log or carry other text into a message.
func TestDNSEventForgedCNAMEIsPrintedSafely(t *testing.T) {
	h := newEvtHarness()
	st := evtReviewState()
	st.CanonicalSeen = "evil.example.com\n2026/10/15 09:00:00 [DNSEntries] ERROR: forged *x*"
	h.rep.nameChanged(context.Background(), evtName, evtEnteredReview, st)
	_ = h.rep.reviewAlert(context.Background(), evtName, st, 1)

	line := dnsEventLogEntry{Level: h.logs.rows[0].Level, Message: h.logs.rows[0].Message}.line()
	for _, s := range []string{h.store.enqueued[0].Fields["detail"], line} {
		if strings.ContainsAny(s, "\n\r*") || strings.Contains(s, "ERROR:") {
			t.Errorf("a forged CNAME reached the output as written: %q", s)
		}
		if !strings.Contains(s, "evil.example.com") {
			t.Errorf("the forged target is not named at all: %q", s)
		}
	}
}

// Removed addresses nginx still allows are announced, audited and logged
// as ERROR; the close lists the names the open alert was about.
func TestDNSEventRevokeAlertOpensAndCloses(t *testing.T) {
	h := newEvtHarness()
	ctx := context.Background()
	if err := h.rep.applyAlert(ctx, dnsApplyAlert{Subject: "revoke", Failing: true, Outcome: "blocked",
		File: "proxy_host_1.conf", Names: []string{"a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 1 {
		t.Fatalf("messages = %d, want 1", len(h.store.enqueued))
	}
	msg := h.store.enqueued[0]
	if msg.Event != dnsEventKeyApplyFailed || msg.Severity != "error" || msg.Fields["subject"] != "revoke" ||
		msg.Fields["reason"] != "blocked" || msg.Fields["count"] != "1" {
		t.Errorf("message = %s/%s %v", msg.Event, msg.Severity, msg.Fields)
	}
	if d := msg.Fields["detail"]; d != "nginx still allows addresses removed from 1 domain entry (a.example.com): nginx -t fails in proxy_host_1.conf." {
		t.Errorf("detail = %q", d)
	}
	if len(h.audit.revokes) != 1 || !h.audit.revokes[0].blocked || h.audit.revokes[0].outcome != "blocked" ||
		h.audit.revokes[0].file != "proxy_host_1.conf" || len(h.audit.revokes[0].names) != 1 {
		t.Errorf("revoke audit rows = %+v", h.audit.revokes)
	}
	if len(h.logs.rows) != 1 || h.logs.rows[0].Level != repository.LevelError {
		t.Fatalf("system log rows = %+v, want one error row", h.logs.rows)
	}

	if err := h.rep.applyAlert(ctx, dnsApplyAlert{Subject: "revoke"}); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 2 || h.store.enqueued[1].Severity != "resolved" {
		t.Fatalf("no recovery message: %+v", h.store.enqueued)
	}
	if len(h.audit.revokes) != 2 || h.audit.revokes[1].blocked || len(h.audit.revokes[1].names) != 1 ||
		h.audit.revokes[1].names[0] != "a.example.com" {
		t.Errorf("revoke audit rows = %+v, want a blocked=false row naming a.example.com", h.audit.revokes)
	}
	if len(h.logs.rows) != 2 || h.logs.rows[1].Level != repository.LevelInfo ||
		h.logs.rows[1].Message != "nginx no longer allows the addresses removed from 1 domain entry (a.example.com)" {
		t.Errorf("system log rows = %+v, want an info row last", h.logs.rows)
	}
}

// A first "recovered" after a start may close an alert the previous process
// left failing: it announces, and writes no audit or log row.
func TestDNSEventQuietRecoveryWritesNoRows(t *testing.T) {
	h := newEvtHarness()
	h.store.state[dnsEventKeyApplyFailed+"|revoke"] = stateFailing
	if err := h.rep.applyAlert(context.Background(), dnsApplyAlert{Subject: "revoke", Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 1 || h.store.enqueued[0].Severity != "resolved" {
		t.Fatalf("the leftover alert was not closed: %+v", h.store.enqueued)
	}
	if len(h.audit.revokes) != 0 || len(h.logs.rows) != 0 {
		t.Errorf("a quiet close wrote %d audit and %d log rows", len(h.audit.revokes), len(h.logs.rows))
	}
}

func TestDNSEventApplyAlertIsANotificationOnly(t *testing.T) {
	h := newEvtHarness()
	ctx := context.Background()
	_ = h.rep.applyAlert(ctx, dnsApplyAlert{Subject: "apply", Failing: true, Names: []string{evtName}})
	if len(h.store.enqueued) != 1 {
		t.Fatalf("messages = %d, want 1", len(h.store.enqueued))
	}
	msg := h.store.enqueued[0]
	if msg.Severity != "error" || msg.Fields["subject"] != "apply" || msg.Fields["count"] != "1" ||
		msg.Fields["detail"] != "Addresses added to 1 domain entry (partner.example.com) have waited more than 15 minutes for nginx." {
		t.Errorf("message = %s %v", msg.Severity, msg.Fields)
	}
	_ = h.rep.applyAlert(ctx, dnsApplyAlert{Subject: "apply"})
	if len(h.store.enqueued) != 2 || h.store.enqueued[1].Severity != "resolved" {
		t.Fatalf("no recovery: %+v", h.store.enqueued)
	}
	if len(h.logs.rows) != 0 || len(h.audit.revokes) != 0 {
		t.Errorf("the apply alert wrote %d log and %d audit rows, want none", len(h.logs.rows), len(h.audit.revokes))
	}
}

// When the notification cannot be recorded nothing else is written and the
// error goes back; the service's retry then writes each row once.
func TestDNSEventFailedNotificationWritesNothing(t *testing.T) {
	h := newEvtHarness()
	flaky := &evtFlakyNotifier{next: h.rep.svc.notifier, fail: true}
	h.rep.svc.notifier = flaky
	a := dnsApplyAlert{Subject: "revoke", Failing: true, Outcome: "rejected", Names: []string{"a.example.com"}}

	if err := h.rep.applyAlert(context.Background(), a); err == nil {
		t.Fatal("a notification the database did not take returned no error")
	}
	if len(h.audit.revokes) != 0 || len(h.logs.rows) != 0 {
		t.Fatalf("a failed notification wrote %d audit and %d log rows", len(h.audit.revokes), len(h.logs.rows))
	}
	flaky.fail = false
	if err := h.rep.applyAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if len(h.store.enqueued) != 1 || len(h.audit.revokes) != 1 || len(h.logs.rows) != 1 {
		t.Fatalf("after the retry: %d messages, %d audits, %d logs", len(h.store.enqueued), len(h.audit.revokes), len(h.logs.rows))
	}
}

// Apply failures and recoveries: the service reports the loop
// failing and working again once each; both are logged, neither notified.
func TestDNSEventApplyingFailingAndWorkingAgain(t *testing.T) {
	h := newEvtHarness()
	ctx := context.Background()
	h.rep.applyFailing(ctx, true, nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_1.conf",
		Detail: `host not found in upstream "app.example.com"`})
	h.rep.applyFailing(ctx, false, nginx.DNSApplyResult{Outcome: "accepted"})
	if len(h.logs.rows) != 2 {
		t.Fatalf("system log rows = %d, want 2", len(h.logs.rows))
	}
	if r := h.logs.rows[0]; r.Level != repository.LevelError ||
		!strings.HasPrefix(r.Message, "domain entry changes could not be applied: nginx -t fails in proxy_host_1.conf") ||
		!strings.Contains(string(r.Details), "host not found in upstream") {
		t.Errorf("failing row = %+v", r)
	}
	if r := h.logs.rows[1]; r.Level != repository.LevelInfo || r.Message != "domain entry changes are applied again" {
		t.Errorf("recovery row = %+v", r)
	}
	if len(h.store.enqueued) != 0 {
		t.Errorf("the loop state sent %d messages", len(h.store.enqueued))
	}
}

func TestDNSEventAppliedAudit(t *testing.T) {
	h := newEvtHarness()
	h.rep.applied(context.Background(), evtName, nil, []string{"198.51.100.10"}, 3)
	if len(h.audit.applied) != 1 || h.audit.before[0] != nil {
		t.Fatalf("applied audit rows = %v / before %v, want one with an unknown before", h.audit.applied, h.audit.before)
	}
}

func TestDNSEventsWithoutOutlets(t *testing.T) {
	rep := &dnsEventReporter{svc: &DNSEntryService{}}
	ctx := context.Background()
	rep.nameChanged(ctx, evtName, evtEnteredReview, evtReviewState())
	rep.applied(ctx, evtName, nil, []string{"198.51.100.10"}, 1)
	rep.applyFailing(ctx, true, nginx.DNSApplyResult{Outcome: "blocked"})
	for _, err := range []error{
		rep.reviewAlert(ctx, evtName, evtReviewState(), 1),
		rep.reviewClosed(ctx, evtName, true),
		rep.applyAlert(ctx, dnsApplyAlert{Subject: "revoke", Failing: true, Outcome: "blocked"}),
	} {
		if err != nil {
			t.Errorf("an unwired outlet returned %v; the service would retry it forever", err)
		}
	}
}
