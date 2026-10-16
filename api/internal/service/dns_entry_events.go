package service

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// Domain entry events (#320): how the DNS entry service's dnsEvents reach
// the operator. The service decides when (dns_entry.go, dns_entry_hooks.go);
// this file decides the words and the outlets:
//   - notifications, edge-triggered on (key, subject): dns_entry.review per
//     name, dns_entry.apply_failed for the subjects "revoke" and "apply";
//   - audit rows written as "system": dns_entry_review_needed,
//     dns_entry_revoke_blocked and dns_entry_applied;
//   - one system_logs row per transition (component dns_entries) with the
//     same text as a container line: a name entering stale, expired,
//     rejected, not_found or needs_review; applying failing and working
//     again; removed addresses nginx still allows and no longer allows. The
//     line reads "[DNSEntries] WARN: …" or "[DNSEntries] ERROR: …" because the
//     log collector files only "WARN:" and "ERROR:" at those levels; a
//     "[WARN]" prefix is filed as info.
//
// Nothing here carries an address or the text of a DNS error, which
// holds the resolver's address: names, codes and file names
// only.

const (
	dnsEventKeyReview      = "dns_entry.review"
	dnsEventKeyApplyFailed = "dns_entry.apply_failed"
	dnsEventSubjectRevoke  = "revoke"
	// dnsEventComponent is the system_logs component of the rows written here.
	dnsEventComponent = "dns_entries"
	// dnsEventNamesShown caps the names one sentence lists.
	dnsEventNamesShown = 3
	// dnsEventNamesLogged caps the names one system log row lists.
	dnsEventNamesLogged = 20
	// dnsEventTimeout bounds the writes of one event.
	dnsEventTimeout = 10 * time.Second
)

// dnsEventReporter is the service's dnsEvents. It reads the service's
// notifier, auditor and system log at each call — SetNotificationService runs
// after construction — and calls nothing else of the service. A nil outlet is
// skipped.
//
// Its writes use their own context, not the caller's: a row the service
// writes on its own is attributed to "system" even when an operator's
// request led to it, and a client that hangs up does not cut a transition
// short.
type dnsEventReporter struct {
	svc *DNSEntryService

	mu sync.Mutex
	// revokeNames are the names of the open "revoke" alert, for the rows
	// that say it closed (the closing alert carries none).
	revokeNames []string
}

var (
	_ dnsEvents          = (*dnsEventReporter)(nil)
	_ dnsAuditor         = (*AuditService)(nil)
	_ dnsSystemLogWriter = (*repository.SystemLogRepository)(nil)
	_ dnsNotifier        = (*NotificationService)(nil)
)

func dnsEventContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), dnsEventTimeout)
}

// nameChanged logs a name entering stale, expired, rejected, not_found or
// needs_review (WARN), and audits a review entry. The review alert itself is
// reviewAlert's: the service sends it once the name is known to be used.
func (r *dnsEventReporter) nameChanged(_ context.Context, name string, eff dnsentry.Effects, st model.DNSEntryState) {
	ctx, cancel := dnsEventContext()
	defer cancel()
	if entry, ok := dnsEventStatusLog(name, eff, st); ok {
		r.writeLog(ctx, entry)
	}
	if eff.EnteredReview == "" || r.svc.audit == nil {
		return
	}
	reason := st.ReviewReason
	if reason == "" {
		reason = eff.EnteredReview
	}
	if err := r.svc.audit.LogDNSEntryReviewNeeded(ctx, name, reason); err != nil {
		log.Printf("[DNSEntries] WARN: could not write the review audit entry of %s: %v", dnsEventPrintable(name), err)
	}
}

// reviewAlert records dns_entry.review as failing for name.
func (r *dnsEventReporter) reviewAlert(_ context.Context, name string, st model.DNSEntryState, scopes int) error {
	n := r.svc.notifier
	if n == nil {
		return nil
	}
	ctx, cancel := dnsEventContext()
	defer cancel()
	return n.EmitTransition(ctx, dnsEventKeyReview, name, true, dnsEventReviewDetail(name, st),
		dnsEventReviewFields(name, st.ReviewReason, scopes))
}

// reviewClosed ends dns_entry.review for name: with a recovery message after
// a confirm, without one when the name stopped being used — nothing was
// confirmed then.
func (r *dnsEventReporter) reviewClosed(_ context.Context, name string, confirmed bool) error {
	n := r.svc.notifier
	if n == nil {
		return nil
	}
	ctx, cancel := dnsEventContext()
	defer cancel()
	if !confirmed {
		return n.ResolveQuietly(ctx, dnsEventKeyReview, name)
	}
	return n.EmitTransition(ctx, dnsEventKeyReview, name, false, dnsEventConfirmedDetail(name),
		dnsEventReviewFields(name, "", 0))
}

// applied writes dns_entry_applied: the record of which addresses nginx
// trusted from when.
func (r *dnsEventReporter) applied(_ context.Context, name string, before, after []string, gen int64) {
	a := r.svc.audit
	if a == nil {
		return
	}
	ctx, cancel := dnsEventContext()
	defer cancel()
	if err := a.LogDNSEntryApplied(ctx, name, before, after, gen); err != nil {
		log.Printf("[DNSEntries] WARN: could not write the apply audit entry of %s: %v", dnsEventPrintable(name), err)
	}
}

// applyFailing logs the apply loop failing (ERROR) or working again (info).
func (r *dnsEventReporter) applyFailing(_ context.Context, failing bool, res nginx.DNSApplyResult) {
	ctx, cancel := dnsEventContext()
	defer cancel()
	r.writeLog(ctx, dnsEventRunLog(failing, res))
}

// applyAlert records one change of dns_entry.apply_failed. The notification
// goes first: when it cannot be recorded nothing else is written and the
// error goes back, so the service's retry does not write the audit and log
// rows twice. A "revoke" change that is not Quiet is also audited
// (dns_entry_revoke_blocked) and logged (ERROR failing, info recovered);
// "apply" is a notification only, because the log already has the failing
// apply.
func (r *dnsEventReporter) applyAlert(_ context.Context, a dnsApplyAlert) error {
	ctx, cancel := dnsEventContext()
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()

	names := a.Names
	if a.Subject == dnsEventSubjectRevoke && !a.Failing {
		names = r.revokeNames
	}
	if n := r.svc.notifier; n != nil {
		detail, fields := dnsEventApplyNotice(a)
		if err := n.EmitTransition(ctx, dnsEventKeyApplyFailed, a.Subject, a.Failing, detail, fields); err != nil {
			return err
		}
	}
	if a.Subject != dnsEventSubjectRevoke {
		return nil
	}
	if a.Failing {
		r.revokeNames = a.Names
	} else {
		r.revokeNames = nil
	}
	if a.Quiet {
		return nil
	}
	if r.svc.audit != nil {
		if err := r.svc.audit.LogDNSEntryRevokeBlocked(ctx, a.Failing, a.Outcome, dnsEventPrintable(a.File), names); err != nil {
			log.Printf("[DNSEntries] WARN: could not write the revoke audit entry: %v", err)
		}
	}
	r.writeLog(ctx, dnsEventRevokeLog(a, names))
	return nil
}

// writeLog prints the container line and writes the system log row.
func (r *dnsEventReporter) writeLog(ctx context.Context, l dnsEventLogEntry) {
	log.Print(l.line())
	w := r.svc.syslog
	if w == nil {
		return
	}
	var details json.RawMessage
	if len(l.Details) > 0 {
		details, _ = json.Marshal(l.Details)
	}
	if err := w.Create(ctx, &repository.SystemLog{
		Source:    repository.SourceScheduler,
		Level:     l.Level,
		Message:   l.Message,
		Details:   details,
		Component: dnsEventComponent,
	}); err != nil {
		log.Printf("[DNSEntries] WARN: could not write a system log entry: %v", err)
	}
}
