package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// The words of the domain entry events (dns_entry_events.go): English
// sentences for notifications, system log rows and container lines, built
// from names, codes and file names only.

// dnsEventLogEntry is one system log row; line is its container log copy.
type dnsEventLogEntry struct {
	Level   repository.SystemLogLevel
	Message string
	Details map[string]interface{}
}

// line is the container log line of the entry.
func (l dnsEventLogEntry) line() string {
	switch l.Level {
	case repository.LevelError:
		return "[DNSEntries] ERROR: " + l.Message
	case repository.LevelWarn:
		return "[DNSEntries] WARN: " + l.Message
	default:
		return "[DNSEntries] " + l.Message
	}
}

// dnsEventStatusLog is the log entry of a name that entered stale, expired,
// rejected, not_found or needs_review; ok is false for every other change.
func dnsEventStatusLog(name string, eff dnsentry.Effects, st model.DNSEntryState) (dnsEventLogEntry, bool) {
	from, to := eff.FromStatus, eff.ToStatus
	if from == to {
		return dnsEventLogEntry{}, false
	}
	n := dnsEventPrintable(name)
	codes := dnsEventParen(dnsEventFamilyCodes(st))
	details := map[string]interface{}{"hostname": n, "from": from, "to": to}
	var msg string
	switch to {
	case model.DNSStatusStale:
		msg = n + ": lookups are failing" + codes + "; its last addresses stay allowed until the grace period ends"
	case model.DNSStatusExpired:
		msg = n + ": lookups failed for longer than the grace period" + codes + "; none of its addresses are allowed"
	case model.DNSStatusRejected:
		msg = n + ": the address policy refused the answer" + codes + "; none of its addresses are allowed"
	case model.DNSStatusNotFound:
		msg = n + ": DNS has no address for it" + codes + "; none of its addresses are allowed"
	case model.DNSStatusNeedsReview:
		if st.ReviewReason == "" {
			st.ReviewReason = eff.EnteredReview
		}
		reason := dnsEventPrintableOr(st.ReviewReason, "unknown")
		details["reason"] = reason
		msg = n + " needs review (" + reason + "): " + dnsEventReviewClause(st) +
			"; none of its addresses are allowed until an operator confirms it"
	default:
		return dnsEventLogEntry{}, false
	}
	if c := dnsEventPrintable(st.V4.Code); c != "" {
		details["ipv4"] = c
	}
	if c := dnsEventPrintable(st.V6.Code); c != "" {
		details["ipv6"] = c
	}
	return dnsEventLogEntry{Level: repository.LevelWarn, Message: msg, Details: details}, true
}

// dnsEventReviewClause says why a name is in review, from its codes and, for
// cname_changed, the pinned and the newly seen CNAME target.
func dnsEventReviewClause(st model.DNSEntryState) string {
	switch st.ReviewReason {
	case model.DNSReviewCNAMEChanged:
		return "its CNAME target changed from " + dnsEventPrintableOr(st.CanonicalName, "(none)") +
			" to " + dnsEventPrintableOr(st.CanonicalSeen, "(unknown)")
	case model.DNSReviewReappeared:
		return "it came back after being empty with addresses outside the ones NPG allowed last"
	case model.DNSReviewUnstable:
		if n := len(st.ChangeTimes); n > 0 {
			return "its addresses changed " + strconv.Itoa(n) + " times in 24 hours"
		}
		return "its addresses changed too often in 24 hours"
	default:
		return "reason " + dnsEventPrintableOr(st.ReviewReason, "unknown")
	}
}

// dnsEventReviewDetail is the detail of a failing dns_entry.review alert.
func dnsEventReviewDetail(name string, st model.DNSEntryState) string {
	return dnsEventPrintable(name) + " needs review: " + dnsEventReviewClause(st) +
		". NPG allows none of its addresses until an operator confirms it."
}

// dnsEventConfirmedDetail is the detail of a recovered dns_entry.review alert.
func dnsEventConfirmedDetail(name string) string {
	return "An operator confirmed " + dnsEventPrintable(name) + "; NPG allows its addresses again."
}

// dnsEventReviewFields are the fields of a dns_entry.review message: the
// name, the review code and how many scopes use the name. All three pass the
// payload allowlist; no address goes in.
func dnsEventReviewFields(name, reason string, scopes int) map[string]string {
	fields := map[string]string{"subject": dnsEventPrintable(name)}
	if r := dnsEventPrintable(reason); r != "" {
		fields["reason"] = r
	}
	if scopes > 0 {
		fields["count"] = strconv.Itoa(scopes)
	}
	return fields
}

// dnsEventApplyNotice is the detail and the fields of a dns_entry.apply_failed
// message. The subject is "revoke" or "apply"; count is the number of names
// waiting, reason the failed apply's outcome.
func dnsEventApplyNotice(a dnsApplyAlert) (string, map[string]string) {
	fields := map[string]string{"subject": dnsEventPrintable(a.Subject)}
	revoke := a.Subject == dnsEventSubjectRevoke
	if !a.Failing {
		if revoke {
			return "nginx no longer allows the removed addresses.", fields
		}
		return "nginx has taken every added address.", fields
	}
	fields["count"] = strconv.Itoa(len(a.Names))
	if o := dnsEventPrintable(a.Outcome); o != "" {
		fields["reason"] = o
	}
	if revoke {
		return dnsEventRevokeSentence(a.Names, a.Outcome, a.File) + ".", fields
	}
	return fmt.Sprintf("Addresses added to %s have waited more than %d minutes for nginx.",
		dnsEventEntries(a.Names), int(dnsApplyAlertAfter/time.Minute)), fields
}

// dnsEventRevokeSentence is what an open "revoke" alert says. The service
// opens it only when an apply failed as blocked, failed or rejected:
// an nginx that is not running allows nothing, so not_up never opens it.
func dnsEventRevokeSentence(names []string, outcome, file string) string {
	return "nginx still allows addresses removed from " + dnsEventEntries(names) + ": " +
		dnsEventOutcomePhrase(outcome, file)
}

// dnsEventRevokeLog is the log entry of a change of the "revoke" alert.
// names are the names the alert is about.
func dnsEventRevokeLog(a dnsApplyAlert, names []string) dnsEventLogEntry {
	details := map[string]interface{}{"names": dnsEventCapNames(names), "names_total": len(names)}
	if !a.Failing {
		return dnsEventLogEntry{Level: repository.LevelInfo, Details: details,
			Message: "nginx no longer allows the addresses removed from " + dnsEventEntries(names)}
	}
	details["outcome"] = dnsEventPrintableOr(a.Outcome, "unknown")
	if f := dnsEventPrintable(a.File); f != "" {
		details["file"] = f
	}
	return dnsEventLogEntry{Level: repository.LevelError, Details: details,
		Message: dnsEventRevokeSentence(names, a.Outcome, a.File) + "; NPG keeps retrying"}
}

// dnsEventRunLog is the log entry of the apply loop failing or working again.
// res is the failed result, or the one that worked again.
func dnsEventRunLog(failing bool, res nginx.DNSApplyResult) dnsEventLogEntry {
	details := map[string]interface{}{"outcome": dnsEventPrintableOr(res.Outcome, "unknown")}
	if !failing {
		return dnsEventLogEntry{Level: repository.LevelInfo, Details: details,
			Message: "domain entry changes are applied again"}
	}
	if f := dnsEventPrintable(res.BlockingFile); f != "" {
		details["file"] = f
	}
	if res.Detail != "" {
		details["detail"] = res.Detail
	}
	return dnsEventLogEntry{Level: repository.LevelError, Details: details,
		Message: "domain entry changes could not be applied: " + dnsEventOutcomePhrase(res.Outcome, res.BlockingFile) +
			"; NPG retries with a growing delay"}
}

// dnsEventOutcomePhrase says why an apply did not go through.
func dnsEventOutcomePhrase(outcome, file string) string {
	file = dnsEventPrintable(file)
	if outcome == "blocked" {
		if file != "" {
			return "nginx -t fails in " + file
		}
		return "nginx -t fails"
	}
	var phrase string
	switch outcome {
	case "rejected":
		phrase = "nginx refused the reload"
	case "not_up":
		phrase = "nginx is not running"
	case "failed":
		phrase = "the reload did not go through"
	default:
		phrase = "the apply ended " + dnsEventPrintableOr(outcome, "without a result")
	}
	if file != "" {
		phrase += " (" + file + ")"
	}
	return phrase
}

// dnsEventEntries names a group of domain entries for a sentence:
// "2 domain entries (a.example.com, b.example.com)", at most
// dnsEventNamesShown of them followed by "and n more".
func dnsEventEntries(names []string) string {
	if len(names) == 0 {
		return "domain entries"
	}
	noun := "domain entries"
	if len(names) == 1 {
		noun = "domain entry"
	}
	shown := names
	if len(shown) > dnsEventNamesShown {
		shown = shown[:dnsEventNamesShown]
	}
	parts := make([]string, len(shown))
	for i, n := range shown {
		parts[i] = dnsEventPrintable(n)
	}
	list := strings.Join(parts, ", ")
	if more := len(names) - len(shown); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	return fmt.Sprintf("%d %s (%s)", len(names), noun, list)
}

// dnsEventCapNames returns at most dnsEventNamesLogged names, never nil.
func dnsEventCapNames(names []string) []string {
	if len(names) > dnsEventNamesLogged {
		names = names[:dnsEventNamesLogged]
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = dnsEventPrintable(n)
	}
	return out
}

// dnsEventFamilyCodes lists the families' classification codes:
// "ipv4 timeout, ipv6 not_found".
func dnsEventFamilyCodes(st model.DNSEntryState) string {
	var parts []string
	if c := dnsEventPrintable(st.V4.Code); c != "" {
		parts = append(parts, "ipv4 "+c)
	}
	if c := dnsEventPrintable(st.V6.Code); c != "" {
		parts = append(parts, "ipv6 "+c)
	}
	return strings.Join(parts, ", ")
}

func dnsEventParen(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// dnsEventPrintable keeps the characters a domain name, a CNAME target, a
// code or a file name may hold — [A-Za-z0-9._-] — and at most 253 of them. A
// CNAME target is whatever a DNS server answered: a forged one cannot start a
// new line in the container log or smuggle other text into a message.
func dnsEventPrintable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 253; i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func dnsEventPrintableOr(s, fallback string) string {
	if p := dnsEventPrintable(s); p != "" {
		return p
	}
	return fallback
}
