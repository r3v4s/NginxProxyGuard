package service

import (
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// Two edge-triggered keys. A review is a notice about one
// name; an apply nginx did not take is a problem.
func TestDNSEntryEventsInCatalogue(t *testing.T) {
	for key, severity := range map[string]string{
		"dns_entry.review":       "warning",
		"dns_entry.apply_failed": "error",
	} {
		if got := model.SeverityOf(key); got != severity {
			t.Errorf("SeverityOf(%s) = %q, want %q", key, got, severity)
		}
		if model.IsBatchedEvent(key) {
			t.Errorf("%s must be edge-triggered, not batched", key)
		}
		if got := recoveryKeyFor(key); got != key {
			t.Errorf("%s recovers under %q, want its own key", key, got)
		}
	}
}

// Both recover under their own key, so each needs a recovery title, or the
// headline reads "Resolved — domain entry change not applied".
func TestDNSEntryRecoveryHeadlines(t *testing.T) {
	for _, key := range []string{"dns_entry.review", "dns_entry.apply_failed"} {
		for _, lang := range []string{LangEnglish, LangKorean} {
			resolved := headline(lang, model.RenderedMessage{Event: key, Severity: "resolved", Fields: map[string]string{}})
			if !strings.Contains(resolved, "✅") || strings.Contains(resolved, "not applied") ||
				strings.Contains(resolved, "needs review") || strings.Contains(resolved, "미반영") ||
				strings.Contains(resolved, "검토 필요") {
				t.Errorf("%s/%s recovery headline = %q", lang, key, resolved)
			}
		}
	}
	if h := headline(LangKorean, model.RenderedMessage{Event: "dns_entry.apply_failed", Severity: "error", Fields: map[string]string{}}); !strings.Contains(h, "도메인 항목 변경 미반영") {
		t.Errorf("failure headline = %q", h)
	}
}

var dnsSampleIPv4 = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)

// The Test button sends these. They carry the real severity and subject, and
// no address.
func TestDNSEntrySamples(t *testing.T) {
	for _, c := range []struct{ key, severity, subject string }{
		{"dns_entry.review", "warning", "partner.example.com"},
		{"dns_entry.apply_failed", "error", "revoke"},
	} {
		for _, lang := range []string{LangEnglish, LangKorean} {
			msg := SampleMessage(lang, c.key)
			if msg.Severity != c.severity || msg.Fields["subject"] != c.subject {
				t.Errorf("%s/%s sample = %s subject %q", lang, c.key, msg.Severity, msg.Fields["subject"])
			}
			if msg.Fields["detail"] == "" || strings.HasPrefix(msg.Fields["detail"], "sample.") {
				t.Errorf("%s/%s sample has no wording: %q", lang, c.key, msg.Fields["detail"])
			}
			if dnsSampleIPv4.MatchString(msg.Text) {
				t.Errorf("%s/%s sample carries an address: %q", lang, c.key, msg.Text)
			}
		}
	}
}
