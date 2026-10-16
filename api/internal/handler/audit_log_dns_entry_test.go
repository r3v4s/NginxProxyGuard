package handler

import "testing"

// The audit screen and GET /audit-logs/actions label every domain entry
// action; an unlabelled one would show its raw key.
func TestDNSEntryAuditLabels(t *testing.T) {
	for action, want := range map[string]string{
		"dns_entry_confirmed":        "도메인 항목 확인",
		"dns_entry_apply_requested":  "도메인 항목 지금 다시 적용",
		"dns_entry_applied":          "도메인 항목 적용",
		"dns_entry_review_needed":    "도메인 항목 검토 필요",
		"dns_entry_revoke_blocked":   "도메인 항목 회수 막힘·풀림",
		"dns_entries_env_disabled":   "도메인 항목 환경변수로 꺼짐",
		"dns_entry_settings_changed": "도메인 항목 설정 변경",
	} {
		if got := formatActionLabel(action); got != want {
			t.Errorf("formatActionLabel(%q) = %q, want %q", action, got, want)
		}
	}
	if got := formatResourceTypeLabel("dns_entry"); got != "도메인 항목" {
		t.Errorf("formatResourceTypeLabel(dns_entry) = %q", got)
	}
}
