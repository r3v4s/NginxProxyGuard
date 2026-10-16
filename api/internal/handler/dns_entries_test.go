package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// fakeDNSEntryService answers as service.DNSEntryService does and records
// what the handler passed. Like the service, it leaves the apply state's
// blocking file and nginx's message out of a view without BlockingFile: the
// service is the one place that hides them. The entries come back as
// they are; the handler filters them again, as the access list responses do.
type fakeDNSEntryService struct {
	overview model.DNSEntryOverview
	err      error
	canRead  func(scope string) bool
	view     model.DNSStatusView
	apply    nginx.DNSApplyResult
	applies  int
}

func (f *fakeDNSEntryService) Overview(_ context.Context, canRead func(scope string) bool, view model.DNSStatusView) (model.DNSEntryOverview, error) {
	f.canRead, f.view = canRead, view
	ov := f.overview
	if !view.BlockingFile {
		ov.Apply.BlockedDetail, ov.Apply.BlockingFile = nil, nil
	}
	return ov, f.err
}

func (f *fakeDNSEntryService) ApplyNow(context.Context) nginx.DNSApplyResult {
	f.applies++
	return f.apply
}

// fakeDNSApplyAudit records the outcomes "apply now" audited.
type fakeDNSApplyAudit struct{ outcomes []string }

func (f *fakeDNSApplyAudit) LogDNSEntryApplyRequested(_ context.Context, outcome string) error {
	f.outcomes = append(f.outcomes, outcome)
	return nil
}

const dnsTestBlockingFile = "proxy_host_shop_example_com.conf"

func dnsTestDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decodeDNSOverview(t *testing.T, rec *httptest.ResponseRecorder) model.DNSEntryOverview {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	var ov model.DNSEntryOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if len(ov.Entries) != 1 {
		t.Fatalf("entries = %+v, want one", ov.Entries)
	}
	return ov
}

// The overview names a use only to a caller who may read its list, and shows
// banned, self_ip, the blocking file and nginx's message only with waf:read,
// ddns:read and proxy:read. settings:read, which
// the route needs, gives none of them. The handler asks the service with the
// caller's view; the apply state comes back gated by it and is not filtered
// again.
func TestDNSEntryOverviewShowsOnlyWhatTheCallerMayRead(t *testing.T) {
	file, outcome := dnsTestBlockingFile, "blocked"
	detail := `unknown directive "x" in /etc/nginx/conf.d/` + dnsTestBlockingFile + `:3`
	warnings := []string{model.DNSWarnBanned, model.DNSWarnSelfIP, model.DNSWarnCGNAT}
	svc := &fakeDNSEntryService{overview: model.DNSEntryOverview{
		Settings: model.DefaultDNSEntrySettings(),
		Apply:    model.DNSApplyState{BlockedOutcome: &outcome, BlockedDetail: &detail, BlockingFile: &file},
		Entries: []model.DNSEntryOverviewEntry{{
			DNSEntryStatus: model.DNSEntryStatus{Hostname: "partner.example.com", Status: model.DNSStatusOK, Warnings: warnings, BlockingFile: &file},
			HiddenUses:     1,
		}},
	}}
	h := &DNSEntryHandler{svc: svc}
	acl := "acl:" + testListID

	got := decodeDNSOverview(t, callWithGrants(t, h.Overview, permGrants{"settings:read": true}, http.MethodGet, ""))
	if e := got.Entries[0]; !reflect.DeepEqual(e.Warnings, []string{model.DNSWarnCGNAT}) || e.BlockingFile != nil || e.HiddenUses != 1 {
		t.Errorf("settings:read alone sees %+v", e)
	}
	if got.Apply.BlockingFile != nil || got.Apply.BlockedDetail != nil || dnsTestDeref(got.Apply.BlockedOutcome) != "blocked" {
		t.Errorf("settings:read alone sees the apply state %+v", got.Apply)
	}
	if svc.view != (model.DNSStatusView{}) || svc.canRead(acl) {
		t.Errorf("settings:read alone: view %+v, may read %s %v", svc.view, acl, svc.canRead(acl))
	}

	all := permGrants{"settings:read": true, "access:read": true, "waf:read": true, "ddns:read": true, "proxy:read": true}
	got = decodeDNSOverview(t, callWithGrants(t, h.Overview, all, http.MethodGet, ""))
	if e := got.Entries[0]; !reflect.DeepEqual(e.Warnings, warnings) || dnsTestDeref(e.BlockingFile) != file {
		t.Errorf("every permission sees %+v", e)
	}
	if dnsTestDeref(got.Apply.BlockingFile) != file || dnsTestDeref(got.Apply.BlockedDetail) != detail {
		t.Errorf("every permission sees the apply state %+v", got.Apply)
	}
	if svc.view != (model.DNSStatusView{Banned: true, SelfIP: true, BlockingFile: true}) || !svc.canRead(acl) ||
		svc.canRead("trusted") || svc.canRead("acl:not-a-uuid") {
		t.Errorf("every permission: view %+v, may read %s %v, trusted %v, a malformed scope %v",
			svc.view, acl, svc.canRead(acl), svc.canRead("trusted"), svc.canRead("acl:not-a-uuid"))
	}
	if !reflect.DeepEqual(svc.overview.Entries[0].Warnings, warnings) {
		t.Errorf("the handler changed the service's warnings: %v", svc.overview.Entries[0].Warnings)
	}

	svc.err = errors.New("connection refused")
	if rec := callWithGrants(t, h.Overview, all, http.MethodGet, ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("a failed read answers %d", rec.Code)
	}
}

// "Apply now" answers 200 with the outcome, and 409 nginx_reload_rejected
// when the running nginx refused the reload; the outcome is audited either
// way. The blocking file and nginx's message need proxy:read.
func TestDNSEntryApplyNowAnswersWithTheOutcome(t *testing.T) {
	detail := `unknown directive "x" in /etc/nginx/conf.d/` + dnsTestBlockingFile + `:3`
	blocked := nginx.DNSApplyResult{Outcome: "blocked", Detail: detail, BlockingFile: dnsTestBlockingFile}
	admin := permGrants{"settings:write": true, "proxy:read": true}
	cases := []struct {
		name         string
		res          nginx.DNSApplyResult
		grants       permGrants
		detail, file string
	}{
		{"accepted", nginx.DNSApplyResult{Outcome: "accepted"}, admin, "", ""},
		{"unconfirmed", nginx.DNSApplyResult{Outcome: "unconfirmed", Snapshot: &nginx.ReloadSnapshot{}}, admin, "", ""},
		{"not up", nginx.DNSApplyResult{Outcome: "not_up"}, admin, "", ""},
		{"blocked", blocked, admin, detail, dnsTestBlockingFile},
		{"blocked, without proxy:read", blocked, permGrants{"settings:write": true}, "", ""},
	}
	for _, c := range cases {
		svc, audit := &fakeDNSEntryService{apply: c.res}, &fakeDNSApplyAudit{}
		rec := callWithGrants(t, (&DNSEntryHandler{svc: svc, audit: audit}).ApplyNow, c.grants, http.MethodPost, "")
		var got model.DNSApplyResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Errorf("%s: status %d; body %s", c.name, rec.Code, rec.Body)
			continue
		}
		if got.Outcome != c.res.Outcome || dnsTestDeref(got.Detail) != c.detail || dnsTestDeref(got.BlockingFile) != c.file {
			t.Errorf("%s: answered %s", c.name, rec.Body)
		}
		if svc.applies != 1 || !reflect.DeepEqual(audit.outcomes, []string{c.res.Outcome}) {
			t.Errorf("%s: %d applies, audited %v", c.name, svc.applies, audit.outcomes)
		}
	}

	refusal := "bind() to 0.0.0.0:8443 failed (98: Address in use)"
	svc, audit := &fakeDNSEntryService{apply: nginx.DNSApplyResult{Outcome: "rejected", Detail: refusal}}, &fakeDNSApplyAudit{}
	rec := callWithGrants(t, (&DNSEntryHandler{svc: svc, audit: audit}).ApplyNow, admin, http.MethodPost, "")
	var body ErrorResponse
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Code != "nginx_reload_rejected" || body.Details != refusal {
		t.Errorf("rejected: status %d; body %s", rec.Code, rec.Body)
	}
	if !reflect.DeepEqual(audit.outcomes, []string{"rejected"}) {
		t.Errorf("rejected: audited %v, want the outcome recorded before the 409", audit.outcomes)
	}

	if rec := callWithGrants(t, NewDNSEntryHandler(nil, nil).ApplyNow, admin, http.MethodPost, ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("without the DNS entry service: status %d", rec.Code)
	}
}
