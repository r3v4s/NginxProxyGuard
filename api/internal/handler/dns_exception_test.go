package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// The domains of the four exception lists (#320) as the API shows and
// confirms them: each list's GET carries its domains' state, and five
// routes allow again a domain of their lists that waits for review.

// exConfirmBody is what the UI sends after showing the operator a domain's
// answer; the name is normalized before it is looked for.
const exConfirmBody = `{"hostname":"Partner.Example.com.","expected_addresses":["192.0.2.10"],"expected_canonical_name":"partner.example.com"}`

const exConfirmName = "partner.example.com"

// fakeConfirmDNS stands for the DNS entry service in a confirm. References
// answers the uses in refs of the name asked.
type fakeConfirmDNS struct {
	log        *callLog
	refs       []model.DNSReference
	confirmed  model.DNSEntryStatus
	result     nginx.DNSApplyResult
	confirmErr error
	// confirming, when set, runs while Confirm applies: a test cancels the
	// request there, after the confirm is stored.
	confirming func()
}

func (f *fakeConfirmDNS) References(_ context.Context, name string) ([]model.DNSReference, error) {
	f.log.add("refs %s", name)
	var out []model.DNSReference
	for _, r := range f.refs {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeConfirmDNS) Confirm(_ context.Context, name string, expected []string, expectedCanonical string) (model.DNSEntryStatus, nginx.DNSApplyResult, error) {
	f.log.add("confirm %s %v %s", name, expected, expectedCanonical)
	if f.confirming != nil {
		f.confirming()
	}
	return f.confirmed, f.result, f.confirmErr
}

// fakeConfirmHosts keeps one proxy host.
type fakeConfirmHosts struct {
	log  *callLog
	host *model.ProxyHost
}

func (f *fakeConfirmHosts) GetByID(_ context.Context, id string) (*model.ProxyHost, error) {
	f.log.add("host %s", id)
	if f.host != nil && f.host.ID == id {
		return f.host, nil
	}
	return nil, nil
}

type fakeConfirmAudit struct{ log *callLog }

func (f *fakeConfirmAudit) LogDNSEntryConfirmed(ctx context.Context, name string, addrs []string, canonical string, scopes []string) error {
	f.log.add("audit confirmed %s %v %s %v%s", name, addrs, canonical, scopes, ctxNote(ctx))
	return nil
}

// newExceptionConfirm returns a handler over the fakes, with the host
// exHostID stored.
func newExceptionConfirm() (*ExceptionDNSHandler, *callLog, *fakeConfirmDNS) {
	calls := &callLog{}
	dns := &fakeConfirmDNS{log: calls}
	h := &ExceptionDNSHandler{
		hosts: &fakeConfirmHosts{log: calls, host: &model.ProxyHost{ID: exHostID, DomainNames: []string{"app.example.com"}}},
		dns:   dns,
		audit: &fakeConfirmAudit{log: calls},
	}
	return h, calls, dns
}

// exceptionConfirmRoute is one confirm route and one of its lists.
type exceptionConfirmRoute struct {
	name   string
	call   func(*ExceptionDNSHandler, echo.Context) error
	params []string
	use    string // the scope of a name in that list
	other  string // the scope of a list the route does not confirm
	write  string // the permission that changes the list
}

func exceptionConfirmRoutes() []exceptionConfirmRoute {
	host := []string{"id", exHostID}
	return []exceptionConfirmRoute{
		{"host URI block", (*ExceptionDNSHandler).ConfirmHost, host, "uri:" + exHostID, "uri:" + exCloneID, "proxy:write"},
		{"host priority allow", (*ExceptionDNSHandler).ConfirmHost, host, "prio:" + exHostID, "prio:global", "proxy:write"},
		{"host rate limit", (*ExceptionDNSHandler).ConfirmHost, host, "rl:" + exHostID, "rl:" + exCloneID, "proxy:write"},
		{"global URI block", (*ExceptionDNSHandler).ConfirmGlobalURIBlock, nil, "uri:global", "uri:" + exHostID, "waf:write"},
		{"global geo", (*ExceptionDNSHandler).ConfirmGlobalGeo, nil, "prio:global", "prio:" + exHostID, "waf:write"},
		{"global rate limit", (*ExceptionDNSHandler).ConfirmGlobalRateLimit, nil, "rl:global", "rl:" + exHostID, "waf:write"},
		{"global trusted list", (*ExceptionDNSHandler).ConfirmTrusted, nil, "trusted", "acl:" + testListID, "settings:write"},
	}
}

func (r exceptionConfirmRoute) handler(h *ExceptionDNSHandler) echo.HandlerFunc {
	return func(c echo.Context) error { return r.call(h, c) }
}

func useOf(scope string) model.DNSReference {
	return model.DNSReference{Scope: scope, Name: exConfirmName}
}

// confirmAnswer decodes a refused confirm's body.
type confirmAnswer struct {
	Code     string   `json:"code"`
	Required []string `json:"required"`
	Details  string   `json:"details"`
	Observed *struct {
		Addresses     []string `json:"addresses"`
		CanonicalName *string  `json:"canonical_name"`
	} `json:"observed"`
}

// Every refusal of the five confirm routes: a domain none of the route's
// lists holds (one of another host, or of the host's list on a global route,
// is not), a use the caller may not change, and what the DNS service and
// nginx answer. Nothing is published or recorded before the DNS service
// confirms; a reload nginx refused is recorded, as the name is published.
func TestExceptionConfirmRefusals(t *testing.T) {
	changed := &dnsentry.ObservationChangedError{Observed: []string{"192.0.2.20"}, Canonical: "home.ddns.example.com"}
	cases := []struct {
		name     string
		refs     func(r exceptionConfirmRoute) []model.DNSReference
		err      error
		result   nginx.DNSApplyResult
		status   int
		code     string
		required []string
		confirms bool // the DNS service was asked
		audited  bool
	}{
		{"domain of another list", func(r exceptionConfirmRoute) []model.DNSReference { return []model.DNSReference{useOf(r.other)} }, nil, nginx.DNSApplyResult{},
			http.StatusBadRequest, "not_in_list", nil, false, false},
		{"also used where the caller may not change it", func(r exceptionConfirmRoute) []model.DNSReference {
			return []model.DNSReference{useOf(r.use), useOf("acl:" + testListID)}
		}, nil, nginx.DNSApplyResult{}, http.StatusForbidden, "", []string{"access:write"}, false, false},
		{"not waiting for review", nil, dnsentry.ErrNotInReview, nginx.DNSApplyResult{}, http.StatusBadRequest, "not_in_review", nil, true, false},
		{"lookup failed", nil, dnsentry.ErrLookupUnavailable, nginx.DNSApplyResult{}, http.StatusConflict, "lookup_unavailable", nil, true, false},
		{"answers differently now", nil, changed, nginx.DNSApplyResult{}, http.StatusConflict, "observation_changed", nil, true, false},
		{"nginx refused the reload", nil, nil, nginx.DNSApplyResult{Outcome: "rejected", Detail: "bind() to 0.0.0.0:18998 failed (98: Address in use)"},
			http.StatusConflict, "nginx_reload_rejected", nil, true, true},
	}
	for _, r := range exceptionConfirmRoutes() {
		for _, tc := range cases {
			t.Run(r.name+"/"+tc.name, func(t *testing.T) {
				h, calls, dns := newExceptionConfirm()
				dns.refs = []model.DNSReference{useOf(r.use)}
				if tc.refs != nil {
					dns.refs = tc.refs(r)
				}
				dns.confirmErr, dns.result = tc.err, tc.result
				rec := callWithGrants(t, r.handler(h), permGrants{r.write: true}, http.MethodPost, exConfirmBody, r.params...)
				if rec.Code != tc.status {
					t.Fatalf("status %d, want %d; body %s", rec.Code, tc.status, rec.Body)
				}
				var body confirmAnswer
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("body %s: %v", rec.Body, err)
				}
				if body.Code != tc.code || !reflect.DeepEqual(body.Required, tc.required) {
					t.Errorf("code %q required %v, want %q %v", body.Code, body.Required, tc.code, tc.required)
				}
				if tc.err == changed && (body.Observed == nil || !reflect.DeepEqual(body.Observed.Addresses, []string{"192.0.2.20"}) ||
					body.Observed.CanonicalName == nil || *body.Observed.CanonicalName != "home.ddns.example.com") {
					t.Errorf("observation_changed without the new answer: %s", rec.Body)
				}
				if tc.code == "nginx_reload_rejected" && !strings.Contains(body.Details, "Address in use") {
					t.Errorf("nginx_reload_rejected without nginx's line: %s", rec.Body)
				}
				var confirmed, audited bool
				for _, call := range calls.calls {
					confirmed = confirmed || strings.HasPrefix(call, "confirm ")
					audited = audited || strings.HasPrefix(call, "audit ")
				}
				if confirmed != tc.confirms || audited != tc.audited {
					t.Errorf("calls = %v, want confirm %v, audit %v", calls.calls, tc.confirms, tc.audited)
				}
				if tc.confirms && !strings.HasPrefix(calls.calls[len(calls.calls)-1-btoi(tc.audited)], "confirm "+exConfirmName+" [192.0.2.10] partner.example.com") {
					t.Errorf("calls = %v, want the normalized name and what the client showed", calls.calls)
				}
			})
		}
	}

	t.Run("host missing", func(t *testing.T) {
		h, calls, _ := newExceptionConfirm()
		rec := callWithGrants(t, h.ConfirmHost, permGrants{"proxy:write": true}, http.MethodPost, exConfirmBody, "id", exCloneID)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404; body %s", rec.Code, rec.Body)
		}
		if want := []string{"host " + exCloneID}; !reflect.DeepEqual(calls.calls, want) {
			t.Errorf("calls = %v, want %v", calls.calls, want)
		}
	})
	t.Run("not JSON", func(t *testing.T) {
		h, calls, _ := newExceptionConfirm()
		rec := callWithGrants(t, h.ConfirmTrusted, permGrants{"settings:write": true}, http.MethodPost, `{"hostname":`)
		if rec.Code != http.StatusBadRequest || len(calls.calls) != 0 {
			t.Errorf("status %d, calls %v; want 400 and nothing asked", rec.Code, calls.calls)
		}
	})
	t.Run("without the DNS entry service", func(t *testing.T) {
		h, _, _ := newExceptionConfirm()
		h.dns = nil
		rec := callWithGrants(t, h.ConfirmTrusted, permGrants{"settings:write": true}, http.MethodPost, exConfirmBody)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d, want 500; body %s", rec.Code, rec.Body)
		}
	})
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// A name has one state for every list that uses it, so a confirm allows it
// again everywhere: here a host's priority allow and the global trusted list
// share it. The host's confirm needs settings:write as well, the trusted
// list's proxy:write as well; with both it goes through, shows the state as
// the caller may see it (no waf:read, no banned), and records both uses,
// also when the client left while nginx applied it.
func TestExceptionConfirmNeedsEveryUsesWritePermission(t *testing.T) {
	refs := []model.DNSReference{useOf("prio:" + exHostID), useOf("trusted")}
	for _, tc := range []struct {
		name     string
		call     func(*ExceptionDNSHandler) echo.HandlerFunc
		params   []string
		grants   permGrants
		required []string
	}{
		{"host without settings:write", func(h *ExceptionDNSHandler) echo.HandlerFunc { return h.ConfirmHost },
			[]string{"id", exHostID}, permGrants{"proxy:write": true}, []string{"settings:write"}},
		{"trusted list without proxy:write", func(h *ExceptionDNSHandler) echo.HandlerFunc { return h.ConfirmTrusted },
			nil, permGrants{"settings:write": true}, []string{"proxy:write"}},
		{"host with neither", func(h *ExceptionDNSHandler) echo.HandlerFunc { return h.ConfirmHost },
			[]string{"id", exHostID}, permGrants{"proxy:read": true}, []string{"proxy:write", "settings:write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, calls, dns := newExceptionConfirm()
			dns.refs = refs
			rec := callWithGrants(t, tc.call(h), tc.grants, http.MethodPost, exConfirmBody, tc.params...)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403; body %s", rec.Code, rec.Body)
			}
			var body confirmAnswer
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(body.Required, tc.required) {
				t.Errorf("required %v, want %v", body.Required, tc.required)
			}
			for _, call := range calls.calls {
				if strings.HasPrefix(call, "confirm") || strings.HasPrefix(call, "audit") {
					t.Errorf("calls = %v, want no confirm", calls.calls)
				}
			}
		})
	}

	both := permGrants{"proxy:write": true, "settings:write": true}
	canonical := exConfirmName
	for _, tc := range []struct {
		name   string
		call   func(*ExceptionDNSHandler) echo.HandlerFunc
		params []string
	}{
		{"host", func(h *ExceptionDNSHandler) echo.HandlerFunc { return h.ConfirmHost }, []string{"id", exHostID}},
		{"trusted list", func(h *ExceptionDNSHandler) echo.HandlerFunc { return h.ConfirmTrusted }, nil},
	} {
		t.Run(tc.name+" with both", func(t *testing.T) {
			h, calls, dns := newExceptionConfirm()
			dns.refs = refs
			dns.confirmed = model.DNSEntryStatus{Hostname: exConfirmName, Status: model.DNSStatusOK, Addresses: []string{"192.0.2.10"},
				ObservedAddresses: []string{"192.0.2.10"}, ObservedCanonicalName: &canonical,
				Warnings: []string{model.DNSWarnBanned, model.DNSWarnCGNAT}}
			dns.result = nginx.DNSApplyResult{Outcome: "accepted"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dns.confirming = cancel
			rec := callWithGrantsCtx(t, ctx, tc.call(h), both, http.MethodPost, exConfirmBody, tc.params...)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d; body %s", rec.Code, rec.Body)
			}
			var st model.DNSEntryStatus
			if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
				t.Fatal(err)
			}
			if st.Status != model.DNSStatusOK || !reflect.DeepEqual(st.Warnings, []string{model.DNSWarnCGNAT}) {
				t.Errorf("state = %+v, want ok without banned (no waf:read)", st)
			}
			want := "audit confirmed partner.example.com [192.0.2.10] partner.example.com [prio:" + exHostID + " trusted]"
			if last := calls.calls[len(calls.calls)-1]; last != want {
				t.Errorf("calls = %v, want %q last", calls.calls, want)
			}
		})
	}
}

// fakeDNSStatuses answers every name it is asked as ok with the banned and
// cgnat warnings, whatever the view: the handler must filter. It keeps the
// names and the view it was asked with.
type fakeDNSStatuses struct {
	asked [][]string
	view  model.DNSStatusView
	err   error
}

func (f *fakeDNSStatuses) Statuses(_ context.Context, names []string, view model.DNSStatusView) (map[string]model.DNSEntryStatus, error) {
	f.asked = append(f.asked, append([]string{}, names...))
	f.view = view
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]model.DNSEntryStatus, len(names))
	for _, n := range names {
		out[n] = model.DNSEntryStatus{Hostname: n, Status: model.DNSStatusOK, Warnings: []string{model.DNSWarnBanned, model.DNSWarnCGNAT}}
	}
	return out, nil
}

// withStatuses gives the handlers of s the fake state reader.
func (s *exceptionSave) withStatuses(f *fakeDNSStatuses) *exceptionSave {
	s.geo.dnsStatus = f
	s.security.dnsStatus = f
	s.settings.dnsStatus = f
	return s
}

// exAuthHostRow is the proxy_hosts row of host id with this Advanced Config
// (proxyHostRow, column 28).
func exAuthHostRow(id, advanced string) *sqlmock.Rows {
	row := proxyHostRow(id)
	row[28] = advanced
	return rowOf(row...)
}

// uriBlockListRow is one row of GET /uri-blocks (URIBlockRepository.ListAll).
func uriBlockListRow(hostID, advanced string, names ...string) *sqlmock.Rows {
	return rowOf("00000000-0000-4000-8000-0000000005c2", hostID, true,
		[]byte(`[{"id":"r1","pattern":"/admin","match_type":"prefix","enabled":true}]`), "{}", true, exTime, exTime,
		pqText("app.example.com"), true, pqText(names...), advanced)
}

// exceptionGet is one exception list GET: the queries it reads, and the
// field of its response that holds the state.
type exceptionGet struct {
	name   string
	field  string
	expect func(s *exceptionSave, names ...string)
	call   func(s *exceptionSave) echo.HandlerFunc
	params []string
}

func exceptionGets() []exceptionGet {
	return []exceptionGet{
		{"host URI block", "exception_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID, names...))
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exAuthHostRow(exHostID, ""))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetURIBlock }, []string{"proxyHostId", exHostID}},
		{"URI block list", "exception_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM uri_blocks ub`).WillReturnRows(uriBlockListRow(exHostID, "", names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.ListAllURIBlocks }, nil},
		{"global URI block", "exception_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(globalURIBlockRow(names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetGlobalURIBlock }, nil},
		{"host geo", "allowed_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, true))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(geoRow(exHostID, nil, names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.geo.GetByProxyHost }, []string{"id", exHostID}},
		{"global geo", "allowed_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow(nil, names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.geo.GetGlobal }, nil},
		{"host rate limit", "whitelist_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM rate_limits`).WithArgs(exHostID).WillReturnRows(rateLimitRow(exHostID, names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetRateLimit }, []string{"proxyHostId", exHostID}},
		{"global rate limit", "whitelist_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow(names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetGlobalRateLimit }, nil},
		{"system settings", "global_trusted_hostname_status", func(s *exceptionSave, names ...string) {
			s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("192.0.2.1", names...))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.settings.GetSystemSettings }, nil},
	}
}

// responseFields decodes a GET's body into its fields; for the URI block
// list, the first entry's.
func responseFields(t *testing.T, rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	expectStatus(t, rec, http.StatusOK)
	body := rec.Body.Bytes()
	if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 {
			t.Fatalf("body %s: %v", body, err)
		}
		return list[0]
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	return fields
}

// Each exception list's GET carries the state of its domains, one per name
// in the list's order, as the caller may see it: without waf:read the
// banned warning is left out, and the DNS service is asked without it too.
// The screens read these GETs already, so the state costs them no call.
func TestExceptionListGetsCarryDomainStatuses(t *testing.T) {
	names := []string{"b.example.com", "a.example.com"}
	for _, g := range exceptionGets() {
		for _, waf := range []bool{false, true} {
			name := g.name + "/without waf:read"
			if waf {
				name = g.name + "/with waf:read"
			}
			t.Run(name, func(t *testing.T) {
				statuses := &fakeDNSStatuses{}
				s := newExceptionSave(t).withStatuses(statuses)
				g.expect(s, names...)
				grants := permGrants{"proxy:read": true, "settings:read": true, "waf:read": waf}
				fields := responseFields(t, callWithGrants(t, g.call(s), grants, http.MethodGet, "", g.params...))
				var got []model.DNSEntryStatus
				if err := json.Unmarshal(fields[g.field], &got); err != nil {
					t.Fatalf("%s = %s: %v", g.field, fields[g.field], err)
				}
				want := []string{model.DNSWarnCGNAT}
				if waf {
					want = []string{model.DNSWarnBanned, model.DNSWarnCGNAT}
				}
				if len(got) != len(names) {
					t.Fatalf("%s = %s, want one state per name", g.field, fields[g.field])
				}
				for i, st := range got {
					if st.Hostname != names[i] || st.Status != model.DNSStatusOK || !reflect.DeepEqual(st.Warnings, want) {
						t.Errorf("%s[%d] = %+v, want %s ok with %v", g.field, i, st, names[i], want)
					}
				}
				if !reflect.DeepEqual(statuses.asked, [][]string{names}) || statuses.view.Banned != waf {
					t.Errorf("asked %v with view %+v", statuses.asked, statuses.view)
				}
			})
		}
	}
}

// What a GET says the configs leave out: priority allow and global trusted
// entries that are not addresses (a name typed there before #320; it stays
// stored and is only moved to the domains on request), and a host whose
// Advanced Config asks for a login, where no URI block exception domain is
// applied. A list without domains carries an empty state and asks the DNS
// service nothing.
func TestExceptionListGetsShowWhatTheConfigsLeaveOut(t *testing.T) {
	type check struct {
		field string
		want  string
	}
	for _, tc := range []struct {
		name   string
		expect func(s *exceptionSave)
		call   func(s *exceptionSave) echo.HandlerFunc
		params []string
		checks []check
	}{
		{"host geo", func(s *exceptionSave) {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, true))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).
				WillReturnRows(geoRow(exHostID, []string{"192.0.2.0/24", " legacy.example.com ", "192.0.2.300"}))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.geo.GetByProxyHost }, []string{"id", exHostID},
			[]check{{"allowed_ips_ignored", `["legacy.example.com","192.0.2.300"]`}, {"allowed_hostname_status", `[]`}}},
		{"host geo without a row", func(s *exceptionSave) {
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).WillReturnRows(exHostRow(exHostID, true))
			s.mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
		}, func(s *exceptionSave) echo.HandlerFunc { return s.geo.GetByProxyHost }, []string{"id", exHostID},
			[]check{{"allowed_ips_ignored", `[]`}, {"allowed_hostname_status", `[]`}}},
		{"global geo", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM global_geo_restrictions`).WillReturnRows(globalGeoRow([]string{"legacy.example.com", "192.0.2.1"}))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.geo.GetGlobal }, nil,
			[]check{{"allowed_ips_ignored", `["legacy.example.com"]`}, {"allowed_hostname_status", `[]`}}},
		{"system settings", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow("192.0.2.1\n old.example.com \n# office\n\n192.0.2.0/24"))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.settings.GetSystemSettings }, nil,
			[]check{{"global_trusted_ips_ignored", `["old.example.com"]`}, {"global_trusted_hostname_status", `[]`}}},
		{"system settings, every line used", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM system_settings`).WillReturnRows(settingsRow(""))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.settings.GetSystemSettings }, nil,
			[]check{{"global_trusted_ips_ignored", `[]`}}},
		{"host URI block, login in the Advanced Config", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(uriBlockRow(exHostID))
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).
				WillReturnRows(exAuthHostRow(exHostID, "location /admin {\n  auth_basic \"Restricted\";\n}"))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetURIBlock }, []string{"proxyHostId", exHostID},
			[]check{{"exception_hostnames_skipped", `true`}, {"exception_hostname_status", `[]`}}},
		{"host URI block, a comment that names a login", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(exHostID).WillReturnRows(noRows())
			s.mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(exHostID).
				WillReturnRows(exAuthHostRow(exHostID, "# auth_basic off;\nauth_request_set $user $upstream_http_x_user;"))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetURIBlock }, []string{"proxyHostId", exHostID},
			[]check{{"exception_hostnames_skipped", `false`}, {"exception_hostname_status", `[]`}}},
		{"URI block list, login in the Advanced Config", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM uri_blocks ub`).WillReturnRows(uriBlockListRow(exHostID, "auth_request /auth;"))
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.ListAllURIBlocks }, nil,
			[]check{{"exception_hostnames_skipped", `true`}, {"exception_hostname_status", `[]`}, {"domain_names", `["app.example.com"]`}}},
		{"host rate limit without domains", func(s *exceptionSave) {
			s.mock.ExpectQuery(`FROM rate_limits`).WithArgs(exHostID).WillReturnRows(noRows())
		}, func(s *exceptionSave) echo.HandlerFunc { return s.security.GetRateLimit }, []string{"proxyHostId", exHostID},
			[]check{{"whitelist_hostname_status", `[]`}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statuses := &fakeDNSStatuses{}
			s := newExceptionSave(t).withStatuses(statuses)
			tc.expect(s)
			fields := responseFields(t, callWithGrants(t, tc.call(s), permGrants{"proxy:read": true, "settings:read": true}, http.MethodGet, "", tc.params...))
			for _, c := range tc.checks {
				if got := string(fields[c.field]); got != c.want {
					t.Errorf("%s = %s, want %s", c.field, got, c.want)
				}
			}
			if len(statuses.asked) != 0 {
				t.Errorf("the DNS service was asked %v for a list without domains", statuses.asked)
			}
		})
	}
}

// A GET answers when the state cannot be read: the names are there, without
// their state.
func TestExceptionListGetAnswersWithoutTheState(t *testing.T) {
	s := newExceptionSave(t).withStatuses(&fakeDNSStatuses{err: errors.New("connection refused")})
	s.mock.ExpectQuery(`FROM global_rate_limits`).WillReturnRows(globalRateLimitRow("a.example.com"))
	fields := responseFields(t, callWithGrants(t, s.security.GetGlobalRateLimit, permGrants{"waf:read": true}, http.MethodGet, ""))
	if string(fields["whitelist_hostnames"]) != `["a.example.com"]` || string(fields["whitelist_hostname_status"]) != `[]` {
		t.Errorf("names %s, state %s", fields["whitelist_hostnames"], fields["whitelist_hostname_status"])
	}
}
