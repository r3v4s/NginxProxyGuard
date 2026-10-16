package handler

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// accessListResponse is the part of a list response these tests read.
type accessListResponse struct {
	Items []struct {
		Directive string                `json:"directive"`
		Address   string                `json:"address"`
		Kind      string                `json:"kind"`
		Effect    string                `json:"effect"`
		DNS       *model.DNSEntryStatus `json:"dns"`
	} `json:"items"`
	LoginBypassHosts struct {
		Count int                `json:"count"`
		Hosts []model.DNSHostRef `json:"hosts"`
	} `json:"login_bypass_hosts"`
}

// getList runs GET /access-lists/:id as a user holding g.
func getList(t *testing.T, h *AccessListHandler, g permGrants) accessListResponse {
	t.Helper()
	rec := callWithGrants(t, h.Get, g, http.MethodGet, "", "id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	var v accessListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	return v
}

// partnersList holds an address rule, two names an older version saved and
// a domain rule, as the repository returns them.
func partnersList(satisfyAny bool) *model.AccessList {
	return &model.AccessList{ID: testListID, Name: "partners", SatisfyAny: satisfyAny, Items: []model.AccessListItem{
		addressRule("allow", "192.0.2.10", 0),
		addressRule("allow", "old.example.com", 1),
		addressRule("deny", "bad.example.com", 2),
		domainRule("partner.example.com", 3),
	}}
}

// The API shows a domain rule as allow <name> with kind hostname and its
// state, a name an older version saved as a legacy rule with what the config
// does with it, and an address rule as before.
func TestAccessListResponsesShowEachRuleKind(t *testing.T) {
	h, _, dns, _ := newDNSListHandler(partnersList(true))
	dns.statuses = map[string]model.DNSEntryStatus{"partner.example.com": {
		Hostname: "partner.example.com", Status: model.DNSStatusOK, Addresses: []string{"203.0.113.10"},
	}}
	v := getList(t, h, permGrants{"access:read": true})
	type rule struct{ Directive, Address, Kind, Effect string }
	var got []rule
	for _, it := range v.Items {
		got = append(got, rule{it.Directive, it.Address, it.Kind, it.Effect})
	}
	want := []rule{
		{"allow", "192.0.2.10", "address", ""},
		{"allow", "old.example.com", "legacy", "ignored"},
		{"deny", "bad.example.com", "legacy", "deny_all"},
		{"allow", "partner.example.com", "hostname", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %+v, want %+v", got, want)
	}
	for i := 0; i < 3; i++ {
		if v.Items[i].DNS != nil {
			t.Errorf("rule %d carries a domain state", i)
		}
	}
	if st := v.Items[3].DNS; st == nil || st.Status != model.DNSStatusOK || !reflect.DeepEqual(st.Addresses, []string{"203.0.113.10"}) {
		t.Errorf("domain state = %+v", st)
	}
}

// A caller sees banned only with waf:read, self_ip only with ddns:read, and
// the blocking file and the login hosts' names only with proxy:read.
// The number of login hosts is always there.
func TestAccessListResponsesShowOnlyWhatTheCallerMayRead(t *testing.T) {
	file := "proxy_host_x.conf"
	host := model.DNSHostRef{ID: "00000000-0000-4000-8000-0000000016c1", Domain: "app.example.com"}
	get := func(g permGrants) (accessListResponse, *fakeAccessListDNS) {
		h, _, dns, _ := newDNSListHandler(partnersList(true))
		dns.statuses = map[string]model.DNSEntryStatus{"partner.example.com": {
			Hostname: "partner.example.com", Status: model.DNSStatusOK, BlockingFile: &file,
			Warnings: []string{model.DNSWarnBanned, model.DNSWarnSelfIP, model.DNSWarnCGNAT},
		}}
		dns.bypass = []model.DNSHostRef{host}
		return getList(t, h, g), dns
	}

	v, dns := get(permGrants{"access:read": true, "waf:read": true, "ddns:read": true, "proxy:read": true})
	st := v.Items[3].DNS
	if dns.view != (model.DNSStatusView{Banned: true, SelfIP: true, BlockingFile: true}) || len(st.Warnings) != 3 ||
		st.BlockingFile == nil || *st.BlockingFile != file {
		t.Errorf("full reader: asked with view %+v, state %+v", dns.view, st)
	}
	if v.LoginBypassHosts.Count != 1 || !reflect.DeepEqual(v.LoginBypassHosts.Hosts, []model.DNSHostRef{host}) {
		t.Errorf("full reader: login hosts %+v", v.LoginBypassHosts)
	}

	v, dns = get(permGrants{"access:read": true})
	st = v.Items[3].DNS
	if dns.view != (model.DNSStatusView{}) || !reflect.DeepEqual(st.Warnings, []string{model.DNSWarnCGNAT}) || st.BlockingFile != nil {
		t.Errorf("access:read only: asked with view %+v, state %+v", dns.view, st)
	}
	if v.LoginBypassHosts.Count != 1 || v.LoginBypassHosts.Hosts != nil {
		t.Errorf("access:read only: login hosts %+v, want the count without names", v.LoginBypassHosts)
	}
}

// Only a satisfy-any list with domains lets them skip a host's login; other
// lists show 0 whatever the host index holds.
func TestAccessListLoginBypassNeedsSatisfyAnyAndDomains(t *testing.T) {
	for name, list := range map[string]*model.AccessList{
		"satisfy all": partnersList(false),
		"no domain":   {ID: testListID, Name: "office", SatisfyAny: true, Items: []model.AccessListItem{addressRule("allow", "192.0.2.10", 0)}},
	} {
		h, _, dns, _ := newDNSListHandler(list)
		dns.bypass = []model.DNSHostRef{{ID: "00000000-0000-4000-8000-0000000016c1", Domain: "app.example.com"}}
		if v := getList(t, h, permGrants{"access:read": true, "proxy:read": true}); v.LoginBypassHosts.Count != 0 {
			t.Errorf("%s: %d login hosts, want 0", name, v.LoginBypassHosts.Count)
		}
	}
}

// A client that saves back what it read leaves every rule what it was: a
// legacy rule stays legacy (only kind=hostname makes a domain), and a client
// that drops kind keeps the domain it read.
func TestAccessListGetThenPutKeepsEveryRuleWhatItWas(t *testing.T) {
	stored := []model.AccessListItem{
		addressRule("allow", "192.0.2.10", 0),
		addressRule("allow", "old.example.com", 1),
		domainRule("partner.example.com", 2),
	}
	h, _, _, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners", Items: stored})
	rec := callWithGrants(t, h.Get, listWriter, http.MethodGet, "", "id", testListID)
	var read model.UpdateAccessListRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	kindless := make([]model.CreateAccessListItemRequest, len(read.Items))
	for i, it := range read.Items {
		it.Kind = ""
		kindless[i] = it
	}
	want := []string{"address allow 192.0.2.10", "legacy allow old.example.com", "hostname deny all partner.example.com"}
	for name, items := range map[string][]model.CreateAccessListItemRequest{"as read": read.Items, "without kind": kindless} {
		req := model.UpdateAccessListRequest{Items: items}
		if err := model.ValidateUpdateAccessListRequest(&req, stored); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, it := range req.Items {
			got = append(got, strings.TrimSpace(it.Kind+" "+it.Directive+" "+it.Address+" "+it.Hostname))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: saved as %q, want %q", name, got, want)
		}
	}
}
