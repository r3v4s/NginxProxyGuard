package service

import (
	"reflect"
	"sort"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func gg(enabled bool) *model.GlobalGeoRestriction {
	return &model.GlobalGeoRestriction{
		Enabled:         enabled,
		Mode:            "blacklist",
		Countries:       []string{"CN"},
		AllowedIPs:      []string{"9.9.9.9"},
		AllowPrivateIPs: true,
	}
}

func TestResolveGeo_Override_UsesHost(t *testing.T) {
	host := &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || got.Mode != "whitelist" || !reflect.DeepEqual(got.Countries, []string{"KR"}) {
		t.Fatalf("override must use host geo, got %+v", got)
	}
}

func TestResolveGeo_Disable_NoBlock_PreservesAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: true, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || got.Enabled {
		t.Fatalf("disable must not produce an enabled geo block, got %+v", got)
	}
	if !reflect.DeepEqual(got.AllowedIPs, []string{"1.1.1.1"}) {
		t.Fatalf("disable must preserve host AllowedIPs for cloud/bot priority-allow, got %+v", got.AllowedIPs)
	}
}

func TestResolveGeo_Disable_NoAllowedIPs_Nil(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: true}
	if got := resolveGeo(gg(true), host); got != nil {
		t.Fatalf("disable with no AllowedIPs must be nil, got %+v", got)
	}
}

func TestResolveGeo_Inherit_UsesGlobal_UnionsHostAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || !got.Enabled || got.Mode != "blacklist" {
		t.Fatalf("inherit must use enabled global geo, got %+v", got)
	}
	sorted := append([]string{}, got.AllowedIPs...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("inherit must union host+global AllowedIPs, got %+v", got.AllowedIPs)
	}
}

func TestResolveGeo_Inherit_GlobalOff_NoBlock(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false}
	got := resolveGeo(gg(false), host)
	if got != nil && got.Enabled {
		t.Fatalf("global off + inherit must not block, got %+v", got)
	}
}

func TestResolveGeo_Inherit_GlobalOff_KeepsHostAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(false), host)
	if got == nil || got.Enabled || !reflect.DeepEqual(got.AllowedIPs, []string{"1.1.1.1"}) {
		t.Fatalf("global off must keep host AllowedIPs disabled, got %+v", got)
	}
}

func TestResolveGeo_NoHostRow_Inherits(t *testing.T) {
	got := resolveGeo(gg(true), nil)
	if got == nil || !got.Enabled {
		t.Fatalf("no host row must inherit enabled global, got %+v", got)
	}
}

func TestResolveGeo_NoHostRow_GlobalOff_Nil(t *testing.T) {
	if got := resolveGeo(gg(false), nil); got != nil {
		t.Fatalf("no host + global off must be nil, got %+v", got)
	}
}

// dnsTestHostID is a host of the domain tests (#320): a UUID, as the scope of
// a host's list needs one.
const dnsTestHostID = "00000000-0000-0000-0000-0000000000d2"

// A host's priority allow domains alone keep the row alive in every branch
// where the host's own geo restriction does not run: the cloud and bot
// sections still read them. Each keeps the host's scope. An overriding host
// gets a copy with its own names only.
func TestResolveGeoKeepsADomainOnlyPriorityAllow(t *testing.T) {
	want := []model.DNSRef{{Scope: "prio:" + dnsTestHostID, Name: "partner.example.com"}}
	global := gg(true)
	global.AllowedHostnames = []string{"office.example.com"}
	for _, tc := range []struct {
		name   string
		global *model.GlobalGeoRestriction
		host   model.GeoRestriction
	}{
		{"geo off, no global default", nil, model.GeoRestriction{}},
		{"disable", global, model.GeoRestriction{DisableGlobal: true}},
		{"inherit, global off", gg(false), model.GeoRestriction{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := tc.host
			host.ProxyHostID = dnsTestHostID
			host.AllowedHostnames = []string{"partner.example.com"}
			got := resolveGeo(tc.global, &host)
			if got == nil || got.Enabled {
				t.Fatalf("got %+v, want a geo restriction that is off and keeps the names", got)
			}
			if !reflect.DeepEqual(got.AllowedDNS, want) {
				t.Fatalf("AllowedDNS = %+v, want %+v", got.AllowedDNS, want)
			}
		})
	}

	host := &model.GeoRestriction{ProxyHostID: dnsTestHostID, Enabled: true, Mode: "whitelist", Countries: []string{"KR"},
		AllowedHostnames: []string{"partner.example.com"}}
	got := resolveGeo(global, host)
	if got == nil || got == host || got.Mode != "whitelist" || !reflect.DeepEqual(got.AllowedDNS, want) {
		t.Fatalf("override = %+v, want a copy of the host row with AllowedDNS %+v", got, want)
	}
	if host.AllowedDNS != nil {
		t.Errorf("the host row was changed: AllowedDNS %+v", host.AllowedDNS)
	}
}

// An inheriting host renders its own names and the global ones. A name on
// both lists is rendered once, with the host's scope: a geo block lists each
// name's addresses once.
func TestResolveGeoUnionsDomainsHostScopeWins(t *testing.T) {
	global := gg(true)
	global.AllowedHostnames = []string{"office.example.com", "partner.example.com"}
	host := &model.GeoRestriction{ProxyHostID: dnsTestHostID, AllowedHostnames: []string{"partner.example.com", "shop.example.com"}}
	want := []model.DNSRef{
		{Scope: "prio:" + dnsTestHostID, Name: "partner.example.com"},
		{Scope: "prio:" + dnsTestHostID, Name: "shop.example.com"},
		{Scope: "prio:global", Name: "office.example.com"},
	}
	if got := resolveGeo(global, host); got == nil || !got.Enabled || !reflect.DeepEqual(got.AllowedDNS, want) {
		t.Fatalf("inherit = %+v, want AllowedDNS %+v", got, want)
	}
	onlyGlobal := []model.DNSRef{{Scope: "prio:global", Name: "office.example.com"}, {Scope: "prio:global", Name: "partner.example.com"}}
	if got := resolveGeo(global, nil); got == nil || !reflect.DeepEqual(got.AllowedDNS, onlyGlobal) {
		t.Fatalf("no host row = %+v, want AllowedDNS %+v", got, onlyGlobal)
	}
}
