package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// dnsTestHosts serves the hosts of each list and their config data.
type dnsTestHosts struct {
	byList map[string][]model.ProxyHost
	data   map[string]nginx.ProxyHostConfigData
	fail   map[string]bool
}

func (h *dnsTestHosts) GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error) {
	return append([]model.ProxyHost(nil), h.byList[accessListID]...), nil
}

func (h *dnsTestHosts) BuildConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error) {
	if h.fail[host.ID] {
		return nginx.ProxyHostConfigData{}, errors.New("geo lookup failed")
	}
	return h.data[host.ID], nil
}

// add registers a host using list with the given config data.
func (h *dnsTestHosts) add(host model.ProxyHost, list *model.AccessList, data nginx.ProxyHostConfigData) {
	cp := host
	data.Host, data.AccessList = &cp, list
	h.byList[list.ID] = append(h.byList[list.ID], host)
	h.data[host.ID] = data
}

const (
	dnsGateH1 = "00000000-0000-4000-8000-000000000001" // satisfy all
	dnsGateH2 = "00000000-0000-4000-8000-000000000002" // satisfy any + ForwardAuth
	dnsGateH3 = "00000000-0000-4000-8000-000000000003" // satisfy any + auth_basic inside a location
	dnsGateH4 = "00000000-0000-4000-8000-000000000004" // satisfy any + ForwardAuth + geo challenge
	dnsGateH5 = "00000000-0000-4000-8000-000000000005" // Advanced Config allow/deny of its own
	dnsGateH7 = "00000000-0000-4000-8000-000000000007" // stream host
	dnsGateH8 = "00000000-0000-4000-8000-000000000008" // config data cannot be built
	dnsGateH9 = "00000000-0000-4000-8000-000000000009" // disabled
)

// dnsGateRig: list A (satisfy all) and list B (satisfy any) both hold
// partner.example.com, published as 203.0.113.10; nginx may still allow
// 203.0.113.9, removed from list A's file a moment ago.
func dnsGateRig(t *testing.T) (*dnsTestRig, *dnsTestHosts) {
	t.Helper()
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.svc.pendingRevoke[dnsSegKey(dnsACL(dnsTestListA), "partner.example.com")] = dnsRevokeEntry{
		Scope: dnsACL(dnsTestListA), Name: "partner.example.com", Gen: 2, Addrs: []string{"203.0.113.9"}}

	items := []model.AccessListItem{
		{Directive: "allow", Address: "198.51.100.7"},
		{Directive: "deny", Address: "198.51.100.0/24"},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}
	listA := &model.AccessList{ID: dnsTestListA, Items: items}
	listB := &model.AccessList{ID: dnsTestListB, SatisfyAny: true, Items: items}
	forwardAuth := &model.AuthProvider{ID: "p1", Enabled: true}
	trusted := []string{"192.0.2.5"}
	host := func(id, domain string) model.ProxyHost {
		return model.ProxyHost{ID: id, DomainNames: []string{domain}, Enabled: true}
	}
	h := &dnsTestHosts{byList: map[string][]model.ProxyHost{}, data: map[string]nginx.ProxyHostConfigData{}, fail: map[string]bool{}}
	h.add(host(dnsGateH1, "app1.example.com"), listA, nginx.ProxyHostConfigData{GlobalTrustedIPs: trusted})
	h.add(host(dnsGateH2, "app2.example.com"), listB, nginx.ProxyHostConfigData{AuthProvider: forwardAuth})
	h3 := host(dnsGateH3, "app3.example.com")
	h3.AdvancedConfig = "location /admin { auth_basic \"admin\"; auth_basic_user_file /etc/nginx/htpasswd; }"
	h.add(h3, listB, nginx.ProxyHostConfigData{})
	h.add(host(dnsGateH4, "app4.example.com"), listB, nginx.ProxyHostConfigData{AuthProvider: forwardAuth,
		GeoRestriction: &model.GeoRestriction{Enabled: true, ChallengeMode: true}})
	h5 := host(dnsGateH5, "app5.example.com")
	h5.AdvancedConfig = "location /status { allow all; }"
	h.add(h5, listA, nginx.ProxyHostConfigData{})
	h7 := host(dnsGateH7, "app7.example.com")
	h7.ProxyType = model.ProxyTypeStream
	h.add(h7, listA, nginx.ProxyHostConfigData{})
	h.add(host(dnsGateH8, "app8.example.com"), listA, nginx.ProxyHostConfigData{})
	h.fail[dnsGateH8] = true
	h9 := host(dnsGateH9, "app9.example.com")
	h9.Enabled = false
	h.add(h9, listA, nginx.ProxyHostConfigData{})
	r.svc.hosts, r.svc.builder = h, h
	r.svc.rebuildHostIndex(context.Background(), r.mustRefs(), "")
	return r, h
}

// The fail2ban gate table: which host 403s are left out of fail2ban.
func TestDNSExemptAccessDenial(t *testing.T) {
	r, _ := dnsGateRig(t)
	cases := []struct {
		host, client string
		exempt       bool
		why          string
	}{
		{dnsGateH1, "203.0.113.99", true, "outside the list: the list's own 403"},
		{dnsGateH1, "::ffff:203.0.113.99", true, "an IPv4-mapped client is the IPv4 client"},
		{dnsGateH1, "198.51.100.8", true, "the list's explicit deny"},
		{dnsGateH1, "192.0.2.5", false, "a global trusted IP is allowed"},
		{dnsGateH1, "198.51.100.7", false, "an IP row allows it"},
		{dnsGateH1, "203.0.113.10", false, "a domain address allows it"},
		{dnsGateH1, "203.0.113.9", false, "a revocation nginx may not have taken yet"},
		{dnsGateH1, "not-an-address", false, "unreadable client"},
		{dnsGateH2, "203.0.113.99", false, "satisfy any + ForwardAuth: the login decides"},
		{dnsGateH3, "203.0.113.99", false, "satisfy any + auth_basic in a location"},
		{dnsGateH4, "203.0.113.99", true, "next to the challenge gate satisfy any is not rendered"},
		{dnsGateH5, "203.0.113.99", false, "Advanced Config with allow/deny of its own"},
		{dnsGateH7, "203.0.113.99", false, "stream host"},
		{dnsGateH8, "203.0.113.99", false, "config data could not be built"},
		{dnsGateH9, "203.0.113.99", false, "disabled host"},
		{"00000000-0000-4000-8000-0000000000ff", "203.0.113.99", false, "a host without a domain list"},
	}
	for _, c := range cases {
		if got := r.svc.ExemptAccessDenial(context.Background(), c.host, c.client); got != c.exempt {
			t.Errorf("%s (%s %s): exempt = %v, want %v", c.why, c.host[len(c.host)-2:], c.client, got, c.exempt)
		}
	}
}

func TestDNSLoginBypassHosts(t *testing.T) {
	r, h := dnsGateRig(t)
	got := r.svc.LoginBypassHosts(dnsTestListB)
	if len(got) != 2 || got[0].ID != dnsGateH2 || got[0].Domain != "app2.example.com" || got[1].ID != dnsGateH3 {
		t.Fatalf("list B = %+v, want app2 (ForwardAuth) and app3 (auth_basic); app4's challenge gate keeps the login", got)
	}
	if got := r.svc.LoginBypassHosts(dnsTestListA); len(got) != 0 {
		t.Fatalf("list A (satisfy all) = %+v, want none", got)
	}

	// Rebuilding one list keeps the others.
	h.byList[dnsTestListB] = nil
	r.svc.rebuildHostIndex(context.Background(), r.mustRefs(), dnsTestListB)
	if got := r.svc.LoginBypassHosts(dnsTestListB); len(got) != 0 {
		t.Fatalf("list B after its rebuild = %+v, want none", got)
	}
	if !r.svc.ExemptAccessDenial(context.Background(), dnsGateH1, "203.0.113.99") {
		t.Fatal("list A's hosts must survive a rebuild of list B")
	}
}

// Building the host index costs about a dozen queries per host, so a
// check rebuilds it only when there is none or it is 5 minutes old. A mark
// (a list save, a settings change, a reload nginx took) rebuilds it at once,
// in the background, and the check after that does not build it again.
func TestDNSHostIndexIsRebuiltEveryFiveMinutesOrWhenMarked(t *testing.T) {
	r, _ := dnsGateRig(t)
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.10")
	r.svc.hostIdx.Store(nil)

	r.tick(t)
	first := r.svc.hostIdx.Load()
	r.clock.Advance(4 * time.Minute)
	r.tick(t)
	if first == nil || r.svc.hostIdx.Load() != first {
		t.Fatal("two checks within 5 minutes must build the host index once")
	}

	r.clock.Advance(time.Minute)
	r.tick(t)
	aged := r.svc.hostIdx.Load()
	if aged == first {
		t.Fatal("a check 5 minutes after the last build must rebuild the host index")
	}

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // e.g. a host save's reload
	r.settle()
	taken := r.svc.hostIdx.Load()
	if taken == aged {
		t.Fatal("a reload nginx took must rebuild the host index at once")
	}
	r.clock.Advance(time.Minute)
	r.tick(t)
	if r.svc.hostIdx.Load() != taken {
		t.Fatal("the check after that rebuild must not build the host index again")
	}

	r.svc.SettingsChanged(context.Background(), model.DefaultDNSEntrySettings(), model.DefaultDNSEntrySettings())
	r.settle()
	if r.svc.hostIdx.Load() == taken {
		t.Fatal("a settings change must rebuild the host index at once")
	}
}

// dnsBlockingHosts holds every read of list A's hosts until it is opened, so
// a test can look at the fail2ban gate while a rebuild of the host index
// runs. Each build reads list A once: reads counts the builds, most the
// builds that ever ran at once.
type dnsBlockingHosts struct {
	*dnsTestHosts
	started chan struct{} // one value each time a read of list A begins
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	reads   int
	running int
	most    int
}

func newDNSBlockingHosts(t *testing.T, h *dnsTestHosts) *dnsBlockingHosts {
	b := &dnsBlockingHosts{dnsTestHosts: h, started: make(chan struct{}, 16), release: make(chan struct{})}
	t.Cleanup(b.open) // runs before the rig waits for its goroutines
	return b
}

func (b *dnsBlockingHosts) GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error) {
	if accessListID == dnsTestListA {
		b.mu.Lock()
		b.reads++
		b.running++
		b.most = max(b.most, b.running)
		b.mu.Unlock()
		b.started <- struct{}{}
		<-b.release
		b.mu.Lock()
		b.running--
		b.mu.Unlock()
	}
	return b.dnsTestHosts.GetByAccessListID(ctx, accessListID)
}

// open lets every read go on.
func (b *dnsBlockingHosts) open() { b.once.Do(func() { close(b.release) }) }

// waitBuild waits until a rebuild reads list A's hosts.
func (b *dnsBlockingHosts) waitBuild(t *testing.T) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("no rebuild of the host index started")
	}
}

func (b *dnsBlockingHosts) counts() (reads, most int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reads, b.most
}

// After a reload the index may no longer say what a host renders. Until a
// rebuild that began after the reload is in place, the gate leaves nothing
// out: every 403 is counted.
func TestDNSMarkedHostIndexExemptsNothingUntilItIsRebuilt(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99") {
		t.Fatal("before the reload, the list's own 403 must be left out")
	}
	hosts := newDNSBlockingHosts(t, h)
	r.svc.hosts = hosts

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // a host save's reload
	hosts.waitBuild(t)
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99") {
		t.Fatal("while the host index is rebuilt after a reload, a 403 must be counted")
	}
	hosts.open()
	r.settle()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99") {
		t.Fatal("once the rebuild is in place, the list's own 403 must be left out again")
	}
}

// A burst of reloads (SyncAll, a run of saves) marks the index again and
// again. Marks made while a rebuild runs start no rebuild of their own:
// exactly one more rebuild, after the running one, covers them all.
func TestDNSMarksDuringARebuildShareOneMoreRebuild(t *testing.T) {
	r, h := dnsGateRig(t)
	hosts := newDNSBlockingHosts(t, h)
	r.svc.hosts = hosts

	r.svc.markHostIndexDirty()
	hosts.waitBuild(t)
	for i := 0; i < 5; i++ {
		r.svc.markHostIndexDirty()
	}
	hosts.open()
	r.settle()

	if reads, most := hosts.counts(); reads != 2 || most != 1 {
		t.Fatalf("%d rebuilds, at most %d at once; want the running one and exactly one more for the five marks, never two at once", reads, most)
	}
	if !r.svc.ExemptAccessDenial(context.Background(), dnsGateH1, "203.0.113.99") {
		t.Fatal("after the rebuilds the index must be current again")
	}
}

// A host save that changes what the host renders reloads nginx, and the
// reload rebuilds the host index at once, without waiting for a check: a
// host that dropped its domain list stops being exempt, the others stay.
func TestDNSAReloadRebuildsTheHostIndexAtOnce(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	var kept []model.ProxyHost
	for _, host := range h.byList[dnsTestListA] {
		if host.ID != dnsGateH1 {
			kept = append(kept, host)
		}
	}
	h.byList[dnsTestListA] = kept // app1 no longer uses list A

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // app1's save reloads nginx
	r.settle()

	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99") {
		t.Error("app1 dropped its domain list: its 403s must be counted")
	}
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH4, "203.0.113.99") {
		t.Error("app4 still uses its list: once the index is rebuilt, its list's own 403 must be left out")
	}
}
