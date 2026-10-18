package service

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

func TestDNSStatusOf(t *testing.T) {
	st := model.DefaultDNSEntrySettings()
	now := dnsTestStart
	checked := now.Add(-30 * time.Second)
	lastReload := now.Add(-2 * time.Minute)
	full := model.DNSStatusView{Banned: true, SelfIP: true, BlockingFile: true}
	none := model.DNSStatusView{}

	ok := dnsOKRow("partner.example.com", 3, "203.0.113.10")
	ok.Warnings = []string{model.DNSWarnBanned, model.DNSWarnCGNAT, model.DNSWarnSelfIP}
	got := dnsStatusOf(ok, st, dnsApplyView{}, time.Time{}, now, none)
	if got.Status != "ok" || !got.Applied || !dnsEqual(got.Addresses, []string{"203.0.113.10"}) ||
		got.Families["ipv4"].State != "ok" || got.Families["ipv6"].State != "not_found" || got.PendingAddresses != nil {
		t.Errorf("ok name: %+v", got)
	}
	if len(got.Warnings) != 1 || got.Warnings[0] != model.DNSWarnCGNAT {
		t.Errorf("warnings without waf:read and ddns:read = %v, want banned and self_ip left out", got.Warnings)
	}
	if got := dnsStatusOf(ok, st, dnsApplyView{}, time.Time{}, now, model.DNSStatusView{SelfIP: true}); !dnsEqual(got.Warnings, []string{model.DNSWarnCGNAT, model.DNSWarnSelfIP}) {
		t.Errorf("warnings with ddns:read only = %v, want cgnat and self_ip", got.Warnings)
	}
	if got := dnsStatusOf(ok, st, dnsApplyView{}, time.Time{}, now, full); len(got.Warnings) != 3 {
		t.Errorf("warnings with every permission = %v, want all three", got.Warnings)
	}

	waiting := dnsOKRow("partner.example.com", 3, "203.0.113.10")
	waiting.Candidate = []string{"203.0.113.10", "203.0.113.11"}
	waiting.LastCheckedAt = &checked
	got = dnsStatusOf(waiting, st, dnsApplyView{}, lastReload, now, none)
	if !dnsEqual(got.PendingAddresses, []string{"203.0.113.11"}) || got.NextApplyAt == nil || !got.NextApplyAt.Equal(lastReload.Add(5*time.Minute)) {
		t.Errorf("waiting addition: pending %v at %v, want 203.0.113.11 once the 5 minute gap has passed", got.PendingAddresses, got.NextApplyAt)
	}

	review := model.DNSEntryState{Hostname: "partner.example.com", Status: model.DNSStatusNeedsReview, ReviewReason: model.DNSReviewCNAMEChanged,
		CanonicalName: "a.ddns.example.com", CanonicalSeen: "b.cdn.example.com", Candidate: []string{"203.0.113.20"}}
	got = dnsStatusOf(review, st, dnsApplyView{}, time.Time{}, now, none)
	if got.ReviewReason == nil || *got.ReviewReason != "cname_changed" || !dnsEqual(got.ObservedAddresses, []string{"203.0.113.20"}) ||
		got.ObservedCanonicalName == nil || *got.ObservedCanonicalName != "b.cdn.example.com" || got.PendingAddresses != nil {
		t.Errorf("review: %+v, want the observed addresses and target for the confirm dialog", got)
	}

	answered := now.Add(-time.Hour)
	stale := dnsOKRow("partner.example.com", 3, "203.0.113.10")
	stale.Status = model.DNSStatusStale
	stale.V4 = model.DNSFamilyState{State: "transient", Code: "timeout", AnswerAt: &answered, Observed: []string{"203.0.113.10"}}
	got = dnsStatusOf(stale, st, dnsApplyView{}, time.Time{}, now, none)
	if got.ErrorCode == nil || *got.ErrorCode != "timeout" || got.StaleUntil == nil || !got.StaleUntil.Equal(answered.Add(24*time.Hour)) {
		t.Errorf("stale: code %v until %v, want timeout until the last answer + 24 h", got.ErrorCode, got.StaleUntil)
	}

	// Both families answered but the CNAME check did not decide: additions
	// wait. A failing family's code comes first.
	undecided := dnsOKRow("partner.example.com", 3, "203.0.113.10")
	undecided.CanonicalSeen = ""
	undecided.Candidate = []string{"203.0.113.10", "203.0.113.11"}
	firstAnswer := model.DNSEntryState{Hostname: "new.example.com", Status: model.DNSStatusPending, Candidate: []string{"203.0.113.30"},
		V4: model.DNSFamilyState{State: "ok", Observed: []string{"203.0.113.30"}}, V6: model.DNSFamilyState{State: "notfound", Code: "not_found"}}
	staleUndecided := stale
	staleUndecided.CanonicalSeen = ""
	// A new name with no usable answer stays pending; its first failing
	// family says why, so a name that does not exist (a typo, a name not
	// registered yet) does not show only "pending" forever.
	noSuchName := model.DNSEntryState{Hostname: "missing.example.com", Status: model.DNSStatusPending, LastCheckedAt: &checked,
		V4: model.DNSFamilyState{State: "notfound", Code: "not_found", NotFound: 3}, V6: model.DNSFamilyState{State: "notfound", Code: "not_found", NotFound: 3}}
	refusedFirst := noSuchName
	refusedFirst.V4 = model.DNSFamilyState{State: "rejected", Code: "private"}
	unchecked := model.DNSEntryState{Hostname: "new.example.com", Status: model.DNSStatusPending}
	for _, c := range []struct {
		name string
		row  model.DNSEntryState
		want string
	}{
		{"ok, CNAME undecided", undecided, "cname_indeterminate"},
		{"pending, CNAME undecided", firstAnswer, "cname_indeterminate"},
		{"stale, CNAME undecided", staleUndecided, "timeout"},
		{"ok, CNAME decided", ok, ""},
		{"pending, no such name", noSuchName, "not_found"},
		{"pending, refused address", refusedFirst, "private"},
		{"pending, not checked yet", unchecked, ""},
	} {
		code := ""
		if got := dnsStatusOf(c.row, st, dnsApplyView{}, time.Time{}, now, full); got.ErrorCode != nil {
			code = *got.ErrorCode
		}
		if code != c.want {
			t.Errorf("%s: error code %q, want %q", c.name, code, c.want)
		}
	}

	since := now
	revoking := dnsOKRow("partner.example.com", 4)
	revoking.AppliedGeneration, revoking.RevokePendingSince = 3, &since
	failed := dnsApplyView{failing: true, last: nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_shop_example_com.conf"}}
	got = dnsStatusOf(revoking, st, failed, time.Time{}, now, full)
	if !got.RevokePending || got.BlockedReason == nil || *got.BlockedReason != "blocked" || got.BlockingFile == nil {
		t.Errorf("blocked revocation: %+v, want revoke_pending with the failed outcome and file", got)
	}
	if got := dnsStatusOf(revoking, st, failed, time.Time{}, now, none); got.BlockedReason == nil || got.BlockingFile != nil {
		t.Errorf("blocked revocation without proxy:read: %+v, want the outcome and no file", got)
	}
	if got := dnsStatusOf(ok, st, failed, time.Time{}, now, full); got.BlockedReason != nil {
		t.Errorf("an applied name is not blocked: %+v", got)
	}
}

// dnsTestWarnSources serves the warning inputs.
type dnsTestWarnSources struct {
	ddns       []model.DDNSRecord
	ipv6       bool
	globalBans []model.BannedIP
	hostBans   map[string][]model.BannedIP
}

func (w *dnsTestWarnSources) ListEnabled(ctx context.Context) ([]model.DDNSRecord, error) {
	return w.ddns, nil
}

func (w *dnsTestWarnSources) Get(ctx context.Context) (*model.GlobalSettings, error) {
	return &model.GlobalSettings{EnableIPv6: w.ipv6}, nil
}

func (w *dnsTestWarnSources) GetActiveGlobalBans(ctx context.Context) ([]model.BannedIP, error) {
	return w.globalBans, nil
}

func (w *dnsTestWarnSources) GetActiveBansForHost(ctx context.Context, proxyHostID string) ([]model.BannedIP, error) {
	return w.hostBans[proxyHostID], nil
}

func TestDNSRefreshWarnings(t *testing.T) {
	r, _ := dnsGateRig(t) // dnsGateH1 uses list A
	ctx := context.Background()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "shop.example.com"),
		dnsRef(dnsTestListA, "cg.example.com"), dnsRef(dnsTestListB, "dup1.example.com"), dnsRef(dnsTestListB, "dup2.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	r.store.put(dnsOKRow("shop.example.com", 1, "198.51.100.7"))
	r.store.put(dnsOKRow("cg.example.com", 1, "100.64.32.10"))
	r.store.put(dnsOKRow("dup1.example.com", 1, "203.0.113.50"))
	r.store.put(dnsOKRow("dup2.example.com", 1, "203.0.113.50", "2001:db8::50"))
	src := &dnsTestWarnSources{
		ddns: []model.DDNSRecord{
			{Hostname: "home.example.com", LastIP: " 203.0.113.10", LastStatus: model.DDNSStatusOK},
			{Hostname: "old.example.com", LastIP: "198.51.100.7", LastStatus: model.DDNSStatusError},
		},
		ipv6: true,
		// A ban inside a static global trusted entry is not enforced.
		globalBans: []model.BannedIP{{IPAddress: "100.64.32.10"}},
		hostBans:   map[string][]model.BannedIP{dnsGateH1: {{IPAddress: " 198.51.100.0/24"}}},
	}
	r.settings.mu.Lock()
	r.settings.trusted = "100.64.32.0/24"
	r.settings.mu.Unlock()
	r.svc.selfIPs, r.svc.global, r.svc.bans = src, src, src
	r.svc.rebuildHostIndex(ctx, r.mustRefs(), "")

	r.svc.refreshWarnings(ctx, r.mustRefs(), map[string]dnsentry.ObserveNotes{"partner.example.com": {PartialRejected: true}})

	want := map[string][]string{
		"partner.example.com": {model.DNSWarnIPv6Listen, model.DNSWarnPartialRejected, model.DNSWarnSelfIP},
		"shop.example.com":    {model.DNSWarnBanned, model.DNSWarnIPv6Listen},
		"cg.example.com":      {model.DNSWarnCGNAT, model.DNSWarnIPv6Listen},
		"dup1.example.com":    {model.DNSWarnDuplicate, model.DNSWarnIPv6Listen},
		"dup2.example.com":    {model.DNSWarnDuplicate},
	}
	for name, w := range want {
		st, _ := r.store.row(name)
		if !dnsEqual(st.Warnings, w) {
			t.Errorf("%s: warnings = %v, want %v", name, st.Warnings, w)
		}
	}

	// A check without an answer for partner keeps partial_rejected.
	r.svc.refreshWarnings(ctx, r.mustRefs(), nil)
	if st, _ := r.store.row("partner.example.com"); !dnsEqual(st.Warnings, want["partner.example.com"]) {
		t.Errorf("partner without a new answer: warnings = %v, want them kept", st.Warnings)
	}
}

// A ban wins over every exception list, but a host's ban only on that host.
// A name in one host's URI block exceptions, priority allow or rate limit
// exceptions is warned about for that host's bans; a name in a global list
// or the global trusted list only for the global bans.
func TestBannedWarningOfAHostScopeUsesThatHostsBans(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	const hostA, hostB = dnsGateH1, dnsGateH2
	use := func(scope, name, ownerID, ownerName string, addr string) {
		r.store.setRefs(append(r.mustRefs(), model.DNSReference{Scope: scope, Name: name, OwnerID: ownerID, OwnerName: ownerName})...)
		r.store.put(dnsOKRow(name, 1, addr))
	}
	use("prio:"+hostA, "prio.example.com", hostA, "app1.example.com", "192.0.2.30")
	use("uri:"+hostA, "uri.example.com", hostA, "app1.example.com", "192.0.2.31")
	use("rl:"+hostA, "rl.example.com", hostA, "app1.example.com", "192.0.2.32")
	use("prio:global", "global.example.com", "global", "", "192.0.2.33")
	use(model.DNSScopeKindTrusted, "office.example.com", "", "", "192.0.2.34")
	src := &dnsTestWarnSources{hostBans: map[string][]model.BannedIP{hostB: {{IPAddress: "192.0.2.0/24"}}}}
	r.svc.bans = src
	banned := func(when string, want ...string) {
		t.Helper()
		r.svc.refreshWarnings(ctx, r.mustRefs(), nil)
		for _, name := range []string{"prio.example.com", "uri.example.com", "rl.example.com", "global.example.com", "office.example.com"} {
			st, _ := r.store.row(name)
			got := slices.Contains(st.Warnings, model.DNSWarnBanned)
			if got != slices.Contains(want, name) {
				t.Errorf("%s: %s banned = %v (warnings %v), want %v", when, name, got, st.Warnings, !got)
			}
		}
	}

	banned("host B bans the range")
	src.hostBans[hostA] = []model.BannedIP{{IPAddress: "192.0.2.0/24"}}
	banned("host A bans the range", "prio.example.com", "uri.example.com", "rl.example.com")
	src.globalBans = []model.BannedIP{{IPAddress: "192.0.2.0/24"}}
	banned("a global ban", "prio.example.com", "uri.example.com", "rl.example.com", "global.example.com", "office.example.com")
}

// dnsCountingWarnSources records every read made for the warnings.
type dnsCountingWarnSources struct {
	dnsTestWarnSources
	mu    sync.Mutex
	reads []string
}

func (w *dnsCountingWarnSources) note(what string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reads = append(w.reads, what)
}

func (w *dnsCountingWarnSources) made() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.reads...)
}

func (w *dnsCountingWarnSources) ListEnabled(ctx context.Context) ([]model.DDNSRecord, error) {
	w.note("ddns records")
	return w.dnsTestWarnSources.ListEnabled(ctx)
}

func (w *dnsCountingWarnSources) Get(ctx context.Context) (*model.GlobalSettings, error) {
	w.note("global settings")
	return w.dnsTestWarnSources.Get(ctx)
}

func (w *dnsCountingWarnSources) GetActiveGlobalBans(ctx context.Context) ([]model.BannedIP, error) {
	w.note("global bans")
	return w.dnsTestWarnSources.GetActiveGlobalBans(ctx)
}

func (w *dnsCountingWarnSources) GetActiveBansForHost(ctx context.Context, proxyHostID string) ([]model.BannedIP, error) {
	w.note("host bans")
	return w.dnsTestWarnSources.GetActiveBansForHost(ctx, proxyHostID)
}

// dnsCountingSettings counts the reads of the system settings.
type dnsCountingSettings struct {
	*dnsTestSettings
	n atomic.Int64
}

func (s *dnsCountingSettings) Get(ctx context.Context) (*model.SystemSettings, error) {
	s.n.Add(1)
	return s.dnsTestSettings.Get(ctx)
}

// Without any domain entry a check reads nothing for the warnings: not the
// DDNS records, the global settings, the bans or the system settings.
// Without Valkey each of those reads logs a cache line, at every check.
func TestDNSRefreshWarningsReadsNothingWithoutDomainEntries(t *testing.T) {
	r := newDNSTestRig(t)
	r.svc.lastGC = r.clock.Now()
	src := &dnsCountingWarnSources{}
	r.svc.selfIPs, r.svc.global, r.svc.bans = src, src, src

	r.tick(t)
	if reads := src.made(); len(reads) != 0 {
		t.Errorf("a check without domain entries read %v for the warnings", reads)
	}

	settings := &dnsCountingSettings{dnsTestSettings: r.settings}
	r.svc.settings = settings
	r.svc.refreshWarnings(context.Background(), nil, nil)
	if n := settings.n.Load(); n != 0 || len(src.made()) != 0 {
		t.Errorf("warnings without domain entries read the system settings %d time(s) and %v", n, src.made())
	}
}

func TestDNSOverview(t *testing.T) {
	r, _ := dnsGateRig(t) // partner in lists A and B; app2 and app3 skip their login through list B
	ctx := context.Background()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"),
		dnsRef(dnsTestListA, "shop.example.com"))
	adding := dnsOKRow("shop.example.com", 2, "198.51.100.7")
	adding.AppliedGeneration = 1
	r.store.put(adding)
	since := dnsTestStart
	dropped := dnsOKRow("dropped.example.com", 5)
	dropped.AppliedGeneration, dropped.RevokePendingSince, dropped.UnusedSince = 4, &since, &since
	r.store.put(dropped)
	r.svc.envInterval = 30 * time.Second

	// nginx's message names the blocking file: both need proxy:read, and the
	// service is the one place that hides them.
	r.svc.applyView = dnsApplyView{failing: true, last: nginx.DNSApplyResult{Outcome: "blocked",
		Detail: `unknown directive "x" in /etc/nginx/conf.d/proxy_host_shop_example_com.conf:3`, BlockingFile: "proxy_host_shop_example_com.conf"}}
	ov, err := r.svc.Overview(ctx, func(scope string) bool { return scope == dnsACL(dnsTestListA) }, model.DNSStatusView{})
	if err != nil {
		t.Fatal(err)
	}
	if ov.TotalNames != 2 || ov.EnvIntervalSeconds == nil || *ov.EnvIntervalSeconds != 30 {
		t.Fatalf("total %d, env interval %v; want 2 used names and 30", ov.TotalNames, ov.EnvIntervalSeconds)
	}
	if ov.Apply.RevokePending != 1 || ov.Apply.PendingAdditions != 1 || ov.Apply.BlockedOutcome == nil ||
		ov.Apply.BlockingFile != nil || ov.Apply.BlockedDetail != nil {
		t.Fatalf("apply = %+v, want one revocation and one addition waiting, the failed outcome, and neither the file nor nginx's message without proxy:read", ov.Apply)
	}
	if withFile, _ := r.svc.Overview(ctx, nil, model.DNSStatusView{BlockingFile: true}); withFile.Apply.BlockingFile == nil || withFile.Apply.BlockedDetail == nil {
		t.Fatalf("apply = %+v, want the blocking file and nginx's message with proxy:read", withFile.Apply)
	}
	if len(ov.Entries) != 3 || ov.Entries[0].Hostname != "dropped.example.com" || ov.Entries[1].Hostname != "partner.example.com" {
		t.Fatalf("entries = %+v, want dropped, partner, shop (a dropped name nginx may still allow is listed)", ov.Entries)
	}
	partner := ov.Entries[1]
	if len(partner.Uses) != 1 || partner.Uses[0].Scope != dnsACL(dnsTestListA) || partner.Uses[0].Kind != "access_list" || partner.HiddenUses != 1 {
		t.Fatalf("partner uses = %+v hidden %d, want list A shown and list B counted", partner.Uses, partner.HiddenUses)
	}
	// The key maps an npg_dns file nginx names back to its name and use.
	if want := nginx.DNSIncludeKey(dnsACL(dnsTestListA), "partner.example.com"); partner.Uses[0].Key != want {
		t.Fatalf("partner use key = %q, want %q", partner.Uses[0].Key, want)
	}
	if partner.LoginBypassHosts != 2 {
		t.Fatalf("partner login bypass hosts = %d, want 2 (through list B)", partner.LoginBypassHosts)
	}
}

// The overview lists an exception list's use with the owner the reference
// carries: a host's list its host and first domain, a global list "global",
// the trusted list none.
func TestDNSOverviewShowsTheExceptionListUses(t *testing.T) {
	r := newDNSTestRig(t)
	const name = "office.example.com"
	refs := []model.DNSReference{
		{Scope: "prio:global", Name: name, OwnerID: "global"},
		{Scope: "rl:" + dnsGateH1, Name: name, OwnerID: dnsGateH1, OwnerName: "app1.example.com"},
		{Scope: model.DNSScopeKindTrusted, Name: name},
		{Scope: "uri:" + dnsGateH1, Name: name, OwnerID: dnsGateH1, OwnerName: "app1.example.com"},
	}
	r.store.setRefs(refs...)
	r.store.put(dnsOKRow(name, 1, "192.0.2.20"))
	ov, err := r.svc.Overview(context.Background(), func(string) bool { return true }, model.DNSStatusView{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Entries) != 1 || len(ov.Entries[0].Uses) != len(refs) {
		t.Fatalf("entries = %+v, want the name with its %d uses", ov.Entries, len(refs))
	}
	kinds := []string{"priority_allow", "rate_limit", "trusted", "uri_block"}
	for i, u := range ov.Entries[0].Uses {
		want := model.DNSEntryUse{Scope: refs[i].Scope, Kind: kinds[i], Key: nginx.DNSIncludeKey(refs[i].Scope, name),
			OwnerID: refs[i].OwnerID, OwnerName: refs[i].OwnerName}
		if u != want {
			t.Errorf("use %d = %+v, want %+v", i, u, want)
		}
	}
}

func TestDNSConfirm(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *dnsTestRig {
		r := newDNSTestRig(t)
		r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListA, "other.example.com"))
		review := dnsOKRow("partner.example.com", 3)
		review.Status, review.ReviewReason, review.CanonicalName = model.DNSStatusNeedsReview, model.DNSReviewCNAMEChanged, "a.ddns.example.com"
		review.LastApplied, review.Candidate = []string{"203.0.113.10"}, []string{"203.0.113.21"}
		r.store.put(review)
		r.store.put(dnsOKRow("other.example.com", 1, "198.51.100.7"))
		r.lookup.set("partner.example.com", "203.0.113.21")
		r.lookup.cname["partner.example.com"] = "b.cdn.example.com"
		if err := r.svc.ReconcileFiles(ctx, false); err != nil {
			t.Fatal(err)
		}
		return r
	}
	unchanged := func(t *testing.T, r *dnsTestRig) {
		t.Helper()
		st, _ := r.store.row("partner.example.com")
		if st.Status != model.DNSStatusNeedsReview || len(st.Published) != 0 || r.nginx.applyCount() != 0 {
			t.Fatalf("row %+v after a refused confirm, %d applies; want nothing published", st, r.nginx.applyCount())
		}
	}

	t.Run("not in review", func(t *testing.T) {
		r := setup(t)
		_, _, err := r.svc.Confirm(ctx, "other.example.com", []string{"198.51.100.7"}, "")
		if !errors.Is(err, dnsentry.ErrNotInReview) || r.lookup.lookups != 0 {
			t.Fatalf("err = %v after %d lookups, want ErrNotInReview before any lookup", err, r.lookup.lookups)
		}
	})
	t.Run("lookup unavailable", func(t *testing.T) {
		r := setup(t)
		r.lookup.fail("partner.example.com", &net.DNSError{Err: "i/o timeout", Name: "partner.example.com.", IsTimeout: true})
		_, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "b.cdn.example.com")
		if !errors.Is(err, dnsentry.ErrLookupUnavailable) {
			t.Fatalf("err = %v, want ErrLookupUnavailable", err)
		}
		unchanged(t, r)
	})
	t.Run("cname indeterminate", func(t *testing.T) {
		r := setup(t)
		r.lookup.cnameSeq["partner.example.com"] = []string{"b.cdn.example.com", "c.cdn.example.com"}
		_, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "")
		if !errors.Is(err, dnsentry.ErrLookupUnavailable) {
			t.Fatalf("err = %v, want ErrLookupUnavailable when the two CNAME answers differ", err)
		}
		unchanged(t, r)
	})
	t.Run("observation changed", func(t *testing.T) {
		r := setup(t)
		// The dialog showed 203.0.113.21 behind b.cdn.example.com; the name
		// answers 203.0.113.22 behind c.cdn.example.com now.
		r.lookup.set("partner.example.com", "203.0.113.22")
		r.lookup.cname["partner.example.com"] = "c.cdn.example.com"
		_, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "b.cdn.example.com")
		var changed *dnsentry.ObservationChangedError
		if !errors.As(err, &changed) || !dnsEqual(changed.Observed, []string{"203.0.113.22"}) || changed.Canonical != "c.cdn.example.com" {
			t.Fatalf("err = %v, want ObservationChangedError carrying 203.0.113.22 behind c.cdn.example.com", err)
		}
		// The 409 goes out, and the new answer stays on the row for the
		// dialog to show; nothing is published.
		st, _ := r.store.row("partner.example.com")
		if st.Status != model.DNSStatusNeedsReview || len(st.Published) != 0 || st.Generation != 3 || st.RevokePendingSince != nil ||
			!dnsEqual(st.Candidate, []string{"203.0.113.22"}) || st.CanonicalSeen != "c.cdn.example.com" ||
			!dnsEqual(st.V4.Observed, []string{"203.0.113.22"}) || st.CanonicalName != "a.ddns.example.com" {
			t.Fatalf("row = %+v, want the new answer kept, still in review, nothing published", st)
		}
		if got := r.partnerFile(t); len(got) != 0 || r.nginx.applyCount() != 0 {
			t.Fatalf("file = %v after %d applies, want it still empty and no apply", got, r.nginx.applyCount())
		}
		if ev := r.events.snapshot(); len(ev.closed) != 0 || len(ev.changes) != 0 {
			t.Fatalf("closes %v, changes %v; want none", ev.closed, ev.changes)
		}
		shown, err := r.svc.Statuses(ctx, []string{"partner.example.com"}, model.DNSStatusView{})
		if err != nil {
			t.Fatal(err)
		}
		if s := shown["partner.example.com"]; !dnsEqual(s.ObservedAddresses, []string{"203.0.113.22"}) ||
			s.ObservedCanonicalName == nil || *s.ObservedCanonicalName != "c.cdn.example.com" {
			t.Fatalf("status = %+v, want the dialog's next read to show the new answer", s)
		}
	})
	t.Run("target not shown", func(t *testing.T) {
		r := setup(t)
		// The dialog showed no target (the last check could not decide it):
		// a target the operator never saw is not pinned. The 409 carries it,
		// and the row keeps it for the dialog's next read.
		_, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "")
		var changed *dnsentry.ObservationChangedError
		if !errors.As(err, &changed) || changed.Canonical != "b.cdn.example.com" {
			t.Fatalf("err = %v, want ObservationChangedError carrying b.cdn.example.com", err)
		}
		unchanged(t, r)
		if st, _ := r.store.row("partner.example.com"); st.CanonicalSeen != "b.cdn.example.com" {
			t.Fatalf("canonical_seen = %q, want the target the dialog shows next", st.CanonicalSeen)
		}
	})
	t.Run("confirmed", func(t *testing.T) {
		r := setup(t)
		status, res, err := r.svc.Confirm(ctx, "Partner.Example.com", []string{"::ffff:203.0.113.21"}, "B.CDN.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		r.settle()
		if res.Outcome != "accepted" || r.nginx.applyCount() != 1 {
			t.Fatalf("apply = %+v (%d applies), want one apply at once", res, r.nginx.applyCount())
		}
		if status.Status != "ok" || !status.Applied || !dnsEqual(status.Addresses, []string{"203.0.113.21"}) ||
			!dnsEqual(status.ObservedAddresses, []string{"203.0.113.21"}) || status.ObservedCanonicalName == nil || *status.ObservedCanonicalName != "b.cdn.example.com" {
			t.Fatalf("status = %+v, want the confirmed addresses published and shown as observed", status)
		}
		st, _ := r.store.row("partner.example.com")
		if st.CanonicalName != "b.cdn.example.com" || st.ReviewReason != "" || len(st.ChangeTimes) != 0 {
			t.Fatalf("row = %+v, want the new target pinned and the counters reset", st)
		}
		if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.21"}) {
			t.Fatalf("file = %v, want the server's own observation", got)
		}
		if ev := r.events.snapshot(); len(ev.closed) != 1 || ev.closed[0] != "partner.example.com confirmed" {
			t.Fatalf("closes = %v, want the review alert recovered", ev.closed)
		}
	})
	t.Run("feature off", func(t *testing.T) {
		r := setup(t)
		r.settings.set(`{"enabled":false}`, nil)
		status, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "b.cdn.example.com")
		if err != nil {
			t.Fatal(err)
		}
		// The audit records what was confirmed; addresses is empty while off.
		if len(status.Addresses) != 0 || !dnsEqual(status.ObservedAddresses, []string{"203.0.113.21"}) {
			t.Fatalf("status = %+v, want no addresses and the confirmed ones as observed", status)
		}
		st, _ := r.store.row("partner.example.com")
		if st.Status != model.DNSStatusOK || !st.Disabled || len(st.Published) != 0 || !dnsEqual(st.LastApplied, []string{"203.0.113.21"}) {
			t.Fatalf("row = %+v, want the review closed but nothing published while the feature is off", st)
		}
	})
	t.Run("switched off during the lookup", func(t *testing.T) {
		r := setup(t)
		// A settings save stores "off" while the confirm looks the name up;
		// it switches every name off only after the confirm took dnsMu.
		r.svc.lookuper = &dnsSwitchingLookuper{dnsTestLookuper: r.lookup, flip: func() {
			r.settings.set(`{"enabled":false}`, nil)
		}}
		status, _, err := r.svc.Confirm(ctx, "partner.example.com", []string{"203.0.113.21"}, "b.cdn.example.com")
		if err != nil {
			t.Fatal(err)
		}
		r.settle()
		st, _ := r.store.row("partner.example.com")
		if !st.Disabled || len(st.Published) != 0 || len(status.Addresses) != 0 {
			t.Fatalf("row = %+v, status = %+v; want the review closed and nothing published once off is stored", st, status)
		}
		if got := r.partnerFile(t); len(got) != 0 {
			t.Fatalf("file = %v, want it still empty", got)
		}
	})
}

func TestDNSApplyNowRepairsTheFilesAndAppliesAtOnce(t *testing.T) {
	r := dnsPartnerRig(t, "203.0.113.10")
	r.nginx.putFile(dnsACL(dnsTestListA), "partner.example.com", 1, "203.0.113.10", "203.0.113.66") // edited by hand
	r.svc.applyView.retryAt = r.clock.Now().Add(8 * time.Minute)
	r.svc.retry.retryAt = r.svc.applyView.retryAt

	res := r.svc.ApplyNow(context.Background())
	r.settle()

	if res.Outcome != "accepted" || r.nginx.applyCount() != 1 {
		t.Fatalf("result %+v after %d applies, want one apply despite the retry schedule", res, r.nginx.applyCount())
	}
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("file = %v, want it back to what the database wants", got)
	}
	if !r.svc.applyView.retryAt.IsZero() {
		t.Fatal("a successful apply ends the retry schedule")
	}
}

// A restore can write a row back below the generation a file of its name
// still carries, until something raises it. Apply now reads the rows the
// way a check does, so its files are written above that generation, and a
// write that fails keeps the name unapplied: the revocation stays pending
// while the file still allows the old address.
func TestDNSApplyNowRepairsAboveTheGenerationsFilesCarry(t *testing.T) {
	ctx := context.Background()
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 9, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	restored := dnsOKRow("partner.example.com", 2)
	since := r.clock.Now()
	restored.AppliedGeneration, restored.RevokePendingSince, restored.EmptyCause = 1, &since, model.DNSEmptyRestored
	r.store.put(restored)
	r.nginx.mu.Lock()
	r.nginx.writeErr = errors.New("no space left on device")
	r.nginx.mu.Unlock()

	r.svc.ApplyNow(ctx)
	r.settle()

	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("file = %v, want the old address still in it (the write failed)", got)
	}
	if st, _ := r.store.row("partner.example.com"); st.RevokePendingSince == nil || st.AppliedGeneration >= st.Generation || st.Generation <= 9 {
		t.Fatalf("row = %+v; while the file still allows 203.0.113.10 the revocation must stay pending, above the file's generation 9", st)
	}
}
