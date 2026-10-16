package service

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// Statuses returns the API status of each name. A name with
// no row yet is pending. view says which caller-dependent parts the caller
// may see: the banned warning (waf:read), the self_ip warning
// (ddns:read, it reveals NPG's own public address) and blocking_file
// (proxy:read). A hidden part is left out, never replaced.
func (s *DNSEntryService) Statuses(ctx context.Context, names []string, view model.DNSStatusView) (map[string]model.DNSEntryStatus, error) {
	names = dnsCleanNames(names)
	out := make(map[string]model.DNSEntryStatus, len(names))
	if len(names) == 0 {
		return out, nil
	}
	rows, err := s.states.GetStates(ctx, names)
	if err != nil {
		return nil, err
	}
	st := s.Settings(ctx)
	apply, lastReload := s.applySnapshot()
	now := s.now()
	for _, n := range names {
		row, ok := rows[n]
		if !ok {
			row = model.DNSEntryState{Hostname: n, Status: model.DNSStatusPending}
		}
		out[n] = dnsStatusOf(row, st, apply, lastReload, now, view)
	}
	return out, nil
}

// applySnapshot reads the retry state and the last reload for readers.
func (s *DNSEntryService) applySnapshot() (dnsApplyView, time.Time) {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	return s.applyView, s.lastReload
}

// dnsStatusOf builds one name's API status from its row and the apply state,
// leaving out what view hides.
func dnsStatusOf(row model.DNSEntryState, st model.DNSEntrySettings, apply dnsApplyView, lastReload, now time.Time, view model.DNSStatusView) model.DNSEntryStatus {
	out := model.DNSEntryStatus{
		Hostname:      row.Hostname,
		Status:        row.Status,
		ReviewReason:  dnsStringPtr(row.ReviewReason),
		Disabled:      row.Disabled,
		Addresses:     dnsSortedUnique(row.Published),
		Applied:       row.AppliedGeneration >= row.Generation,
		RevokePending: row.RevokePendingSince != nil,
		CanonicalName: dnsStringPtr(row.CanonicalName),
		Families: map[string]model.DNSFamilyStatus{
			"ipv4": dnsFamilyStatus(row.V4),
			"ipv6": dnsFamilyStatus(row.V6),
		},
		ErrorCode:     dnsErrorCode(row),
		StaleUntil:    dnsStaleUntil(row, st),
		LastCheckedAt: row.LastCheckedAt,
		LastChangedAt: row.LastChangedAt,
	}
	if out.Status == "" {
		out.Status = model.DNSStatusPending
	}
	if row.Status == model.DNSStatusNeedsReview {
		out.ObservedAddresses = dnsSortedUnique(row.Candidate)
		out.ObservedCanonicalName = dnsStringPtr(row.CanonicalSeen)
	} else if !row.Disabled && row.UnusedSince == nil {
		if pending := dnsMinus(row.Candidate, row.Published); len(pending) > 0 {
			out.PendingAddresses = pending
			out.NextApplyAt = dnsNextApplyAt(row, st, lastReload, now)
		}
	}
	for _, w := range row.Warnings {
		if (w == model.DNSWarnBanned && !view.Banned) || (w == model.DNSWarnSelfIP && !view.SelfIP) {
			continue
		}
		out.Warnings = append(out.Warnings, w)
	}
	if apply.failing && (out.RevokePending || !out.Applied) {
		out.BlockedReason = dnsStringPtr(apply.last.Outcome)
		if view.BlockingFile {
			out.BlockingFile = dnsStringPtr(apply.last.BlockingFile)
		}
	}
	return out
}

func dnsStringPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// dnsFamilyStatus maps a family's stored state to the API's:
// unknown | ok | not_found | transient | rejected.
func dnsFamilyStatus(f model.DNSFamilyState) model.DNSFamilyStatus {
	state := "unknown"
	switch f.State {
	case "ok", "transient", "rejected":
		state = f.State
	case "notfound":
		state = "not_found"
	}
	return model.DNSFamilyStatus{State: state, Code: dnsStringPtr(f.Code)}
}

// dnsCodeCNAMEIndeterminate: the addresses answered, but the two CNAME
// lookups of the last check disagreed or one failed.
const dnsCodeCNAMEIndeterminate = "cname_indeterminate"

// dnsErrorCode is the code behind a status that is not ok: the family that
// made it, IPv4 first. A pending name that no family answered with a usable
// address gets its first failing family's code, so a name that does not
// exist (a typo) says so instead of only "pending". Otherwise, when both
// families answered (ok, or ok and not found) but the last check could not
// decide the CNAME target, cname_indeterminate: additions wait until a
// check decides it.
func dnsErrorCode(row model.DNSEntryState) *string {
	want := ""
	switch row.Status {
	case model.DNSStatusStale, model.DNSStatusExpired:
		want = "transient"
	case model.DNSStatusRejected:
		want = "rejected"
	case model.DNSStatusNotFound:
		want = "notfound"
	}
	if want != "" {
		for _, f := range []model.DNSFamilyState{row.V4, row.V6} {
			if f.State == want && f.Code != "" {
				return dnsStringPtr(f.Code)
			}
		}
		return nil
	}
	if row.Status == model.DNSStatusPending && row.V4.State != "ok" && row.V6.State != "ok" {
		for _, f := range []model.DNSFamilyState{row.V4, row.V6} {
			if f.Code != "" {
				return dnsStringPtr(f.Code)
			}
		}
		return nil
	}
	answered := func(f model.DNSFamilyState) bool { return f.State == "ok" || f.State == "notfound" }
	if answered(row.V4) && answered(row.V6) && (row.V4.State == "ok" || row.V6.State == "ok") && row.CanonicalSeen == "" {
		return dnsStringPtr(dnsCodeCNAMEIndeterminate)
	}
	return nil
}

// dnsStaleUntil is when a stale name's held addresses expire: the earliest
// last definitive answer of a failing family plus the grace.
func dnsStaleUntil(row model.DNSEntryState, st model.DNSEntrySettings) *time.Time {
	if row.Status != model.DNSStatusStale {
		return nil
	}
	var until *time.Time
	for _, f := range []model.DNSFamilyState{row.V4, row.V6} {
		if f.State != "transient" || f.AnswerAt == nil {
			continue
		}
		t := f.AnswerAt.Add(st.StaleGrace())
		if until == nil || t.Before(*until) {
			until = &t
		}
	}
	return until
}

// dnsNextApplyAt estimates when a waiting addition can be published: at the
// check that sees it again, not before the gap after the last DNS reload.
func dnsNextApplyAt(row model.DNSEntryState, st model.DNSEntrySettings, lastReload, now time.Time) *time.Time {
	at := now
	if row.LastCheckedAt != nil {
		at = row.LastCheckedAt.Add(st.CheckInterval())
	}
	if !lastReload.IsZero() {
		if gap := lastReload.Add(st.MinReloadGap()); gap.After(at) {
			at = gap
		}
	}
	return &at
}

// Overview is GET /dns-entries: every used name — and
// every name nginx may still allow after it was dropped — with its status
// and uses, the apply state and the effective settings. canRead decides
// which uses the caller may see by name; the others are only counted. view
// hides what Statuses hides, and the apply state's blocking file and
// nginx's message, which names that file: the handler does not
// filter them again.
func (s *DNSEntryService) Overview(ctx context.Context, canRead func(scope string) bool, view model.DNSStatusView) (model.DNSEntryOverview, error) {
	refs, err := s.states.ListReferences(ctx)
	if err != nil {
		return model.DNSEntryOverview{}, err
	}
	rows, err := s.states.GetStates(ctx, nil)
	if err != nil {
		return model.DNSEntryOverview{}, err
	}
	st := s.Settings(ctx)
	apply, lastReload := s.applySnapshot()
	now := s.now()
	used := dnsUseCounts(refs)
	ov := model.DNSEntryOverview{
		Settings:    st,
		EnvDisabled: s.envDisabled,
		TotalNames:  len(used),
		Apply:       dnsApplyStateOf(rows, apply, lastReload, view),
		Entries:     []model.DNSEntryOverviewEntry{},
	}
	if s.envInterval > 0 {
		secs := int(s.envInterval / time.Second)
		ov.EnvIntervalSeconds = &secs
	}
	names := make(map[string]bool, len(used))
	for n := range used {
		names[n] = true
	}
	for n, row := range rows {
		if row.RevokePendingSince != nil {
			names[n] = true
		}
	}
	idx := s.hostIdx.Load()
	for _, name := range dnsSortedKeys(names) {
		row, ok := rows[name]
		if !ok {
			row = model.DNSEntryState{Hostname: name, Status: model.DNSStatusPending}
		}
		e := model.DNSEntryOverviewEntry{DNSEntryStatus: dnsStatusOf(row, st, apply, lastReload, now, view), Uses: []model.DNSEntryUse{}}
		bypass := make(map[string]bool)
		seen := make(map[string]bool)
		for _, r := range refs {
			if r.Name != name || seen[r.Scope] {
				continue
			}
			seen[r.Scope] = true
			if canRead != nil && canRead(r.Scope) {
				e.Uses = append(e.Uses, model.DNSEntryUse{Scope: r.Scope, Kind: dnsUseKind(r.Scope), Key: nginx.DNSIncludeKey(r.Scope, name),
					OwnerID: r.OwnerID, OwnerName: r.OwnerName})
			} else {
				e.HiddenUses++
			}
			if kind, owner, ok := model.ParseDNSScope(r.Scope); ok && kind == model.DNSScopeKindAccessList && idx != nil {
				for _, h := range idx.byList[owner] {
					if h.skipsLogin {
						bypass[h.hostID] = true
					}
				}
			}
		}
		e.LoginBypassHosts = len(bypass)
		ov.Entries = append(ov.Entries, e)
	}
	return ov, nil
}

// dnsUseKind names a scope's kind for the overview.
func dnsUseKind(scope string) string {
	kind, _, _ := model.ParseDNSScope(scope)
	switch kind {
	case model.DNSScopeKindAccessList:
		return "access_list"
	case model.DNSScopeKindURIBlock:
		return "uri_block"
	case model.DNSScopeKindPriority:
		return "priority_allow"
	case model.DNSScopeKindRateLimit:
		return "rate_limit"
	case model.DNSScopeKindTrusted:
		return "trusted"
	}
	return ""
}

// dnsApplyStateOf is the overview's apply line. nginx's
// message names the blocking file, so both need view.BlockingFile
// (proxy:read); this is the only place that hides them.
func dnsApplyStateOf(rows map[string]model.DNSEntryState, apply dnsApplyView, lastReload time.Time, view model.DNSStatusView) model.DNSApplyState {
	var a model.DNSApplyState
	if !lastReload.IsZero() {
		t := lastReload
		a.LastDNSReloadAt = &t
	}
	for _, row := range rows {
		switch {
		case row.RevokePendingSince != nil:
			a.RevokePending++
		case row.Generation > row.AppliedGeneration:
			a.PendingAdditions++
		}
	}
	if apply.failing {
		a.BlockedOutcome = dnsStringPtr(apply.last.Outcome)
		if view.BlockingFile {
			a.BlockedDetail = dnsStringPtr(apply.last.Detail)
			a.BlockingFile = dnsStringPtr(apply.last.BlockingFile)
		}
		if !apply.retryAt.IsZero() {
			t := apply.retryAt
			a.NextRetryAt = &t
		}
	}
	return a
}

// dnsWarnInputs are what the warnings are computed from.
type dnsWarnInputs struct {
	selfIPs    map[netip.Addr]bool       // NPG's own public IPs: DDNS records last updated with status ok
	globalBans []netip.Prefix            // active global bans
	hostBans   map[string][]netip.Prefix // active bans per host
	ipv6Listen bool                      // global enable_ipv6
}

func (in dnsWarnInputs) banned(a netip.Addr, hosts []string) bool {
	for _, p := range in.globalBans {
		if p.Contains(a) {
			return true
		}
	}
	for _, h := range hosts {
		for _, p := range in.hostBans[h] {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// loadWarnInputs reads the warning inputs. They are information only: one
// that cannot be read gives no warning. Bans are read as the render reads
// them: a ban equal to or inside a static global trusted entry is not
// enforced, so it is left out.
func (s *DNSEntryService) loadWarnInputs(ctx context.Context, hostIDs []string) dnsWarnInputs {
	in := dnsWarnInputs{selfIPs: make(map[netip.Addr]bool), hostBans: make(map[string][]netip.Prefix)}
	if s.selfIPs != nil {
		if recs, err := s.selfIPs.ListEnabled(ctx); err == nil {
			for _, r := range recs {
				if r.LastStatus != model.DDNSStatusOK {
					continue
				}
				if a, err := netip.ParseAddr(strings.TrimSpace(r.LastIP)); err == nil {
					in.selfIPs[a.Unmap()] = true
				}
			}
		}
	}
	var trusted []string
	if s.settings != nil {
		if cur, err := s.settings.Get(ctx); err == nil && cur != nil {
			trusted = ParseGlobalTrustedIPs(cur.GlobalTrustedIPs)
		}
	}
	if s.global != nil {
		if gs, err := s.global.Get(ctx); err == nil && gs != nil {
			in.ipv6Listen = gs.EnableIPv6
		}
	}
	if s.bans != nil {
		if bans, err := s.bans.GetActiveGlobalBans(ctx); err == nil {
			in.globalBans = dnsBanPrefixes(filterBannedByTrustedIPs(bans, trusted))
		}
		for _, h := range hostIDs {
			if bans, err := s.bans.GetActiveBansForHost(ctx, h); err == nil {
				in.hostBans[h] = dnsBanPrefixes(filterBannedByTrustedIPs(bans, trusted))
			}
		}
	}
	return in
}

// dnsBanPrefixes reads bans as nginx's ban geo does (an address or a CIDR
// range, never unmapped; anything else is not rendered).
func dnsBanPrefixes(bans []model.BannedIP) []netip.Prefix {
	var out []netip.Prefix
	for _, b := range bans {
		if p, ok := dnsParseRuleAddress(strings.TrimSpace(b.IPAddress)); ok {
			out = append(out, p)
		}
	}
	return out
}

// dnsWarnings computes one name's warnings: self_ip, banned and cgnat for
// its published or waiting addresses; partial_rejected from this check's
// answer (kept from the last one when this check had none); ipv6_listen when
// it publishes IPv4 only while NPG listens on IPv6; duplicate when another
// name in one of its scopes publishes the same address. A name not
// in use or switched off has none.
func dnsWarnings(st model.DNSEntryState, used bool, hosts []string, in dnsWarnInputs, notes *dnsentry.ObserveNotes, duplicate bool) []string {
	if !used || st.Disabled || st.UnusedSince != nil {
		return nil
	}
	var out []string
	var self, banned, cgnat bool
	for _, v := range dnsUnion(st.Published, st.Candidate) {
		a, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		self = self || in.selfIPs[a]
		banned = banned || in.banned(a, hosts)
		cgnat = cgnat || model.IsCGNAT(a)
	}
	if self {
		out = append(out, model.DNSWarnSelfIP)
	}
	if banned {
		out = append(out, model.DNSWarnBanned)
	}
	if cgnat {
		out = append(out, model.DNSWarnCGNAT)
	}
	partial := notes != nil && notes.PartialRejected
	if notes == nil {
		for _, w := range st.Warnings {
			partial = partial || w == model.DNSWarnPartialRejected
		}
	}
	if partial {
		out = append(out, model.DNSWarnPartialRejected)
	}
	if in.ipv6Listen {
		var v4, v6 bool
		for _, v := range st.Published {
			if a, err := netip.ParseAddr(v); err == nil {
				v4, v6 = v4 || a.Is4(), v6 || a.Is6()
			}
		}
		if v4 && !v6 {
			out = append(out, model.DNSWarnIPv6Listen)
		}
	}
	if duplicate {
		out = append(out, model.DNSWarnDuplicate)
	}
	return dnsSortedUnique(out)
}

// dnsDuplicates marks the names that publish an address another name in the
// same scope publishes too.
func dnsDuplicates(refs []model.DNSReference, rows map[string]model.DNSEntryState) map[string]bool {
	byScope := make(map[string]map[string][]string)
	for _, r := range refs {
		st, ok := rows[r.Name]
		if !ok {
			continue
		}
		for _, a := range dnsDesired(st, true) {
			if byScope[r.Scope] == nil {
				byScope[r.Scope] = make(map[string][]string)
			}
			byScope[r.Scope][a] = append(byScope[r.Scope][a], r.Name)
		}
	}
	out := make(map[string]bool)
	for _, addrs := range byScope {
		for _, names := range addrs {
			if names = dnsSortedUnique(names); len(names) > 1 {
				for _, n := range names {
					out[n] = true
				}
			}
		}
	}
	return out
}

// refreshWarnings recomputes every name's warnings at the end of a
// check and stores the ones that changed. Without a row there is nothing to
// warn about, and nothing is read for it.
func (s *DNSEntryService) refreshWarnings(ctx context.Context, refs []model.DNSReference, notes map[string]dnsentry.ObserveNotes) {
	rows, err := s.states.GetStates(ctx, nil)
	if err != nil || len(rows) == 0 {
		return
	}
	used := dnsUseCounts(refs)
	idx := s.hostIdx.Load()
	hostsOf := make(map[string][]string)
	hostSet := make(map[string]bool)
	for _, r := range refs {
		kind, owner, ok := model.ParseDNSScope(r.Scope)
		if !ok || kind != model.DNSScopeKindAccessList || idx == nil {
			continue
		}
		for _, h := range idx.byList[owner] {
			hostsOf[r.Name] = append(hostsOf[r.Name], h.hostID)
			hostSet[h.hostID] = true
		}
	}
	in := s.loadWarnInputs(ctx, dnsSortedKeys(hostSet))
	dup := dnsDuplicates(refs, rows)
	want := make(map[string][]string)
	for name, st := range rows {
		var n *dnsentry.ObserveNotes
		if v, ok := notes[name]; ok {
			n = &v
		}
		w := dnsWarnings(st, used[name] > 0, hostsOf[name], in, n, dup[name])
		if !dnsSameSet(w, st.Warnings) {
			want[name] = w
		}
	}
	if len(want) == 0 {
		return
	}
	names := dnsSortedKeys(want)
	err = func() error {
		s.dnsMu.Lock()
		defer s.dnsMu.Unlock()
		return s.states.WithTx(ctx, func(tx repository.DNSEntryTx) error {
			cur, err := tx.GetStates(ctx, names)
			if err != nil {
				return err
			}
			for _, name := range names {
				st, ok := cur[name]
				if !ok {
					continue
				}
				st.Warnings = want[name]
				if err := tx.UpsertState(ctx, st); err != nil {
					return err
				}
			}
			return nil
		})
	}()
	if err != nil {
		s.logs.fail("warnings", "[DNSEntries] WARN: could not store the domain entry warnings: %v", err)
		return
	}
	s.logs.ok("warnings")
}
