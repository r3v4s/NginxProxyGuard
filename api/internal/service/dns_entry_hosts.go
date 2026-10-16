package service

import (
	"context"
	"log"
	"net/netip"
	"sort"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// dnsHostIndexMaxAge is how old the host index may get before a check
// rebuilds it unasked: building it costs about a dozen queries per
// host, too much for every check.
const dnsHostIndexMaxAge = 5 * time.Minute

// dnsHostIndexBuildTimeout bounds one background rebuild of the host index.
const dnsHostIndexBuildTimeout = 30 * time.Second

// dnsHostIndex answers, from memory, the two questions about hosts that use
// an access list with domain entries: which hosts skip their login
// for such a list (LoginBypassHosts), and whether a host's 403 came from its
// list (ExemptAccessDenial). A mark (markHostIndexDirty) rebuilds it at once
// in the background, and the fail2ban gate trusts it only once a build that
// began after the latest mark is in place. A check builds it when there is
// none or it is dnsHostIndexMaxAge old; SyncScope rebuilds one list's hosts
// at once. Readers load it lock-free.
type dnsHostIndex struct {
	byHost  map[string]*dnsHostEntry
	byList  map[string][]*dnsHostEntry
	builtAt time.Time
	marks   int64 // hostIdxMarks when the build began; lower when entries were kept from an older index
}

// dnsHostEntry is one enabled HTTP host using a list with domain entries,
// as its config renders.
type dnsHostEntry struct {
	hostID, domain, listID string
	scope                  string // acl:<listID>
	skipsLogin             bool   // satisfy any + a login: listed addresses skip the login
	covered                bool   // a client outside the list gets the list's 403
	usable                 bool   // every rule parsed; when false nothing is exempt
	trusted                []netip.Prefix
	rules                  []dnsAccessRule
}

// dnsAccessRule is one rendered allow/deny line.
type dnsAccessRule struct {
	deny   bool
	all    bool
	prefix netip.Prefix
}

// markHostIndexDirty marks the host index stale and rebuilds it in the
// background: a list was saved, the settings changed, or nginx took a reload
// (a host save reloads), so what a host renders may have changed. Until an
// index whose build began after the mark is in place, ExemptAccessDenial
// leaves nothing out; that takes the seconds a rebuild takes. It never
// blocks and takes no lock: the reload hooks call it under diskMu.
func (s *DNSEntryService) markHostIndexDirty() {
	s.hostIdxMarks.Add(1)
	if !s.hostIdxBuilding.CompareAndSwap(false, true) {
		return // the rebuild that runs builds again for this mark
	}
	s.bg.Add(1)
	go s.rebuildHostIndexInBackground()
}

// rebuildHostIndexInBackground rebuilds the whole host index, and again for
// as long as marks came in while it was building: one rebuild at a time,
// however many marks. It takes no DNS lock; it only reads the database.
func (s *DNSEntryService) rebuildHostIndexInBackground() {
	defer s.bg.Done()
	defer func() {
		if r := recover(); r != nil {
			// A bug in a host's render data must not end the process. The
			// index stays stale, so every 403 counts, until a later mark (the
			// flag cleared lets it start a rebuild) or the next check builds it.
			log.Printf("[DNSEntries] ERROR: the host index rebuild stopped unexpectedly; fail2ban counts every 403 until a rebuild works: %v", r)
			s.hostIdxBuilding.Store(false)
		}
	}()
	for {
		marks := s.hostIdxMarks.Load()
		ctx, cancel := context.WithTimeout(context.Background(), dnsHostIndexBuildTimeout)
		s.rebuildHostIndexFromStore(ctx)
		cancel()
		s.hostIdxBuilding.Store(false)
		// A mark made since this build began needs another one. A mark made
		// after the flag was cleared started it already.
		if s.hostIdxMarks.Load() == marks || !s.hostIdxBuilding.CompareAndSwap(false, true) {
			return
		}
	}
}

// rebuildHostIndexFromStore rebuilds the whole host index from the
// references the database holds now. When they cannot be read, the index
// stays as it is: marked stale, it leaves nothing out until a build works
// (the next check tries again).
func (s *DNSEntryService) rebuildHostIndexFromStore(ctx context.Context) {
	if s.hosts == nil || s.builder == nil {
		return
	}
	refs, err := s.states.ListReferences(ctx)
	if err != nil {
		s.logs.fail("hostrefs", "[DNSEntries] WARN: could not read the domain references to rebuild the host index; fail2ban counts every 403 until it is rebuilt: %v", err)
		return
	}
	s.logs.ok("hostrefs")
	s.rebuildHostIndex(ctx, refs, "")
}

// refreshHostIndex is a check's part: it builds the host index when there is
// none yet, when it is stale (a mark came after its build began, and the
// rebuild the mark started failed or has not finished), and when it is
// dnsHostIndexMaxAge old, for a change no mark announced.
func (s *DNSEntryService) refreshHostIndex(ctx context.Context, refs []model.DNSReference) {
	idx := s.hostIdx.Load()
	if idx != nil && idx.marks == s.hostIdxMarks.Load() && s.now().Sub(idx.builtAt) < dnsHostIndexMaxAge {
		return
	}
	s.rebuildHostIndex(ctx, refs, "")
}

// rebuildHostIndex builds the index for every list with domain entries, or
// only for onlyList (keeping the other lists' entries). A host whose config
// data cannot be built is left out: its 403s are counted, as today. Entries
// kept from the index in place make the new one as stale as that one.
func (s *DNSEntryService) rebuildHostIndex(ctx context.Context, refs []model.DNSReference, onlyList string) {
	if s.hosts == nil || s.builder == nil {
		return
	}
	// Read before anything the index is built from: a mark made after this
	// read leaves the new index stale.
	marks := s.hostIdxMarks.Load()
	lists := make(map[string]bool)
	for _, r := range refs {
		if kind, owner, ok := model.ParseDNSScope(r.Scope); ok && kind == model.DNSScopeKindAccessList {
			lists[owner] = true
		}
	}
	old := s.hostIdx.Load()
	idx := &dnsHostIndex{byHost: make(map[string]*dnsHostEntry), byList: make(map[string][]*dnsHostEntry), builtAt: s.now(), marks: marks}
	if onlyList != "" && old != nil {
		idx.marks = min(idx.marks, old.marks)
		for listID, entries := range old.byList {
			if listID == onlyList || !lists[listID] {
				continue
			}
			for _, e := range entries {
				idx.add(e)
			}
		}
	}
	for _, listID := range dnsSortedKeys(lists) {
		if onlyList != "" && listID != onlyList {
			continue
		}
		hosts, err := s.hosts.GetByAccessListID(ctx, listID)
		if err != nil {
			s.logs.fail("hosts", "[DNSEntries] WARN: could not read the hosts of an access list with domain entries; keeping the last answer: %v", err)
			if old != nil {
				idx.marks = min(idx.marks, old.marks)
				for _, e := range old.byList[listID] {
					idx.add(e)
				}
			}
			continue
		}
		s.logs.ok("hosts")
		for i := range hosts {
			h := &hosts[i]
			if !h.Enabled || h.IsStream() {
				continue
			}
			data, err := s.builder.BuildConfigData(ctx, h)
			if err != nil {
				continue
			}
			idx.add(dnsHostEntryFrom(h, listID, data))
		}
	}
	s.storeHostIndex(idx)
}

// storeHostIndex puts idx in place unless the index there began after a
// later mark: builds overlap (a check, a list save, the background rebuild),
// and a slower one must not put older answers back.
func (s *DNSEntryService) storeHostIndex(idx *dnsHostIndex) {
	for {
		cur := s.hostIdx.Load()
		if cur != nil && cur.marks > idx.marks {
			return
		}
		if s.hostIdx.CompareAndSwap(cur, idx) {
			return
		}
	}
}

func (idx *dnsHostIndex) add(e *dnsHostEntry) {
	idx.byHost[e.hostID] = e
	idx.byList[e.listID] = append(idx.byList[e.listID], e)
}

// dnsHostEntryFrom reads one host's rendered access phase: the global trusted
// IPs, the list's rules exactly as the template writes them (hostname rows are
// include lines, not rules), and whether the list decides the host's 403s:
// not when satisfy any lets a login pass instead, and not when its Advanced
// Config has access rules of its own.
func dnsHostEntryFrom(h *model.ProxyHost, listID string, data nginx.ProxyHostConfigData) *dnsHostEntry {
	e := &dnsHostEntry{hostID: h.ID, listID: listID, scope: model.AccessListDNSScope(listID), usable: true}
	if len(h.DomainNames) > 0 {
		e.domain = h.DomainNames[0]
	}
	list := data.AccessList
	if list == nil || list.ID != listID {
		return e
	}
	e.skipsLogin = data.ListSkipsLogin()
	advanced := h.AdvancedConfig
	if data.Host != nil {
		advanced = data.Host.AdvancedConfig
	}
	e.covered = len(list.Items) > 0 && dnsListHasHostname(list) && !e.skipsLogin && !nginx.AdvancedConfigHasAccessRules(advanced)
	for _, v := range data.GlobalTrustedIPs {
		p, ok := dnsParseRuleAddress(v)
		if !ok {
			e.usable = false
			continue
		}
		e.trusted = append(e.trusted, p)
	}
	for _, it := range nginx.AccessListRules(list) {
		if it.Directive != "allow" && it.Directive != "deny" {
			e.usable = false
			continue
		}
		r := dnsAccessRule{deny: it.Directive == "deny"}
		if it.Address == "all" {
			r.all = true
		} else if p, ok := dnsParseRuleAddress(it.Address); ok {
			r.prefix = p
		} else {
			e.usable = false
			continue
		}
		e.rules = append(e.rules, r)
	}
	return e
}

// dnsListHasHostname: the list has a domain entry.
func dnsListHasHostname(list *model.AccessList) bool {
	for _, it := range list.Items {
		if it.Hostname != "" {
			return true
		}
	}
	return false
}

// dnsParseRuleAddress reads an allow/deny address the way nginx does: a CIDR
// range or one address. It is never Unmap()ed: nginx compares a
// "::ffff:a.b.c.d" rule as IPv6, and it does not match an IPv4 client.
func dnsParseRuleAddress(v string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// ExemptAccessDenial is the fail2ban gate: a
// host-attributed 403 that nginx answered in the access phase is left out of
// the host's fail2ban count when the host's list decides its 403s and the
// list denies the client. The client is walked through the rules in render
// order — global trusted IPs, the list's rules (first match), the list's
// domain files — and is exempt only when the walk ends in deny. A domain
// file allows what it holds and what was removed from it but may still be in
// nginx; anything the evaluator cannot read is counted, as today. So is
// every 403 while the host index is stale: a list save, a settings change or
// a reload came after its build began, and what the host renders may have
// changed (the rebuild the mark started takes seconds). It runs on the log
// tail goroutine: memory only.
func (s *DNSEntryService) ExemptAccessDenial(ctx context.Context, hostID, clientIP string) bool {
	idx := s.hostIdx.Load()
	if idx == nil || idx.marks != s.hostIdxMarks.Load() {
		return false
	}
	e := idx.byHost[hostID]
	if e == nil || !e.covered || !e.usable {
		return false
	}
	client, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	client = client.Unmap()
	for _, p := range e.trusted {
		if p.Contains(client) {
			return false
		}
	}
	for _, r := range e.rules {
		if r.all || r.prefix.Contains(client) {
			return r.deny
		}
	}
	return !s.dnsAllows(e.scope, client.String())
}

// LoginBypassHosts lists the enabled hosts where list, a satisfy-any list
// with domain entries, lets its addresses skip the host's login.
// From the index; no database read.
func (s *DNSEntryService) LoginBypassHosts(listID string) []model.DNSHostRef {
	idx := s.hostIdx.Load()
	if idx == nil {
		return nil
	}
	var out []model.DNSHostRef
	for _, e := range idx.byList[listID] {
		if e.skipsLogin {
			out = append(out, model.DNSHostRef{ID: e.hostID, Domain: e.domain})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].ID < out[j].ID
	})
	return out
}
