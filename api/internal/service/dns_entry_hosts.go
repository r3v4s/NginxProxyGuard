package service

import (
	"context"
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

// dnsHostIndex answers, from memory, the two questions about hosts that use
// an access list with domain entries: which hosts skip their login
// for such a list (LoginBypassHosts), and whether a host's 403 came from its
// list (ExemptAccessDenial). A check rebuilds it when it is dnsHostIndexMaxAge
// old or marked (markHostIndexDirty); SyncScope rebuilds one list's hosts at
// once. Readers load it lock-free.
type dnsHostIndex struct {
	byHost  map[string]*dnsHostEntry
	byList  map[string][]*dnsHostEntry
	builtAt time.Time
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

// markHostIndexDirty asks the next check to rebuild the host index: a list
// was saved, the settings changed, or nginx took a reload (a host save
// reloads), so what a host renders may have changed.
func (s *DNSEntryService) markHostIndexDirty() {
	s.hostIdxDirty.Store(true)
}

// refreshHostIndex rebuilds the host index at the end of a check when there
// is none yet, it is dnsHostIndexMaxAge old, or it was marked. Until
// then a host change shows up late, and the host's 403s are counted as
// today meanwhile.
func (s *DNSEntryService) refreshHostIndex(ctx context.Context, refs []model.DNSReference) {
	idx := s.hostIdx.Load()
	if idx != nil && !s.hostIdxDirty.Load() && s.now().Sub(idx.builtAt) < dnsHostIndexMaxAge {
		return
	}
	s.hostIdxDirty.Store(false)
	s.rebuildHostIndex(ctx, refs, "")
}

// rebuildHostIndex builds the index for every list with domain entries, or
// only for onlyList (keeping the other lists' entries). A host whose config
// data cannot be built is left out: its 403s are counted, as today.
func (s *DNSEntryService) rebuildHostIndex(ctx context.Context, refs []model.DNSReference, onlyList string) {
	if s.hosts == nil || s.builder == nil {
		return
	}
	lists := make(map[string]bool)
	for _, r := range refs {
		if kind, owner, ok := model.ParseDNSScope(r.Scope); ok && kind == model.DNSScopeKindAccessList {
			lists[owner] = true
		}
	}
	old := s.hostIdx.Load()
	idx := &dnsHostIndex{byHost: make(map[string]*dnsHostEntry), byList: make(map[string][]*dnsHostEntry), builtAt: s.now()}
	if onlyList != "" && old != nil {
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
	s.hostIdx.Store(idx)
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
// nginx; anything the evaluator cannot read is counted, as today. It runs on
// the log tail goroutine: memory only.
func (s *DNSEntryService) ExemptAccessDenial(ctx context.Context, hostID, clientIP string) bool {
	idx := s.hostIdx.Load()
	if idx == nil {
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
