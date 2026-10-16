package handler

import (
	"context"
	"log"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
)

// The API shows a domain rule as {directive: allow, address: <name>, kind:
// hostname, dns: <state>}, while the repository keeps the stored form (deny,
// all, hostname) that the renderer and the audit diff read. The conversion
// happens here only, for List, Get, Create and Update: a converted
// rule handed to the renderer would be an allow of a name, which it leaves
// out.

// accessListItemView is a rule as the API shows it.
type accessListItemView struct {
	model.AccessListItem
	Kind   string                `json:"kind"`
	Effect string                `json:"effect,omitempty"`
	DNS    *model.DNSEntryStatus `json:"dns,omitempty"`
}

// accessListLoginBypass counts the hosts where the list lets its domains in
// without the host's login. Hosts is nil without
// proxy:read.
type accessListLoginBypass struct {
	Count int                `json:"count"`
	Hosts []model.DNSHostRef `json:"hosts"`
}

// accessListView is an access list as the API shows it.
type accessListView struct {
	model.AccessList
	Items            []accessListItemView  `json:"items,omitempty"`
	LoginBypassHosts accessListLoginBypass `json:"login_bypass_hosts"`
}

// accessListListResponse is a page of lists as the API shows them.
type accessListListResponse struct {
	model.AccessListListResponse
	Data []accessListView `json:"data"`
}

// viewsOf converts lists for this caller. The domains' state is read once
// for all of them, and the caller's permissions are asked only when a list
// has domains. nil stays nil.
func (h *AccessListHandler) viewsOf(c echo.Context, lists []model.AccessList) []accessListView {
	if lists == nil {
		return nil
	}
	var view dnsStatusView
	var statuses map[string]model.DNSEntryStatus
	if names := listsDNSNames(lists); h.dns != nil && len(names) > 0 {
		view = dnsStatusViewFor(c)
		statuses = h.dnsStatuses(c.Request().Context(), names, view)
	}
	out := make([]accessListView, 0, len(lists))
	for i := range lists {
		out = append(out, h.listView(&lists[i], statuses, view))
	}
	return out
}

// viewOf converts one list for this caller.
func (h *AccessListHandler) viewOf(c echo.Context, list *model.AccessList) accessListView {
	return h.viewsOf(c, []model.AccessList{*list})[0]
}

// dnsStatuses reads the state of names as this caller may see it: the DNS
// service leaves out what the view hides, and filter checks it once more. A
// failed read is logged and leaves the rules without state: the lists still
// answer.
func (h *AccessListHandler) dnsStatuses(ctx context.Context, names []string, view dnsStatusView) map[string]model.DNSEntryStatus {
	statuses, err := h.dns.Statuses(ctx, names, view.serviceView())
	if err != nil {
		log.Printf("[AccessList] could not read the state of the lists' domains: %v", err)
		return nil
	}
	out := make(map[string]model.DNSEntryStatus, len(statuses))
	for name, st := range statuses {
		out[name] = view.filter(st)
	}
	return out
}

// listView converts one list with the states read for it.
func (h *AccessListHandler) listView(list *model.AccessList, statuses map[string]model.DNSEntryStatus, view dnsStatusView) accessListView {
	v := accessListView{AccessList: *list}
	for _, it := range list.Items {
		v.Items = append(v.Items, itemView(it, statuses))
	}
	v.LoginBypassHosts = h.loginBypass(list, view)
	return v
}

// itemView converts one stored rule.
func itemView(it model.AccessListItem, statuses map[string]model.DNSEntryStatus) accessListItemView {
	v := accessListItemView{AccessListItem: it, Kind: model.AccessListItemKind(it)}
	switch v.Kind {
	case model.AccessListKindHostname:
		v.Directive, v.Address = "allow", it.Hostname
		if st, ok := statuses[it.Hostname]; ok {
			v.DNS = &st
		}
	case model.AccessListKindLegacy:
		v.Effect = model.AccessListLegacyEffect(it)
	}
	return v
}

// loginBypass counts the hosts where list lets its domains skip the login.
// Only a satisfy-any list with domains can; which hosts have a login the DNS
// service's host index knows.
func (h *AccessListHandler) loginBypass(list *model.AccessList, view dnsStatusView) accessListLoginBypass {
	if h.dns == nil || !list.SatisfyAny || len(accessListDNSNames(list.Items)) == 0 {
		return accessListLoginBypass{}
	}
	hosts := h.dns.LoginBypassHosts(list.ID)
	out := accessListLoginBypass{Count: len(hosts)}
	if view.proxyRead && len(hosts) > 0 {
		out.Hosts = hosts
	}
	return out
}

// listsDNSNames returns the domains of lists, each once.
func listsDNSNames(lists []model.AccessList) []string {
	var names []string
	seen := map[string]bool{}
	for i := range lists {
		for _, name := range accessListDNSNames(lists[i].Items) {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// accessListDNSNames returns the domains of stored rules, in rule order, each
// once.
func accessListDNSNames(items []model.AccessListItem) []string {
	var names []string
	seen := map[string]bool{}
	for _, it := range items {
		if it.Hostname != "" && !seen[it.Hostname] {
			seen[it.Hostname] = true
			names = append(names, it.Hostname)
		}
	}
	return names
}

// requestDNSNames returns the domains of checked request rules, in rule
// order, each once.
func requestDNSNames(items []model.CreateAccessListItemRequest) []string {
	var names []string
	seen := map[string]bool{}
	for _, it := range items {
		if it.Hostname != "" && !seen[it.Hostname] {
			seen[it.Hostname] = true
			names = append(names, it.Hostname)
		}
	}
	return names
}

// hasDNSName reports whether one of items is the domain name.
func hasDNSName(items []model.AccessListItem, name string) bool {
	for _, it := range items {
		if name != "" && it.Hostname == name {
			return true
		}
	}
	return false
}
