package service

import "nginx-proxy-guard/internal/model"

// resolveGeo collapses the global geo default and a host's own geo row into the
// single effective *model.GeoRestriction the nginx template consumes. The
// template is unchanged — it always reads one object — so this resolver is the
// only place the global-vs-host precedence lives.
//
// 3-state:
//   - override: host has its own enabled geo  -> use host (current behavior)
//   - disable:  host.DisableGlobal            -> no geo block
//   - inherit:  otherwise                     -> global default (when enabled)
//
// The host's AllowedIPs are ALWAYS preserved (unioned in) because the cloud and
// bot-filter template sections read GeoRestriction.AllowedIPs as priority-allow
// IPs regardless of whether a geo block is active. Dropping them here would
// silently break cloud/bot priority-allow — a side effect this design forbids.
//
// The priority allow domains (#320) follow the addresses: AllowedDNS holds the
// host's names with the host's scope in every state, and an inheriting host
// also gets the global names, a name on both lists once with the host's scope.
// A host row of names alone is kept like one of addresses alone. An overriding
// host gets a copy of its row: the row is the repository's.
func resolveGeo(global *model.GlobalGeoRestriction, host *model.GeoRestriction) *model.GeoRestriction {
	var hostAllowed []string
	var hostDNS []model.DNSRef
	if host != nil {
		hostAllowed = host.AllowedIPs
		hostDNS = dnsRefs(model.DNSScopeKindPriority+":"+host.ProxyHostID, host.AllowedHostnames)
	}

	// Override: host runs its own geo restriction.
	if host != nil && host.Enabled {
		geo := *host
		geo.AllowedDNS = hostDNS
		return &geo
	}

	// Disable: no geo block for this host, but keep its AllowedIPs alive so the
	// cloud/bot priority-allow sections still see them.
	if host != nil && host.DisableGlobal {
		if len(hostAllowed) == 0 && len(hostDNS) == 0 {
			return nil
		}
		return &model.GeoRestriction{Enabled: false, AllowedIPs: hostAllowed, AllowedDNS: hostDNS}
	}

	// Inherit: use the global default when it is enabled.
	if global != nil && global.Enabled {
		return &model.GeoRestriction{
			Mode:            global.Mode,
			Countries:       global.Countries,
			AllowedIPs:      unionStrings(hostAllowed, global.AllowedIPs),
			AllowPrivateIPs: global.AllowPrivateIPs,
			AllowSearchBots: global.AllowSearchBots,
			Enabled:         true,
			ChallengeMode:   global.ChallengeMode,
			AllowedDNS:      unionDNSRefs(hostDNS, dnsRefs(model.DNSScopeKindPriority+":global", global.AllowedHostnames)),
		}
	}

	// Inherit but the global default is off: preserve host AllowedIPs if any
	// (cloud/bot priority-allow), otherwise there is nothing to render.
	if len(hostAllowed) > 0 || len(hostDNS) > 0 {
		return &model.GeoRestriction{Enabled: false, AllowedIPs: hostAllowed, AllowedDNS: hostDNS}
	}
	return nil
}

// unionStrings returns a and b concatenated with duplicates removed, preserving
// first-seen order (a's entries first).
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// dnsRefs returns the names of an exception list (#320) as the domains a
// config renders, each with scope, in order and each name once. A host's
// list has the scope of the host the row belongs to ("prio:<id>"; the DNS
// entry service writes the file of the same row's proxy_host_id), a global
// list "<kind>:global". The render leaves out a name it cannot use
// (dnsGeoIncludes).
func dnsRefs(scope string, names []string) []model.DNSRef {
	if len(names) == 0 {
		return nil
	}
	refs := make([]model.DNSRef, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !seen[name] {
			seen[name] = true
			refs = append(refs, model.DNSRef{Scope: scope, Name: name})
		}
	}
	return refs
}

// unionDNSRefs returns a, then the refs of b whose name a does not hold. With
// a host's list first, a name it shares with the global list keeps the host's
// scope: a geo block includes each name's addresses once (the same network
// twice is a warning at every reload).
func unionDNSRefs(a, b []model.DNSRef) []model.DNSRef {
	out := make([]model.DNSRef, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, list := range [][]model.DNSRef{a, b} {
		for _, ref := range list {
			if !seen[ref.Name] {
				seen[ref.Name] = true
				out = append(out, ref)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
