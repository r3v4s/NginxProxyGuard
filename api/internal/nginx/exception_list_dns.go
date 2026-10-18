package nginx

import (
	"nginx-proxy-guard/internal/model"
)

// The domains of the exception lists (#320): URI block exceptions, priority
// allow and rate limit exceptions. Each name reaches nginx as an include
// line, inside the list's geo block ($npg_uri_exc_<id>, $npg_prio_<id>,
// $rate_wl_<id>), of the .geo file the DNS entry service writes for the
// name's scope and the name (dns_includes.go). The service's resolvers
// decide each name's scope (model.DNSRef: the host's list or the global
// one); this file only writes them. Whether a geo block and the checks that
// read it are rendered depends on the names a list holds, never on what they
// resolve to.

// dnsGeoIncludes returns the include lines of the .geo files of refs, in
// their order, each file once. A ref whose path cannot be built (a name that
// breaks the name rules, a scope that is not one) is left out and logged
// once: it allows no one, as an empty file would.
func dnsGeoIncludes(refs []model.DNSRef) []DNSIncludeLine {
	var lines []DNSIncludeLine
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		path := DNSIncludeRenderPath(ref.Scope, ref.Name, ".geo")
		if path == "" {
			warnSkippedOnce("dns geo include "+ref.Scope+" "+ref.Name,
				"[DNSEntries] WARN: domain entry %.80q of %.80q is not a usable domain name, so it is left out of the nginx config. Edit the list to correct or remove it.",
				ref.Name, ref.Scope)
			continue
		}
		if !seen[path] {
			seen[path] = true
			lines = append(lines, DNSIncludeLine{Name: ref.Name, Path: path})
		}
	}
	return lines
}

// URIExceptionDNSIncludes returns the include lines of the URI block's
// exception domains, or none on a host whose Advanced Config asks for a login
// (auth_basic or auth_request, AdvancedConfigHasAuth). The exception path
// cannot run that login, so a domain there would open the blocked paths to
// whoever holds the name's DNS. The static exceptions stay as they are. A
// host with an auth provider (ForwardAuth) does get them: the exception path
// runs the same login gate as location /.
func (d ProxyHostConfigData) URIExceptionDNSIncludes() []DNSIncludeLine {
	if d.URIBlock == nil || !d.URIBlock.Enabled || len(d.URIBlock.ExceptionDNS) == 0 {
		return nil
	}
	if d.Host != nil && AdvancedConfigHasAuth(d.Host.AdvancedConfig) {
		warnSkippedOnce("uri block exception domains skipped "+d.Host.ID,
			"[DNSEntries] WARN: Host %s: its Advanced Config asks for a login (auth_basic or auth_request), which the URI block exception path cannot run, so its exception domains are not applied there. Its exception IPs still are.",
			d.Host.ID)
		return nil
	}
	return dnsGeoIncludes(d.URIBlock.ExceptionDNS)
}

// URIExceptionsConfigured reports whether the URI block has exceptions to
// test: exception IPs, or exception domains the host renders. Then
// access_list.conf defines $npg_uri_exc_<id> and each blocked location tests
// it.
func (d ProxyHostConfigData) URIExceptionsConfigured() bool {
	return d.URIBlock != nil && d.URIBlock.Enabled &&
		(len(d.URIBlock.ExceptionIPs) > 0 || len(d.URIExceptionDNSIncludes()) > 0)
}

// PriorityAllowConfigured reports whether the host has priority allow
// entries, addresses or domains. Then access_list.conf defines
// $npg_prio_<id>, and the geo direct block, the geo challenge, the cloud
// provider block and the bot filter let it through. The host's WAF file
// gets the addresses alone (GenerateHostWAFConfig): a domain never turns
// the WAF off.
func (d ProxyHostConfigData) PriorityAllowConfigured() bool {
	return d.GeoRestriction != nil &&
		(len(d.GeoRestriction.AllowedIPs) > 0 || len(dnsGeoIncludes(d.GeoRestriction.AllowedDNS)) > 0)
}

// hostDNSIncludeLines returns every domain include line the host config
// renders, under the conditions the templates render them: the access list
// block's, then the exception lists'.
func hostDNSIncludeLines(data ProxyHostConfigData) []DNSIncludeLine {
	lines := accessListDNSIncludes(data.AccessList)
	lines = append(lines, data.URIExceptionDNSIncludes()...)
	if data.PriorityAllowConfigured() {
		lines = append(lines, dnsGeoIncludes(data.GeoRestriction.AllowedDNS)...)
	}
	if data.RateLimitEnabled() {
		lines = append(lines, dnsGeoIncludes(data.RateLimit.WhitelistDNS)...)
	}
	return lines
}
