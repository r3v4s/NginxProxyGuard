package nginx

import (
	"nginx-proxy-guard/internal/model"
)

// The domains of the exception lists (#320): URI block exceptions, priority
// allow, rate limit exceptions and the global trusted list. Each name
// reaches nginx as an include line, inside the list's geo block
// ($npg_uri_exc_<id>, $npg_prio_<id>, $rate_wl_<id>, $npg_trusted_<id>,
// nginx.conf's $global_trusted_ip), of the .geo file the DNS entry service
// writes for the name's scope and the name (dns_includes.go); a trusted name
// also reaches the access list block as its .allow file. The service's
// resolvers decide each name's scope (model.DNSRef: the host's list or the
// global one); this file only writes them. Whether a geo block and the
// checks that read it are rendered depends on the names a list holds, never
// on what they resolve to.

// dnsGeoIncludes returns the include lines of the .geo files of refs, in
// their order, each file once (dnsIncludeLines).
func dnsGeoIncludes(refs []model.DNSRef) []DNSIncludeLine {
	return dnsIncludeLines(refs, ".geo")
}

// dnsIncludeLines returns the include lines of the files of refs with the
// extension ext, in their order, each file once. A ref whose path cannot be
// built (a name that breaks the name rules, a scope that is not one) is left
// out and logged once: it allows no one, as an empty file would.
func dnsIncludeLines(refs []model.DNSRef, ext string) []DNSIncludeLine {
	var lines []DNSIncludeLine
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		path := DNSIncludeRenderPath(ref.Scope, ref.Name, ext)
		if path == "" {
			warnSkippedOnce("dns include "+ref.Scope+" "+ref.Name,
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

// trustedDNSIncludes returns the include lines of the files of the global
// trusted domains in names (scope "trusted") with the extension ext: ".geo"
// for a geo block, ".allow" for an access list block.
func trustedDNSIncludes(names []string, ext string) []DNSIncludeLine {
	refs := make([]model.DNSRef, len(names))
	for i, name := range names {
		refs[i] = model.DNSRef{Scope: model.DNSScopeKindTrusted, Name: name}
	}
	return dnsIncludeLines(refs, ext)
}

// TrustedDNSIncludes returns the include lines of the host's global trusted
// domains with the extension ext (trustedDNSIncludes).
func (d ProxyHostConfigData) TrustedDNSIncludes(ext string) []DNSIncludeLine {
	return trustedDNSIncludes(d.TrustedHostnames, ext)
}

// TrustedConfigured reports whether the host has global trusted entries,
// addresses or domains. Then access_list.conf defines $npg_trusted_<id>
// (it does for a host with rate limiting too: its key chain reads it), and
// the geo restriction, the geo challenge, the cloud provider block and the
// bot filter let it through. A ban, a filter subscription IP and the WAF
// give way to the addresses alone (the ban geo, $trusted_ip_<id>,
// nginx.conf's WAF rule): a domain never lifts them.
func (d ProxyHostConfigData) TrustedConfigured() bool {
	return len(d.GlobalTrustedIPs) > 0 || len(d.TrustedDNSIncludes(".geo")) > 0
}

// DNSTrustInAccessList reports whether the host's access list block
// includes the global trusted domains' .allow files, after the list's
// address rules and before the list's own domains, so that an address the
// list denies stays denied: the host has a list with entries and trusted
// domains, and the list does not let the addresses it allows skip the
// host's login (ListSkipsLogin). There a trusted domain would skip the
// login too, so it is left out; whoever holds it still passes the geo
// restriction and the bot filter, and signs in.
func (d ProxyHostConfigData) DNSTrustInAccessList() bool {
	return d.AccessList != nil && len(d.AccessList.Items) > 0 &&
		len(d.TrustedDNSIncludes(".allow")) > 0 && !d.ListSkipsLogin()
}

// hostDNSIncludeLines returns every domain include line the host config
// renders, under the conditions the templates render them: the access list
// block's (the list's domains, the trusted domains' .allow), then the
// exception lists' and the trusted domains' .geo.
func hostDNSIncludeLines(data ProxyHostConfigData) []DNSIncludeLine {
	lines := accessListDNSIncludes(data.AccessList)
	if data.DNSTrustInAccessList() {
		lines = append(lines, data.TrustedDNSIncludes(".allow")...)
	}
	lines = append(lines, data.URIExceptionDNSIncludes()...)
	if data.PriorityAllowConfigured() {
		lines = append(lines, dnsGeoIncludes(data.GeoRestriction.AllowedDNS)...)
	}
	if data.RateLimitEnabled() {
		lines = append(lines, dnsGeoIncludes(data.RateLimit.WhitelistDNS)...)
	}
	if data.TrustedConfigured() || data.RateLimitEnabled() {
		lines = append(lines, data.TrustedDNSIncludes(".geo")...)
	}
	return lines
}
