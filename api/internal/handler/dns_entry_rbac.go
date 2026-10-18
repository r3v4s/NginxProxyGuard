package handler

import (
	"sort"

	"github.com/labstack/echo/v4"

	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
)

// A DNS name has one state for every list that uses it, so two
// questions need the permission of each use's scope: who uses a name (the
// overview names a use only to a caller who may read its list), and who may
// confirm a name that waits for review (a confirm allows the name again in
// every list that uses it). One table answers both: a use is read and
// changed with the permissions of its list's screen. An access list is
// access; a host's URI block exceptions, priority allow and rate limit
// exceptions are proxy, as the host form that edits them; the global ones
// are waf, the area their screens sit under; the global trusted list is
// settings. A scope that does not parse is readable and writable by no one,
// so a confirm of a name used there answers 403 naming the scope.

// Permissions checked in this file.
const (
	permAccessRead    = "access:read"
	permAccessWrite   = "access:write"
	permWAFRead       = "waf:read"
	permWAFWrite      = "waf:write"
	permDDNSRead      = "ddns:read"
	permProxyRead     = "proxy:read"
	permProxyWrite    = "proxy:write"
	permSettingsRead  = "settings:read"
	permSettingsWrite = "settings:write"
)

// dnsScopePermissions returns the permissions that show and change a use of a
// name in scope, "" and "" when none do.
func dnsScopePermissions(scope string) (read, write string) {
	kind, owner, ok := model.ParseDNSScope(scope)
	if !ok {
		return "", ""
	}
	switch kind {
	case model.DNSScopeKindAccessList:
		return permAccessRead, permAccessWrite
	case model.DNSScopeKindURIBlock, model.DNSScopeKindPriority, model.DNSScopeKindRateLimit:
		if owner == "global" {
			return permWAFRead, permWAFWrite
		}
		return permProxyRead, permProxyWrite
	case model.DNSScopeKindTrusted:
		return permSettingsRead, permSettingsWrite
	}
	return "", ""
}

// dnsScopeReadPermission returns the permission that shows a use of a name in
// scope, "" when none does.
func dnsScopeReadPermission(scope string) string {
	read, _ := dnsScopePermissions(scope)
	return read
}

// dnsScopeWritePermission returns the permission that changes a name's use in
// scope, "" when none does.
func dnsScopeWritePermission(scope string) string {
	_, write := dnsScopePermissions(scope)
	return write
}

// missingDNSWritePermissions returns what the caller lacks to confirm a name
// that refs use: the write permission of each scope it may not change, or
// the scope itself when no permission changes it. Sorted, each once; empty
// when the caller may change the name everywhere it is used.
func missingDNSWritePermissions(c echo.Context, refs []model.DNSReference) []string {
	held := map[string]bool{}
	missing := map[string]bool{}
	for _, ref := range refs {
		need := dnsScopeWritePermission(ref.Scope)
		if need == "" {
			missing[ref.Scope] = true
			continue
		}
		ok, asked := held[need]
		if !asked {
			ok = authMiddleware.HasPermissionFromContext(c, need)
			held[need] = ok
		}
		if !ok {
			missing[need] = true
		}
	}
	out := make([]string, 0, len(missing))
	for m := range missing {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// dnsStatusView is what one caller may see of a name's state: the banned
// warning needs waf:read, the self_ip warning
// ddns:read (it tells NPG's own public address), and the blocking file and
// the names of login hosts proxy:read.
type dnsStatusView struct {
	banned, selfIP, proxyRead bool
}

// dnsStatusViewFor asks the caller's permissions, once per request.
func dnsStatusViewFor(c echo.Context) dnsStatusView {
	return dnsStatusView{
		banned:    authMiddleware.HasPermissionFromContext(c, permWAFRead),
		selfIP:    authMiddleware.HasPermissionFromContext(c, permDDNSRead),
		proxyRead: authMiddleware.HasPermissionFromContext(c, permProxyRead),
	}
}

// serviceView is the view as the DNS service takes it (Statuses, Overview):
// the service leaves out what the caller may not see.
func (v dnsStatusView) serviceView() model.DNSStatusView {
	return model.DNSStatusView{Banned: v.banned, SelfIP: v.selfIP, BlockingFile: v.proxyRead}
}

// filter returns st as this caller may see it. It does not change st's
// slices.
func (v dnsStatusView) filter(st model.DNSEntryStatus) model.DNSEntryStatus {
	if st.Warnings != nil && (!v.banned || !v.selfIP) {
		kept := make([]string, 0, len(st.Warnings))
		for _, w := range st.Warnings {
			if (w == model.DNSWarnBanned && !v.banned) || (w == model.DNSWarnSelfIP && !v.selfIP) {
				continue
			}
			kept = append(kept, w)
		}
		st.Warnings = kept
	}
	if !v.proxyRead {
		st.BlockingFile = nil
	}
	return st
}
