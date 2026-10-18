package handler

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// The priority allow domain names (#320) of a host's geo restriction
// (prio:<host id>) and of the global one (prio:global).

// globalPriorityScope is the scope of the global geo restriction's names.
const globalPriorityScope = model.DNSScopeKindPriority + ":global"

// SetDNSEntries wires the DNS entry service: a geo save checks its domain
// names against the limits and hands them to it before nginx is
// regenerated, and a GET shows their state.
func (h *GeoHandler) SetDNSEntries(svc *service.DNSEntryService) {
	if svc != nil {
		h.dns = svc
		h.dnsStatus = svc
	}
}

// geoRestrictionView is a host's geo restriction as GET shows it: the state
// of its priority allow domains, and the entries of allowed_ips the configs
// leave out (not an address: a name typed there before the domains had a
// field of their own). Such an entry stays stored; it moves to
// allowed_hostnames only when a save sends it there.
type geoRestrictionView struct {
	*model.GeoRestriction
	AllowedHostnameStatus []model.DNSEntryStatus `json:"allowed_hostname_status"`
	AllowedIPsIgnored     []string               `json:"allowed_ips_ignored"`
}

// globalGeoRestrictionView is geoRestrictionView for the global geo
// restriction.
type globalGeoRestrictionView struct {
	*model.GlobalGeoRestriction
	AllowedHostnameStatus []model.DNSEntryStatus `json:"allowed_hostname_status"`
	AllowedIPsIgnored     []string               `json:"allowed_ips_ignored"`
}

// hostGeoView converts a host's stored geo restriction for this caller.
func (h *GeoHandler) hostGeoView(c echo.Context, geo *model.GeoRestriction) geoRestrictionView {
	return geoRestrictionView{
		GeoRestriction:        geo,
		AllowedHostnameStatus: dnsStatusList(c, h.dnsStatus, geo.AllowedHostnames),
		AllowedIPsIgnored:     ignoredIPEntries(geo.AllowedIPs),
	}
}

// globalGeoView converts the global geo restriction for this caller.
func (h *GeoHandler) globalGeoView(c echo.Context, g *model.GlobalGeoRestriction) globalGeoRestrictionView {
	return globalGeoRestrictionView{
		GlobalGeoRestriction:  g,
		AllowedHostnameStatus: dnsStatusList(c, h.dnsStatus, g.AllowedHostnames),
		AllowedIPsIgnored:     ignoredIPEntries(g.AllowedIPs),
	}
}

// geoBefore is what a geo save compares with: the stored priority allow
// entries (a stored entry passes as it is, model.ValidateChangedGeoLists)
// and names. failed: the read failed, so every entry is checked as new and
// the names are handed over all the same.
type geoBefore struct {
	allowedIPs []string
	names      []string
	failed     bool
}

// geoBeforeNeeded reports whether a save reads the stored row: an entry
// that is not an address passes only when it is stored, and when the save
// changes the names (namesChange: it sends them, or deletes the row) the
// DNS entry service and the audit compare them with the stored ones. A save
// that leaves the names out keeps them, so the saved row has the stored
// names.
func (h *GeoHandler) geoBeforeNeeded(allowedIPs []string, namesChange bool) bool {
	return hasNonAddressEntry(allowedIPs) || (namesChange && (h.dns != nil || h.audit != nil))
}

// hasNonAddressEntry reports whether an entry is not an IP address or a
// CIDR range, a blank one included.
func hasNonAddressEntry(entries []string) bool {
	for _, e := range entries {
		if _, ok := model.NormalizeIPOrCIDR(strings.TrimSpace(e)); !ok {
			return true
		}
	}
	return false
}

// hostGeoBefore reads the host's stored geo restriction for a save.
func (h *GeoHandler) hostGeoBefore(ctx context.Context, hostID string, allowedIPs []string, namesChange bool) geoBefore {
	if !h.geoBeforeNeeded(allowedIPs, namesChange) {
		return geoBefore{}
	}
	geo, err := h.geoRepo.GetByProxyHostID(ctx, hostID)
	if err != nil {
		log.Printf("[Geo] WARN: could not read the geo restriction of host %s before saving it (%v); every priority allow entry is checked as new", hostID, err)
		return geoBefore{failed: true}
	}
	if geo == nil {
		return geoBefore{}
	}
	return geoBefore{allowedIPs: geo.AllowedIPs, names: geo.AllowedHostnames}
}

// globalGeoBefore reads the stored global geo restriction for a save.
func (h *GeoHandler) globalGeoBefore(ctx context.Context, allowedIPs []string, namesChange bool) geoBefore {
	if !h.geoBeforeNeeded(allowedIPs, namesChange) {
		return geoBefore{}
	}
	g, err := h.globalGeoRepo.GetGlobal(ctx)
	if err != nil {
		log.Printf("[Geo] WARN: could not read the global geo restriction before saving it (%v); every priority allow entry is checked as new", err)
		return geoBefore{failed: true}
	}
	return geoBefore{allowedIPs: g.AllowedIPs, names: g.AllowedHostnames}
}

// checkGeoLists checks the lists of a geo save against before: the
// countries and the priority allow entries it changed
// (model.ValidateChangedGeoLists, normalized in place), then the domain
// limits of scope. The names are checked before the stored row is read
// (normalizeDNSNames).
func (h *GeoHandler) checkGeoLists(ctx context.Context, scope string, countries, allowedIPs []string, names *[]string, before geoBefore) error {
	if err := model.ValidateChangedGeoLists(countries, allowedIPs, before.allowedIPs); err != nil {
		return err
	}
	return checkScopeLimits(ctx, h.dns, scope, names)
}

// geoRefused answers a geo save refused before it wrote (exceptionListRefusal),
// and any other error as the geo handler answers a failed read.
func geoRefused(c echo.Context, err error) error {
	if body, ok := exceptionListRefusal(err, "allowed_hostnames"); ok {
		return c.JSON(http.StatusBadRequest, body)
	}
	return directInternalError(c, err)
}

// syncGeoNames hands a geo save's names to the DNS entry service. A host's
// is called before the skip_reload branch: the host form saves geo with
// skip_reload and reloads once at the end (C5).
func (h *GeoHandler) syncGeoNames(ctx context.Context, scope string, before geoBefore, names []string) {
	syncExceptionNames(ctx, h.dns, scope, before.failed || len(before.names) > 0, names)
}

// auditHostGeo records a save of a host's geo restriction
// (geo_restriction_updated) and, when the save sent the names (namesSent)
// or removed the row, a change of them (dns_entries_changed).
func (h *GeoHandler) auditHostGeo(c echo.Context, hostName, scope string, details map[string]interface{}, namesSent bool, before geoBefore, names []string) {
	if h.audit == nil {
		return
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogGeoRestrictionUpdated(auditCtx, hostName, details)
	if namesSent {
		auditDNSNames(auditCtx, h.audit, scope, before.names, names)
	}
}

// hostName is a host's first domain name for the audit, or its id when the
// host cannot be read.
func (h *GeoHandler) hostName(ctx context.Context, hostID string) string {
	if host, err := h.proxyHostRepo.GetByID(ctx, hostID); err == nil && host != nil {
		return hostDomain(host)
	}
	return hostID
}

// hostDomain is a host's first domain name, or its id.
func hostDomain(host *model.ProxyHost) string {
	if len(host.DomainNames) > 0 {
		return host.DomainNames[0]
	}
	return host.ID
}
