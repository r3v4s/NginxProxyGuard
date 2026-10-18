package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// The domains of the four exception lists (#320) as the API shows and
// confirms them: URI block exceptions, priority allow, rate limit exceptions
// and the global trusted list.
//   - Each list's GET carries the state of its domains (dnsStatusList). The
//     screens read those GETs already, so the state costs them no call, and
//     none of them calls a route of another area for it.
//   - Five routes allow again a domain of their lists that waits for
//     review, as POST /access-lists/:id/dns-confirm does for an access list
//     (AccessListHandler.ConfirmDNS). Each route needs the permission of its
//     lists' PUT; a domain has one state for every list that uses it, so the
//     handler also checks the write permission of every other use.

// exceptionDNSService is what ExceptionDNSHandler needs of
// service.DNSEntryService.
type exceptionDNSService interface {
	References(ctx context.Context, name string) ([]model.DNSReference, error)
	Confirm(ctx context.Context, name string, expected []string, expectedCanonical string) (model.DNSEntryStatus, nginx.DNSApplyResult, error)
}

// exceptionDNSHosts reads the host of POST /proxy-hosts/:id/dns-confirm
// (repository.ProxyHostRepository).
type exceptionDNSHosts interface {
	GetByID(ctx context.Context, id string) (*model.ProxyHost, error)
}

// exceptionDNSAuditor records a confirm (service.AuditService).
type exceptionDNSAuditor interface {
	LogDNSEntryConfirmed(ctx context.Context, name string, addrs []string, canonical string, scopes []string) error
}

// ExceptionDNSHandler serves the confirm routes of the exception lists. Its
// dependencies sit behind the narrow interfaces above, so its tests can use
// fakes.
type ExceptionDNSHandler struct {
	hosts exceptionDNSHosts
	dns   exceptionDNSService
	audit exceptionDNSAuditor
}

// NewExceptionDNSHandler builds the handler. Without a DNS entry service
// every confirm answers 500; without an audit service nothing is recorded.
func NewExceptionDNSHandler(hosts *repository.ProxyHostRepository, dns *service.DNSEntryService, audit *service.AuditService) *ExceptionDNSHandler {
	h := &ExceptionDNSHandler{}
	if hosts != nil {
		h.hosts = hosts
	}
	if dns != nil {
		h.dns = dns
	}
	if audit != nil {
		h.audit = audit
	}
	return h
}

// ConfirmHost is POST /proxy-hosts/:id/dns-confirm: a domain of the host's
// URI block exceptions, priority allow or rate limit exceptions.
func (h *ExceptionDNSHandler) ConfirmHost(c echo.Context) error {
	host, err := h.hosts.GetByID(c.Request().Context(), c.Param("id"))
	if err != nil {
		return databaseError(c, "get proxy host", err)
	}
	if host == nil {
		return notFoundError(c, "Proxy host")
	}
	return h.confirmDNSInScopes(c, []string{
		exceptionHostScope(model.DNSScopeKindURIBlock, host.ID),
		exceptionHostScope(model.DNSScopeKindPriority, host.ID),
		exceptionHostScope(model.DNSScopeKindRateLimit, host.ID),
	})
}

// ConfirmGlobalURIBlock is POST /global-uri-block/dns-confirm.
func (h *ExceptionDNSHandler) ConfirmGlobalURIBlock(c echo.Context) error {
	return h.confirmDNSInScopes(c, []string{globalURIBlockScope})
}

// ConfirmGlobalGeo is POST /settings/global-geo/dns-confirm: a domain of the
// global priority allow list.
func (h *ExceptionDNSHandler) ConfirmGlobalGeo(c echo.Context) error {
	return h.confirmDNSInScopes(c, []string{globalPriorityScope})
}

// ConfirmGlobalRateLimit is POST /settings/global-rate-limit/dns-confirm.
func (h *ExceptionDNSHandler) ConfirmGlobalRateLimit(c echo.Context) error {
	return h.confirmDNSInScopes(c, []string{globalRateLimitScope})
}

// ConfirmTrusted is POST /system-settings/trusted-dns-confirm: a domain of
// the global trusted list.
func (h *ExceptionDNSHandler) ConfirmTrusted(c echo.Context) error {
	return h.confirmDNSInScopes(c, []string{model.DNSScopeKindTrusted})
}

// confirmDNSInScopes allows again a domain that waits for review and is in
// one of scopes, the lists of the route. It answers as an access list's
// confirm does: 400 not_in_list when none of those lists holds the domain;
// 403 {error, required} when the caller may not change the domain everywhere
// it is used; then what the DNS service refused (dnsConfirmRefused). The
// service looks the name up again (at most 3 s) and publishes its own
// answer, and only when that is what the client showed. A confirmed domain
// is published, so it is recorded also when nginx refused to load it (409
// nginx_reload_rejected) or the client left meanwhile; the answer is its
// state as the caller may see it.
func (h *ExceptionDNSHandler) confirmDNSInScopes(c echo.Context, scopes []string) error {
	ctx := c.Request().Context()
	var req accessListDNSConfirmRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if h.dns == nil {
		return internalError(c, "confirm exception list domain", errDNSEntriesUnavailable)
	}
	name := model.NormalizeDNSName(req.Hostname)
	refs, err := h.dns.References(ctx, name)
	if err != nil {
		return internalError(c, "read where a domain is used", err)
	}
	if !dnsUsedIn(refs, scopes) {
		return c.JSON(http.StatusBadRequest, dnsConfirmError{
			Error: "hostname: not a domain of this list", Code: "not_in_list", Field: "hostname",
		})
	}
	if missing := missingDNSWritePermissions(c, refs); len(missing) > 0 {
		return c.JSON(http.StatusForbidden, dnsConfirmForbidden{
			Error:    "this domain is also used where you may not make changes, and confirming it allows it there too",
			Required: missing,
		})
	}

	expectedCanonical := dnsentry.NormalizeCanonical(strings.TrimSpace(req.ExpectedCanonicalName))
	status, result, err := h.dns.Confirm(ctx, name, req.ExpectedAddresses, expectedCanonical)
	if err != nil {
		return dnsConfirmRefused(c, err)
	}
	// The audit records the answer the server saw and published.
	canonical := ""
	if status.ObservedCanonicalName != nil {
		canonical = *status.ObservedCanonicalName
	}
	if h.audit != nil {
		h.audit.LogDNSEntryConfirmed(service.ContextWithAudit(context.WithoutCancel(ctx), c), name, status.ObservedAddresses, canonical, dnsRefScopes(refs))
	}
	if result.Outcome == string(nginx.ReloadRejected) {
		return internalError(c, "apply the confirmed domain to nginx", &nginx.ReloadRejectedError{Detail: result.Detail})
	}
	return c.JSON(http.StatusOK, dnsStatusViewFor(c).filter(status))
}

// dnsUsedIn reports whether one of refs is a use in one of scopes.
func dnsUsedIn(refs []model.DNSReference, scopes []string) bool {
	for _, ref := range refs {
		if slices.Contains(scopes, ref.Scope) {
			return true
		}
	}
	return false
}

// dnsStatusReader is what an exception list's GET needs of
// service.DNSEntryService: the state of the list's domains.
type dnsStatusReader interface {
	Statuses(ctx context.Context, names []string, view model.DNSStatusView) (map[string]model.DNSEntryStatus, error)
}

// dnsStatusesFor reads the state of names as the caller may see it: the DNS
// service leaves out what the caller's view hides (dnsStatusView), and
// filter checks it once more. The caller's permissions are asked only when
// there are names. nil without names or a DNS entry service, and when the
// state cannot be read (logged): the list still answers, its domains
// without state.
func dnsStatusesFor(c echo.Context, dns dnsStatusReader, names []string) map[string]model.DNSEntryStatus {
	if dns == nil || len(names) == 0 {
		return nil
	}
	view := dnsStatusViewFor(c)
	statuses, err := dns.Statuses(c.Request().Context(), names, view.serviceView())
	if err != nil {
		log.Printf("[DNSEntries] WARN: could not read the state of a list's domains, so the list is shown without it: %v", err)
		return nil
	}
	out := make(map[string]model.DNSEntryStatus, len(statuses))
	for name, st := range statuses {
		out[name] = view.filter(st)
	}
	return out
}

// dnsStatusesOf returns the states in statuses of names, in the names'
// order; a name without one is left out. Never nil.
func dnsStatusesOf(statuses map[string]model.DNSEntryStatus, names []string) []model.DNSEntryStatus {
	out := make([]model.DNSEntryStatus, 0, len(names))
	for _, n := range names {
		if st, ok := statuses[n]; ok {
			out = append(out, st)
		}
	}
	return out
}

// dnsStatusList returns the state of one list's names, in their order, as
// the caller may see it (dnsStatusesFor). Never nil.
func dnsStatusList(c echo.Context, dns dnsStatusReader, names []string) []model.DNSEntryStatus {
	return dnsStatusesOf(dnsStatusesFor(c, dns, names), names)
}

// ignoredIPEntries returns the entries of an IP field that the configs leave
// out (model.IgnoredIPEntries), never nil.
func ignoredIPEntries(entries []string) []string {
	if ignored := model.IgnoredIPEntries(entries); ignored != nil {
		return ignored
	}
	return []string{}
}
