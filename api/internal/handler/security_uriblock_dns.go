package handler

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// The URI block exception domain names (#320) of a host (uri:<host id>) and
// of the global URI block (uri:global). The service checks the limits and
// hands the names over; the handlers check the names and record their
// change.

// globalURIBlockScope is the scope of the global URI block's names.
const globalURIBlockScope = model.DNSScopeKindURIBlock + ":global"

// checkURIBlockExceptions checks the exceptions of a URI block save: the
// exception IPs (checked whole since v2.4.3; the first entry refused decides
// the answer, and a domain name says it goes in exception_hostnames), then
// the names, normalized in place.
func checkURIBlockExceptions(ips []string, names *[]string) error {
	if invalid := ValidateIPList(ips); len(invalid) > 0 {
		for i, ip := range ips {
			if ValidateCIDR(ip) {
				continue
			}
			if e := model.HostnameInIPField(fmt.Sprintf("exception_ips[%d]", i), ip, "exception_hostnames"); e != nil {
				return e
			}
			break
		}
		return fmt.Errorf("%w: Invalid IP address(es) in exception_ips: %s", model.ErrInvalidInput, strings.Join(invalid, ", "))
	}
	return normalizeDNSNames("exception_hostnames", names)
}

// uriBlockRefused answers a URI block save refused before it wrote
// (exceptionListRefusal), and any other error as internalError does for
// operation.
func uriBlockRefused(c echo.Context, err error, operation string) error {
	if body, ok := exceptionListRefusal(err, "exception_hostnames"); ok {
		return c.JSON(http.StatusBadRequest, body)
	}
	return internalError(c, operation, err)
}

// storedURIBlockNames returns the names of the host's URI block before a
// delete, for its audit; nil without an audit service or when the block
// cannot be read.
func (h *SecurityHandler) storedURIBlockNames(ctx context.Context, proxyHostID string) []string {
	if h.audit == nil {
		return nil
	}
	if cur, err := h.securityService.GetURIBlock(ctx, proxyHostID); err == nil && cur != nil {
		return cur.ExceptionHostnames
	}
	return nil
}

// uriBlockView is a host's URI block as GET shows it: the state of its
// exception domains, and whether the host leaves them out
// (exception_hostnames_skipped). A host whose Advanced Config asks for a
// login (auth_basic or auth_request) applies no exception domain, its own
// or the global ones: the exception path cannot run that login
// (nginx.ProxyHostConfigData.URIExceptionDNSIncludes). Its exception IPs
// still apply.
type uriBlockView struct {
	*model.URIBlock
	ExceptionHostnameStatus   []model.DNSEntryStatus `json:"exception_hostname_status"`
	ExceptionHostnamesSkipped bool                   `json:"exception_hostnames_skipped"`
}

// uriBlockListEntryView is uriBlockView for an entry of GET /uri-blocks,
// which the URI block screen reads for every host.
type uriBlockListEntryView struct {
	repository.URIBlockWithHost
	ExceptionHostnameStatus   []model.DNSEntryStatus `json:"exception_hostname_status"`
	ExceptionHostnamesSkipped bool                   `json:"exception_hostnames_skipped"`
}

// globalURIBlockView is the global URI block as GET shows it: the state of
// its exception domains.
type globalURIBlockView struct {
	*model.GlobalURIBlock
	ExceptionHostnameStatus []model.DNSEntryStatus `json:"exception_hostname_status"`
}

// uriBlockView converts a host's URI block for this caller.
func (h *SecurityHandler) uriBlockView(c echo.Context, ub *model.URIBlock) uriBlockView {
	return uriBlockView{
		URIBlock:                  ub,
		ExceptionHostnameStatus:   dnsStatusList(c, h.dnsStatus, ub.ExceptionHostnames),
		ExceptionHostnamesSkipped: h.securityService.URIExceptionDomainsSkipped(c.Request().Context(), ub.ProxyHostID),
	}
}

// uriBlockListView converts GET /uri-blocks for this caller; the state of
// every entry's domains is read at once.
func (h *SecurityHandler) uriBlockListView(c echo.Context, blocks []repository.URIBlockWithHost) []uriBlockListEntryView {
	var names []string
	for _, b := range blocks {
		for _, n := range b.ExceptionHostnames {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	statuses := dnsStatusesFor(c, h.dnsStatus, names)
	out := make([]uriBlockListEntryView, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, uriBlockListEntryView{
			URIBlockWithHost:          b,
			ExceptionHostnameStatus:   dnsStatusesOf(statuses, b.ExceptionHostnames),
			ExceptionHostnamesSkipped: nginx.AdvancedConfigHasAuth(b.AdvancedConfig),
		})
	}
	return out
}

// globalURIBlockView converts the global URI block for this caller.
func (h *SecurityHandler) globalURIBlockView(c echo.Context, block *model.GlobalURIBlock) globalURIBlockView {
	return globalURIBlockView{GlobalURIBlock: block, ExceptionHostnameStatus: dnsStatusList(c, h.dnsStatus, block.ExceptionHostnames)}
}
