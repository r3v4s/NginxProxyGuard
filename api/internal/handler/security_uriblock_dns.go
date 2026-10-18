package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
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
