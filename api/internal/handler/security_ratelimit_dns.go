package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
)

// The rate limit exception domain names (#320) of a host (rl:<host id>) and
// of the global rate limit (rl:global). The service checks the limits and
// hands the names over; the handlers check the names and record their
// change.

// globalRateLimitScope is the scope of the global rate limit's names.
const globalRateLimitScope = model.DNSScopeKindRateLimit + ":global"

// checkWhitelistIPs checks a rate limit exception list a save changes
// (model.ValidateIPWhitelist): the first entry refused is named, and a
// domain name says it goes in whitelist_hostnames.
func checkWhitelistIPs(raw string) error {
	_, invalid := model.ParseIPWhitelist(raw)
	if len(invalid) == 0 {
		return nil
	}
	if e := model.HostnameInIPField("whitelist_ips", invalid[0], "whitelist_hostnames"); e != nil {
		return e
	}
	return fmt.Errorf("%w: %v", model.ErrInvalidInput, model.ValidateIPWhitelist(raw))
}

// rateLimitRefused answers a rate limit save refused before it wrote
// (exceptionListRefusal), and any other error as internalError does for
// operation.
func rateLimitRefused(c echo.Context, err error, operation string) error {
	if body, ok := exceptionListRefusal(err, "whitelist_hostnames"); ok {
		return c.JSON(http.StatusBadRequest, body)
	}
	return internalError(c, operation, err)
}

// storedRateLimitNames returns the names of the host's rate limit before a
// delete, for its audit; nil without an audit service or when it cannot be
// read.
func (h *SecurityHandler) storedRateLimitNames(ctx context.Context, proxyHostID string) []string {
	if h.audit == nil {
		return nil
	}
	if cur, err := h.securityService.GetRateLimit(ctx, proxyHostID); err == nil && cur != nil {
		return cur.WhitelistHostnames
	}
	return nil
}

// rateLimitView is a host's rate limit as GET shows it: the state of its
// exception domains.
type rateLimitView struct {
	*model.RateLimit
	WhitelistHostnameStatus []model.DNSEntryStatus `json:"whitelist_hostname_status"`
}

// globalRateLimitView is rateLimitView for the global rate limit.
type globalRateLimitView struct {
	*model.GlobalRateLimit
	WhitelistHostnameStatus []model.DNSEntryStatus `json:"whitelist_hostname_status"`
}

// rateLimitView converts a host's rate limit for this caller.
func (h *SecurityHandler) rateLimitView(c echo.Context, rl *model.RateLimit) rateLimitView {
	return rateLimitView{RateLimit: rl, WhitelistHostnameStatus: dnsStatusList(c, h.dnsStatus, rl.WhitelistHostnames)}
}

// globalRateLimitView converts the global rate limit for this caller.
func (h *SecurityHandler) globalRateLimitView(c echo.Context, g *model.GlobalRateLimit) globalRateLimitView {
	return globalRateLimitView{GlobalRateLimit: g, WhitelistHostnameStatus: dnsStatusList(c, h.dnsStatus, g.WhitelistHostnames)}
}
