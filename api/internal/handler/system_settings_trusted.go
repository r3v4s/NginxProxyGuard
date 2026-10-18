package handler

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// The global trusted list in PUT /system-settings (#320): the IP lines
// (global_trusted_ips) and the domain names (global_trusted_hostnames,
// scope trusted). The names reach the DNS entry service before the
// background worker re-renders nginx.conf and the hosts, so a name taken
// out has an empty file before the save answers.

// trustedSave carries the global trusted domain names of one PUT from the
// checks before the save to the work after it.
type trustedSave struct {
	set    bool     // the request carried global_trusted_hostnames
	before []string // the stored names
}

// checkTrustedLists checks the global trusted list fields of a PUT against
// cur, the stored row, which the handler reads whenever the request carries
// one of them: the IP lines the save changes
// (model.ValidateChangedTrustedIPs: a stored line passes as it is), the
// names (normalized in place), then the domain limits.
func (h *SystemSettingsHandler) checkTrustedLists(ctx context.Context, req *model.UpdateSystemSettingsRequest, cur *model.SystemSettings) (trustedSave, error) {
	if cur == nil {
		cur = &model.SystemSettings{}
	}
	if req.GlobalTrustedIPs != nil {
		if err := model.ValidateChangedTrustedIPs(*req.GlobalTrustedIPs, cur.GlobalTrustedIPs); err != nil {
			return trustedSave{}, err
		}
	}
	if req.GlobalTrustedHostnames == nil {
		return trustedSave{}, nil
	}
	if err := normalizeDNSNames("global_trusted_hostnames", req.GlobalTrustedHostnames); err != nil {
		return trustedSave{}, err
	}
	if err := checkScopeLimits(ctx, h.dnsEntries, model.DNSScopeKindTrusted, req.GlobalTrustedHostnames); err != nil {
		return trustedSave{}, err
	}
	return trustedSave{set: true, before: cur.GlobalTrustedHostnames}, nil
}

// trustedListsRefused answers a PUT whose global trusted list was refused
// (exceptionListRefusal), and any other error as a failed read.
func trustedListsRefused(c echo.Context, err error) error {
	if body, ok := exceptionListRefusal(err, "global_trusted_hostnames"); ok {
		return c.JSON(http.StatusBadRequest, body)
	}
	return directInternalError(c, err)
}

// finishTrustedSave runs once the row is saved and before the background
// worker starts: it hands the saved names to the DNS entry service and
// records their change (dns_entries_changed, scope trusted). Both run to
// the end when the client has left.
func (h *SystemSettingsHandler) finishTrustedSave(c echo.Context, save trustedSave, settings *model.SystemSettings) {
	if !save.set {
		return
	}
	ctx := c.Request().Context()
	syncExceptionNames(ctx, h.dnsEntries, model.DNSScopeKindTrusted, len(save.before) > 0, settings.GlobalTrustedHostnames)
	auditDNSNames(context.WithoutCancel(service.ContextWithAudit(ctx, c)), h.audit, model.DNSScopeKindTrusted, save.before, settings.GlobalTrustedHostnames)
}
