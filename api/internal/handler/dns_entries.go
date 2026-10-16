package handler

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

// The settings screen's domain entries (#320): an
// overview of every name with its state and uses, and "apply now". The
// routes need settings:read and settings:write (middleware/permissions.go).
// What the overview shows of each name also depends on the caller's other
// permissions: a use is named only to a caller who may read its
// list, and the parts dnsStatusView guards are left out.

// dnsEntryOverviewer is what DNSEntryHandler needs of
// service.DNSEntryService.
type dnsEntryOverviewer interface {
	Overview(ctx context.Context, canRead func(scope string) bool, view model.DNSStatusView) (model.DNSEntryOverview, error)
	ApplyNow(ctx context.Context) nginx.DNSApplyResult
}

// dnsApplyAuditor records "apply now" (service.AuditService).
type dnsApplyAuditor interface {
	LogDNSEntryApplyRequested(ctx context.Context, outcome string) error
}

// DNSEntryHandler serves /dns-entries.
type DNSEntryHandler struct {
	svc   dnsEntryOverviewer
	audit dnsApplyAuditor
}

// NewDNSEntryHandler builds the handler. Without a DNS entry service both
// routes answer 500; without an audit service nothing is recorded.
func NewDNSEntryHandler(svc *service.DNSEntryService, audit *service.AuditService) *DNSEntryHandler {
	h := &DNSEntryHandler{}
	if svc != nil {
		h.svc = svc
	}
	if audit != nil {
		h.audit = audit
	}
	return h
}

// Overview is GET /dns-entries: every name in use, and every name nginx may
// still allow after it was dropped, with its state and uses; the apply
// state; the effective settings and the environment switches.
func (h *DNSEntryHandler) Overview(c echo.Context) error {
	if h.svc == nil {
		return internalError(c, "read the domain entries", errDNSEntriesUnavailable)
	}
	view := dnsStatusViewFor(c)
	ov, err := h.svc.Overview(c.Request().Context(), dnsScopeReaderFor(c), view.serviceView())
	if err != nil {
		return internalError(c, "read the domain entries", err)
	}
	return c.JSON(http.StatusOK, filterDNSEntryOverview(ov, view))
}

// ApplyNow is POST /dns-entries/apply, "apply now": the DNS
// entry service puts the files in line with the database and runs nginx -t
// and a reload at once, whatever its retry schedule says. It changes no
// trust. The outcome is audited first. A reload the running nginx refused
// answers 409 nginx_reload_rejected, as a save does; every other outcome
// answers 200 with what happened.
func (h *DNSEntryHandler) ApplyNow(c echo.Context) error {
	if h.svc == nil {
		return internalError(c, "apply the domain entries", errDNSEntriesUnavailable)
	}
	ctx := c.Request().Context()
	res := h.svc.ApplyNow(ctx)
	if h.audit != nil {
		// Also when the client left meanwhile: nginx may have taken the files.
		h.audit.LogDNSEntryApplyRequested(service.ContextWithAudit(context.WithoutCancel(ctx), c), res.Outcome)
	}
	if res.Outcome == string(nginx.ReloadRejected) {
		return internalError(c, "apply the domain entries to nginx", &nginx.ReloadRejectedError{Detail: res.Detail})
	}
	return c.JSON(http.StatusOK, dnsApplyResponseOf(res, authMiddleware.HasPermissionFromContext(c, permProxyRead)))
}

// dnsScopeReaderFor answers for one request, asking each permission once,
// whether the caller may read a use in scope: the overview asks about every
// use of every name, and each question reads the caller's role from the
// database. Overview calls it from the request's goroutine only.
func dnsScopeReaderFor(c echo.Context) func(scope string) bool {
	held := map[string]bool{}
	return func(scope string) bool {
		need := dnsScopeReadPermission(scope)
		if need == "" {
			return false
		}
		ok, asked := held[need]
		if !asked {
			ok = authMiddleware.HasPermissionFromContext(c, need)
			held[need] = ok
		}
		return ok
	}
}

// filterDNSEntryOverview returns ov as view may see it: every name's state
// through view.filter, as the access list responses do. The apply state is
// left as the service gave it: the service hides its blocking file and
// nginx's message, which names that file, from a view without proxy:read,
// and that is the one place that does. It does not change ov's
// slices.
func filterDNSEntryOverview(ov model.DNSEntryOverview, view dnsStatusView) model.DNSEntryOverview {
	entries := make([]model.DNSEntryOverviewEntry, len(ov.Entries))
	for i, e := range ov.Entries {
		e.DNSEntryStatus = view.filter(e.DNSEntryStatus)
		entries[i] = e
	}
	ov.Entries = entries
	return ov
}

// dnsApplyResponseOf is the 200 body of "apply now". The blocking file and
// nginx's message, which names the same file, need proxy:read; the handler
// builds this body, so it hides them here.
func dnsApplyResponseOf(res nginx.DNSApplyResult, proxyRead bool) model.DNSApplyResponse {
	out := model.DNSApplyResponse{Outcome: res.Outcome}
	if proxyRead {
		out.Detail = dnsOptionalString(res.Detail)
		out.BlockingFile = dnsOptionalString(res.BlockingFile)
	}
	return out
}

// dnsOptionalString is s, or nil when s is empty.
func dnsOptionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
