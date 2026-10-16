package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

// accessListDNSConfirmRequest is the body of POST
// /access-lists/:id/dns-confirm: a domain of the list and what the client
// showed of it.
type accessListDNSConfirmRequest struct {
	Hostname              string   `json:"hostname"`
	ExpectedAddresses     []string `json:"expected_addresses"`
	ExpectedCanonicalName string   `json:"expected_canonical_name,omitempty"`
}

// dnsConfirmError is the body of a refused confirm (400, 409). Observed is
// the domain's answer now, for observation_changed.
type dnsConfirmError struct {
	Error    string              `json:"error"`
	Code     string              `json:"code"`
	Field    string              `json:"field,omitempty"`
	Observed *dnsConfirmObserved `json:"observed,omitempty"`
}

type dnsConfirmObserved struct {
	Addresses     []string `json:"addresses"`
	CanonicalName *string  `json:"canonical_name"`
}

// dnsConfirmForbidden is the 403 of a confirm the caller may not make for
// every list that uses the domain.
type dnsConfirmForbidden struct {
	Error    string   `json:"error"`
	Required []string `json:"required"`
}

var errDNSEntriesUnavailable = errors.New("domain entries are not available")

// ConfirmDNS allows again a domain of this list that waits for
// review. The DNS service looks the name up again (at most 3 s) and
// publishes its own answer, and only when that is what the client showed: a
// value the client sends is never published. A domain has one state for all
// the lists that use it, so the caller needs the write permission of each of
// them.
func (h *AccessListHandler) ConfirmDNS(c echo.Context) error {
	ctx := c.Request().Context()
	var req accessListDNSConfirmRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	list, err := h.repo.GetByID(ctx, c.Param("id"))
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	name := model.NormalizeDNSName(req.Hostname)
	if !hasDNSName(list.Items, name) {
		return c.JSON(http.StatusBadRequest, dnsConfirmError{
			Error: "hostname: not a domain of this access list", Code: "not_in_list", Field: "hostname",
		})
	}
	if h.dns == nil {
		return internalError(c, "confirm access list domain", errDNSEntriesUnavailable)
	}
	refs, err := h.dns.References(ctx, name)
	if err != nil {
		return internalError(c, "read where a domain is used", err)
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
	// The audit records what was confirmed: the answer the server saw and
	// published (observed_addresses, observed_canonical_name). addresses is
	// empty while domain entries are switched off.
	canonical := ""
	if status.ObservedCanonicalName != nil {
		canonical = *status.ObservedCanonicalName
	}
	// Recorded before the outcome: the domain is published even when nginx
	// refuses the reload that applies it, as a list save is, and even when
	// the client left while nginx applied it.
	h.audit.LogDNSEntryConfirmed(service.ContextWithAudit(context.WithoutCancel(ctx), c), name, status.ObservedAddresses, canonical, dnsRefScopes(refs))
	if result.Outcome == string(nginx.ReloadRejected) {
		return internalError(c, "apply the confirmed domain to nginx", &nginx.ReloadRejectedError{Detail: result.Detail})
	}
	return c.JSON(http.StatusOK, dnsStatusViewFor(c).filter(status))
}

// dnsConfirmRefused answers a confirm the DNS service refused; nothing was
// published.
func dnsConfirmRefused(c echo.Context, err error) error {
	var changed *dnsentry.ObservationChangedError
	switch {
	case errors.Is(err, dnsentry.ErrNotInReview):
		return c.JSON(http.StatusBadRequest, dnsConfirmError{
			Error: "hostname: this domain does not wait for review", Code: "not_in_review", Field: "hostname",
		})
	case errors.Is(err, dnsentry.ErrLookupUnavailable):
		return c.JSON(http.StatusConflict, dnsConfirmError{
			Error: "the domain could not be looked up just now, so nothing was allowed; try again", Code: "lookup_unavailable",
		})
	case errors.As(err, &changed):
		observed := &dnsConfirmObserved{Addresses: changed.Observed}
		if observed.Addresses == nil {
			observed.Addresses = []string{}
		}
		if changed.Canonical != "" {
			canonical := changed.Canonical
			observed.CanonicalName = &canonical
		}
		return c.JSON(http.StatusConflict, dnsConfirmError{
			Error:    "the domain answers differently from what you confirmed, so nothing was allowed; check the new answer",
			Code:     "observation_changed",
			Observed: observed,
		})
	}
	return internalError(c, "confirm access list domain", err)
}

// dnsRefScopes returns the scopes of refs, sorted, each once.
func dnsRefScopes(refs []model.DNSReference) []string {
	seen := map[string]bool{}
	var scopes []string
	for _, ref := range refs {
		if !seen[ref.Scope] {
			seen[ref.Scope] = true
			scopes = append(scopes, ref.Scope)
		}
	}
	sort.Strings(scopes)
	return scopes
}
