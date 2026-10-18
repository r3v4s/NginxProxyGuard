package handler

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type GeoHandler struct {
	geoRepo          *repository.GeoRepository
	globalGeoRepo    *repository.GlobalGeoRepository
	proxyHostRepo    *repository.ProxyHostRepository
	proxyHostService *service.ProxyHostService
	audit            *service.AuditService
	// dns is the DNS entry service (SetDNSEntries, #320). Without it the
	// priority allow domain names are stored and checked against no limit.
	dns dnsScopeSyncer
}

func NewGeoHandler(
	geoRepo *repository.GeoRepository,
	globalGeoRepo *repository.GlobalGeoRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *service.ProxyHostService,
	audit *service.AuditService,
) *GeoHandler {
	return &GeoHandler{
		geoRepo:          geoRepo,
		globalGeoRepo:    globalGeoRepo,
		proxyHostRepo:    proxyHostRepo,
		proxyHostService: proxyHostService,
		audit:            audit,
	}
}

// GetGlobal returns the singleton global geo default (#198).
func (h *GeoHandler) GetGlobal(c echo.Context) error {
	g, err := h.globalGeoRepo.GetGlobal(c.Request().Context())
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobal updates the global geo default and regenerates every inheriting
// host so the new default takes effect (#198).
func (h *GeoHandler) UpdateGlobal(c echo.Context) error {
	var req model.UpdateGlobalGeoRestrictionRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	if req.Mode != nil && *req.Mode != "whitelist" && *req.Mode != "blacklist" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Mode must be 'whitelist' or 'blacklist'"})
	}
	ctx := c.Request().Context()
	if err := normalizeDNSNames("allowed_hostnames", req.AllowedHostnames); err != nil {
		return geoRefused(c, err)
	}
	before := h.globalGeoBefore(ctx, req.AllowedIPs, req.AllowedHostnames != nil)
	if err := h.checkGeoLists(ctx, globalPriorityScope, req.Countries, req.AllowedIPs, req.AllowedHostnames, before); err != nil {
		return geoRefused(c, err)
	}

	g, err := h.globalGeoRepo.Upsert(ctx, &req)
	if err != nil {
		return directInternalError(c, err)
	}
	h.syncGeoNames(ctx, globalPriorityScope, before, g.AllowedHostnames)
	namesSent := req.AllowedHostnames != nil

	// Regenerate all hosts so inheriting hosts pick up the new default.
	if err := h.proxyHostService.SyncAllConfigs(ctx); err != nil {
		if reloadRefused(err) {
			h.auditGlobalUpdate(c, namesSent, before, g.AllowedHostnames)
		}
		if status, body, ok := reloadRejectedResponse(err); ok {
			return c.JSON(status, body)
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate configs: " + SafeErrorMessage(err)})
	}

	h.auditGlobalUpdate(c, namesSent, before, g.AllowedHostnames)

	return c.JSON(http.StatusOK, g)
}

// auditGlobalUpdate records a change to the global geo default and, when
// the save sent the names, a change of them (#320).
func (h *GeoHandler) auditGlobalUpdate(c echo.Context, namesSent bool, before geoBefore, names []string) {
	if h.audit != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.audit.LogGlobalGeoUpdate(auditCtx)
		if namesSent {
			auditDNSNames(auditCtx, h.audit, globalPriorityScope, before.names, names)
		}
	}
}

// GetByProxyHost returns geo restriction settings for a proxy host
func (h *GeoHandler) GetByProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")

	// Verify proxy host exists
	host, err := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	if err != nil {
		return directInternalError(c, err)
	}
	if host == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Proxy host not found"})
	}

	geo, err := h.geoRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return directInternalError(c, err)
	}
	if geo == nil {
		// Return default empty response
		return c.JSON(http.StatusOK, map[string]interface{}{
			"proxy_host_id": proxyHostID,
			"mode":          "blacklist",
			"countries":     []string{},
			"enabled":       false,

			"allowed_hostnames": []string{},
		})
	}

	return c.JSON(http.StatusOK, geo)
}

// SetForProxyHost creates or updates geo restriction settings
func (h *GeoHandler) SetForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")
	skipReload := c.QueryParam("skip_reload") == "true"

	// Verify proxy host exists
	host, err := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	if err != nil {
		return directInternalError(c, err)
	}
	if host == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Proxy host not found"})
	}

	var req model.CreateGeoRestrictionRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Mode != "whitelist" && req.Mode != "blacklist" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Mode must be 'whitelist' or 'blacklist'"})
	}
	ctx := c.Request().Context()
	if err := normalizeDNSNames("allowed_hostnames", req.AllowedHostnames); err != nil {
		return geoRefused(c, err)
	}
	scope := exceptionHostScope(model.DNSScopeKindPriority, host.ID)
	before := h.hostGeoBefore(ctx, host.ID, req.AllowedIPs, req.AllowedHostnames != nil)
	if err := h.checkGeoLists(ctx, scope, req.Countries, req.AllowedIPs, req.AllowedHostnames, before); err != nil {
		return geoRefused(c, err)
	}

	geo, err := h.geoRepo.Upsert(ctx, proxyHostID, &req)
	if err != nil {
		return directInternalError(c, err)
	}
	h.syncGeoNames(ctx, scope, before, geo.AllowedHostnames)
	audit := func() {
		h.auditHostGeo(c, hostDomain(host), scope, map[string]interface{}{"enabled": geo.Enabled, "mode": geo.Mode},
			req.AllowedHostnames != nil, before, geo.AllowedHostnames)
	}

	// Regenerate nginx config with geo restrictions (skip if requested)
	if !skipReload {
		if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
			if status, body, ok := reloadRejectedResponse(err); ok {
				audit()
				return c.JSON(status, body)
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + SafeErrorMessage(err)})
		}
	}
	audit()

	return c.JSON(http.StatusOK, geo)
}

// UpdateForProxyHost updates geo restriction settings
func (h *GeoHandler) UpdateForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")

	var req model.UpdateGeoRestrictionRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	ctx := c.Request().Context()
	if err := normalizeDNSNames("allowed_hostnames", req.AllowedHostnames); err != nil {
		return geoRefused(c, err)
	}
	before := h.hostGeoBefore(ctx, proxyHostID, req.AllowedIPs, req.AllowedHostnames != nil)
	if err := h.checkGeoLists(ctx, exceptionHostScope(model.DNSScopeKindPriority, proxyHostID), req.Countries, req.AllowedIPs, req.AllowedHostnames, before); err != nil {
		return geoRefused(c, err)
	}

	geo, err := h.geoRepo.Update(ctx, proxyHostID, &req)
	if err != nil {
		return directInternalError(c, err)
	}
	if geo == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Geo restriction not found"})
	}
	scope := exceptionHostScope(model.DNSScopeKindPriority, geo.ProxyHostID)
	h.syncGeoNames(ctx, scope, before, geo.AllowedHostnames)
	audit := func() {
		h.auditHostGeo(c, h.hostName(ctx, proxyHostID), scope, map[string]interface{}{"enabled": geo.Enabled, "mode": geo.Mode},
			req.AllowedHostnames != nil, before, geo.AllowedHostnames)
	}

	// Regenerate nginx config
	if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
		if status, body, ok := reloadRejectedResponse(err); ok {
			audit()
			return c.JSON(status, body)
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + SafeErrorMessage(err)})
	}
	audit()

	return c.JSON(http.StatusOK, geo)
}

// DeleteForProxyHost removes geo restriction settings
func (h *GeoHandler) DeleteForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")
	skipReload := c.QueryParam("skip_reload") == "true"
	ctx := c.Request().Context()
	before := h.hostGeoBefore(ctx, proxyHostID, nil, true)

	if err := h.geoRepo.Delete(ctx, proxyHostID); err != nil {
		return directInternalError(c, err)
	}
	// The row's names leave with it: their files are emptied before the skip.
	scope := exceptionHostScope(model.DNSScopeKindPriority, proxyHostID)
	h.syncGeoNames(ctx, scope, before, nil)
	audit := func() {
		h.auditHostGeo(c, h.hostName(ctx, proxyHostID), scope, map[string]interface{}{"action": "delete"}, true, before, nil)
	}

	// Regenerate nginx config without geo restrictions (skip if requested)
	if !skipReload {
		if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
			if status, body, ok := reloadRejectedResponse(err); ok {
				audit()
				return c.JSON(status, body)
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + SafeErrorMessage(err)})
		}
	}
	audit()

	return c.NoContent(http.StatusNoContent)
}

// GetCountryCodes returns the list of available country codes
func (h *GeoHandler) GetCountryCodes(c echo.Context) error {
	return c.JSON(http.StatusOK, model.CommonCountryCodes)
}

func (h *GeoHandler) regenerateHostConfig(c echo.Context, proxyHostID string) error {
	// Delegate to the service path: complete config data (fail-closed when a
	// security-relevant lookup errors), single-lock atomic write + nginx -t +
	// reload with rollback. The handler-local aggregation this replaced was
	// missing whole sections (URI block, cloud blocking, exploit rules,
	// global trusted IPs, filter subscriptions) and reloaded without rollback,
	// so a geo edit could silently strip those protections from the host.
	return h.proxyHostService.RegenerateConfigForHost(c.Request().Context(), proxyHostID)
}
