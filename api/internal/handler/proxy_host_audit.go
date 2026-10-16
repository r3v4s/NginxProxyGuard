package handler

import (
	"context"
	"log"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// accessListReader reads an access list with its rules
// (repository.AccessListRepository).
type accessListReader interface {
	GetByID(ctx context.Context, id string) (*model.AccessList, error)
}

// SetAccessLists lets the update audit name the domains of an access list a
// host is newly linked to: linking a host to such a list lets
// whoever controls those domains' DNS reach it.
func (h *ProxyHostHandler) SetAccessLists(r accessListReader) {
	h.accessLists = r
}

// auditUpdate records the update of host id, which was existingHost before
// req and is host after it.
func (h *ProxyHostHandler) auditUpdate(c echo.Context, id string, existingHost, host *model.ProxyHost, req *model.UpdateProxyHostRequest) {
	if existingHost == nil {
		return
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	// Check if it's just an enable/disable toggle
	if req.Enabled != nil && existingHost.Enabled != *req.Enabled {
		h.audit.LogProxyHostToggle(auditCtx, host.DomainNames, *req.Enabled)
	} else {
		changes := map[string]interface{}{
			"id": id,
		}
		if names := linkedAccessListDNSNames(auditCtx, h.accessLists, existingHost, host); len(names) > 0 {
			changes["access_list_dns_names"] = names
		}
		h.audit.LogProxyHostUpdate(auditCtx, host.DomainNames, changes)
	}
}

// linkedAccessListDNSNames returns the domains of the access list after
// links the host to, when this update changed the link and that list has
// domains. It reads the list only when the link changed, so an update that
// leaves the link alone costs no query.
func linkedAccessListDNSNames(ctx context.Context, lists accessListReader, before, after *model.ProxyHost) []string {
	id := linkedAccessListID(after)
	if lists == nil || id == "" || id == linkedAccessListID(before) {
		return nil
	}
	list, err := lists.GetByID(ctx, id)
	if err != nil {
		log.Printf("[ProxyHost] read access list %s for the update audit: %v", id, err)
		return nil
	}
	if list == nil {
		return nil
	}
	return accessListDNSNames(list.Items)
}

// linkedAccessListID returns the access list host uses, "" for none.
func linkedAccessListID(host *model.ProxyHost) string {
	if host == nil || host.AccessListID == nil {
		return ""
	}
	return *host.AccessListID
}
