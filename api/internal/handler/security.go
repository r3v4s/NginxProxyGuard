package handler

import (
	"nginx-proxy-guard/internal/service"
)

type SecurityHandler struct {
	securityService *service.SecurityService
	audit           *service.AuditService
	// dnsStatus is the DNS entry service (SetDNSEntries, #320) as the URI
	// block and rate limit GETs read it: the state of their domains.
	// Without it they show none.
	dnsStatus dnsStatusReader
}

func NewSecurityHandler(
	securityService *service.SecurityService,
	audit *service.AuditService,
) *SecurityHandler {
	return &SecurityHandler{
		securityService: securityService,
		audit:           audit,
	}
}

// SetDNSEntries wires the DNS entry service for the GETs of the URI block
// and rate limit exceptions: they show their domains' state (#320). The
// saves reach it through the security service.
func (h *SecurityHandler) SetDNSEntries(svc *service.DNSEntryService) {
	if svc != nil {
		h.dnsStatus = svc
	}
}
