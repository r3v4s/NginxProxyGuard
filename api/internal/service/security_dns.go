package service

import (
	"context"
	"log"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Domain names (#320) in the exception lists the security service saves:
// URI block exceptions (uri:<host id>, uri:global) and rate limit
// exceptions (rl:<host id>, rl:global). The handlers check the names; a save
// checks them against the limits before it writes, and hands them to the DNS
// entry service after it wrote and before nginx is regenerated.

// dnsScopeSyncer is what an exception list save needs of DNSEntryService.
type dnsScopeSyncer interface {
	ValidateScopeNames(ctx context.Context, scope string, names []string) error
	SyncScope(ctx context.Context, scope string, names []string) error
}

// SetDNSEntries wires the DNS entry service. Without it the names are
// stored and checked against no limit, and the next DNS check writes their
// files.
func (s *SecurityService) SetDNSEntries(svc dnsScopeSyncer) {
	if dnsSyncerMissing(svc) {
		return
	}
	s.dns = svc
}

// dnsSyncerMissing reports whether svc is no service: nil, or a nil
// *DNSEntryService, which as an interface is not nil.
func dnsSyncerMissing(svc dnsScopeSyncer) bool {
	d, ok := svc.(*DNSEntryService)
	return svc == nil || (ok && d == nil)
}

// hostDNSScope is the scope of a host's own list of kind (uri, prio, rl). A
// scope holds the id as PostgreSQL prints it, in lower case.
func hostDNSScope(kind, hostID string) string {
	return kind + ":" + strings.ToLower(hostID)
}

// checkDNSLimits refuses (*DNSLimitError) a save whose names would raise a
// count above its limit. names is the request's field: nil keeps the stored
// names, which raises nothing.
func checkDNSLimits(ctx context.Context, dns dnsScopeSyncer, scope string, names *[]string) error {
	if dns == nil || names == nil || len(*names) == 0 {
		return nil
	}
	return dns.ValidateScopeNames(ctx, scope, *names)
}

// dnsSyncTimeout bounds a save's hand-over of its names: up to 3 s of
// lookups, one transaction and the files.
const dnsSyncTimeout = 30 * time.Second

// syncDNSScope hands a list's names to the DNS entry service once the list
// is saved and before nginx is regenerated: a name taken out has an empty
// file before the save answers, and a new one its first answer. It runs on a
// context of its own, so a client that leaves does not cut it short. A
// failure is logged and does not fail the save: the next DNS check does the
// same from the database. had says the list may have had names before the
// save; a list without names before and after leaves the service alone.
func syncDNSScope(ctx context.Context, dns dnsScopeSyncer, scope string, had bool, names []string) {
	if dns == nil || (!had && len(names) == 0) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsSyncTimeout)
	defer cancel()
	if err := dns.SyncScope(ctx, scope, names); err != nil {
		log.Printf("[DNSEntries] WARN: the domains of %s are saved, but their include files were not updated (%v); the next DNS check updates them", scope, err)
	}
}

// hadDNSNames reports whether a list read before a save held names. A read
// that failed counts as names, so the save hands the list over all the same.
// A save that leaves the names out reads nothing: it keeps them, so the
// saved row holds the stored names.
func hadDNSNames(names []string, err error) bool {
	if err != nil {
		log.Printf("[DNSEntries] WARN: could not read a list's domains before saving it (%v); handing it to the DNS entry service all the same", err)
		return true
	}
	return len(names) > 0
}

// uriBlockHadNames reports whether the host's URI block holds domain names
// (hadDNSNames). It reads nothing without the DNS entry service.
func (s *SecurityService) uriBlockHadNames(ctx context.Context, proxyHostID string) bool {
	if s.dns == nil {
		return false
	}
	ub, err := s.uriBlockRepo.GetByProxyHostID(ctx, proxyHostID)
	var names []string
	if ub != nil {
		names = ub.ExceptionHostnames
	}
	return hadDNSNames(names, err)
}

// globalURIBlockHadNames is uriBlockHadNames for the global URI block.
func (s *SecurityService) globalURIBlockHadNames(ctx context.Context) bool {
	if s.dns == nil {
		return false
	}
	block, err := s.uriBlockRepo.GetGlobalURIBlock(ctx)
	var names []string
	if block != nil {
		names = block.ExceptionHostnames
	}
	return hadDNSNames(names, err)
}

// rateLimitHadNames is uriBlockHadNames for the host's rate limit.
func (s *SecurityService) rateLimitHadNames(ctx context.Context, proxyHostID string) bool {
	if s.dns == nil {
		return false
	}
	rl, err := s.rateLimitRepo.GetByProxyHostID(ctx, proxyHostID)
	var names []string
	if rl != nil {
		names = rl.WhitelistHostnames
	}
	return hadDNSNames(names, err)
}

// globalRateLimitHadNames is uriBlockHadNames for the global rate limit.
func (s *SecurityService) globalRateLimitHadNames(ctx context.Context) bool {
	if s.dns == nil || s.globalRateLimitRepo == nil {
		return false
	}
	g, err := s.globalRateLimitRepo.GetGlobal(ctx)
	var names []string
	if g != nil {
		names = g.WhitelistHostnames
	}
	return hadDNSNames(names, err)
}

// uriBlockDNSScope and rateLimitDNSScope are the scopes of a host's URI
// block and rate limit exceptions.
func uriBlockDNSScope(proxyHostID string) string {
	return hostDNSScope(model.DNSScopeKindURIBlock, proxyHostID)
}

func rateLimitDNSScope(proxyHostID string) string {
	return hostDNSScope(model.DNSScopeKindRateLimit, proxyHostID)
}

// The global lists' scopes.
const (
	globalURIBlockDNSScope  = model.DNSScopeKindURIBlock + ":global"
	globalRateLimitDNSScope = model.DNSScopeKindRateLimit + ":global"
)
