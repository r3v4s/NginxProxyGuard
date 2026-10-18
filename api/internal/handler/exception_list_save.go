package handler

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// Saves of the four exception lists (#320): URI block exceptions, priority
// allow, rate limit exceptions and the global trusted list. Each save
// checks its domain names (400 naming the entry), then the domain limits,
// writes, hands the saved names to the DNS entry service before nginx is
// regenerated (a removed name's file is empty before the save answers),
// and records a change of the names (dns_entries_changed).

// dnsScopeSyncer is what an exception list save needs of
// service.DNSEntryService: the limits before the save, and the hand-over of
// the saved names before nginx is regenerated.
type dnsScopeSyncer interface {
	ValidateScopeNames(ctx context.Context, scope string, names []string) error
	SyncScope(ctx context.Context, scope string, names []string) error
}

// exceptionHostScope is the scope of a host's own list of kind (uri, prio,
// rl). A scope holds the id as PostgreSQL prints it, in lower case.
func exceptionHostScope(kind, hostID string) string {
	return kind + ":" + strings.ToLower(hostID)
}

// normalizeDNSNames puts the domain names of a request field into the form
// they are stored in (model.ValidateDNSNameList: normalized, a repeat
// dropped), in place. names is nil when the request left the field out. A
// refused name is a *model.DNSNameFieldError naming field[i].
func normalizeDNSNames(field string, names *[]string) error {
	if names == nil {
		return nil
	}
	valid, err := model.ValidateDNSNameList(field, *names)
	if err != nil {
		return err
	}
	*names = valid
	return nil
}

// checkScopeLimits refuses (*service.DNSLimitError) names that would raise a
// count above its limit. names is the request's field; nil keeps the stored
// names, which raises nothing.
func checkScopeLimits(ctx context.Context, dns dnsScopeSyncer, scope string, names *[]string) error {
	if dns == nil || names == nil || len(*names) == 0 {
		return nil
	}
	return dns.ValidateScopeNames(ctx, scope, *names)
}

// exceptionListRefusal is the 400 body of an exception list save refused
// before it wrote: {error, field, code} for a domain name
// (*model.DNSNameFieldError, the name rule's code), an IP field entry
// (*model.IPEntryError) and the domain limits (*service.DNSLimitError, code
// limit; the per-list limit names nameField, the list's name field), and
// {error} for other invalid input. ok is false for any other error, which
// the caller answers as before.
func exceptionListRefusal(err error, nameField string) (body map[string]string, ok bool) {
	var name *model.DNSNameFieldError
	var entry *model.IPEntryError
	var limit *service.DNSLimitError
	switch {
	case errors.As(err, &name):
		return accessListRuleError(trimInvalidInputPrefix(name), name.Field, name.Code), true
	case errors.As(err, &entry):
		return accessListRuleError(entry.Message, entry.Field, entry.Code), true
	case errors.As(err, &limit):
		l := *limit
		if l.Field == "items" {
			l.Field = nameField
		}
		return accessListRuleError(l.Error(), l.Field, "limit"), true
	case errors.Is(err, model.ErrInvalidInput):
		return map[string]string{"error": scrubbedClientText(trimInvalidInputPrefix(err))}, true
	}
	return nil, false
}

// exceptionSyncTimeout bounds a save's hand-over of its names: up to 3 s of
// lookups, one transaction and the files.
const exceptionSyncTimeout = 30 * time.Second

// syncExceptionNames hands a list's saved names to the DNS entry service
// once the list is saved and before nginx is regenerated. It runs on a
// context of its own, so a client that leaves does not cut it short. A
// failure is logged and does not fail the save: the next DNS check does the
// same from the database. had says the list may have had names before the
// save; a list without names before and after leaves the service alone.
func syncExceptionNames(ctx context.Context, dns dnsScopeSyncer, scope string, had bool, names []string) {
	if dns == nil || (!had && len(names) == 0) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exceptionSyncTimeout)
	defer cancel()
	if err := dns.SyncScope(ctx, scope, names); err != nil {
		log.Printf("[DNSEntries] WARN: the domains of %s are saved, but their include files were not updated (%v); the next DNS check updates them", scope, err)
	}
}

// dnsNamesDiff returns the names after holds and before does not (added),
// and the other way round (removed), each in its list's order.
func dnsNamesDiff(before, after []string) (added, removed []string) {
	for _, n := range after {
		if !slices.Contains(before, n) {
			added = append(added, n)
		}
	}
	for _, n := range before {
		if !slices.Contains(after, n) {
			removed = append(removed, n)
		}
	}
	return added, removed
}

// auditDNSNames records, in auditCtx (the request's user), that a save
// changed scope's names from before to after (dns_entries_changed), and
// nothing when it did not. audit may be nil.
func auditDNSNames(auditCtx context.Context, audit *service.AuditService, scope string, before, after []string) {
	added, removed := dnsNamesDiff(before, after)
	if audit == nil || (len(added) == 0 && len(removed) == 0) {
		return
	}
	audit.LogDNSEntriesChanged(auditCtx, scope, added, removed)
}
