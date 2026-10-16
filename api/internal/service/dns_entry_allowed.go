package service

import (
	"slices"
	"time"
)

// The record of what nginx allowed through the domain files, and when. The
// log collector reads a line seconds after its request, so the fail2ban gate
// judges the line by the files nginx ran when the request came in, not by
// the files of the moment it reads the line: a partner's 403s from just
// before its new address was published must not count once it is.
const (
	// dnsAllowSlack: old workers may serve requests with the previous files
	// for a while after nginx takes a reload, so an address counts as
	// allowed only from this long after the reload that added it.
	dnsAllowSlack = 5 * time.Second
	// dnsAllowMemory is how long the record keeps a stretch that ended.
	dnsAllowMemory = 10 * time.Minute
	// dnsAllowSpansMax is how many stretches the record keeps per address,
	// the newest.
	dnsAllowSpansMax = 8
)

// dnsAllowSpan is a stretch of time nginx allowed an address through a
// scope's files: from the taken reload that held it first to the taken
// reload that dropped it. from is zero when nginx may have allowed it since
// before this process saw a reload taken; until is zero while nginx allows it.
type dnsAllowSpan struct {
	from, until time.Time
}

// seedAllowedLocked starts the record from what the files hold or held
// (the disk table and the revocations) the first time the rows and files
// are in line: nginx may run any of it, since before this process started.
// A record a reload filled before that is left as it is. Caller holds
// diskMu.
func (s *DNSEntryService) seedAllowedLocked() {
	if len(s.allowed) > 0 {
		return
	}
	seed := func(scope string, addrs []string) {
		for _, a := range addrs {
			if s.allowed[scope] == nil {
				s.allowed[scope] = make(map[string][]dnsAllowSpan)
			}
			s.allowed[scope][a] = []dnsAllowSpan{{}}
		}
	}
	for _, e := range s.disk {
		seed(e.Scope, e.Addrs)
	}
	for _, e := range s.pendingRevoke {
		seed(e.Scope, e.Addrs)
	}
}

// recordAllowedLocked moves the record to the files t describes, which nginx
// took at now: an address t holds that nginx did not allow starts a stretch,
// and one nginx allowed that t no longer holds ends its stretch. Stretches
// that ended more than dnsAllowMemory ago are dropped, and at most
// dnsAllowSpansMax are kept per address. Caller holds diskMu.
func (s *DNSEntryService) recordAllowedLocked(t *dnsReloadToken, now time.Time) {
	held := make(map[string]map[string]bool)
	for _, e := range t.segs {
		for _, a := range e.Addrs {
			if held[e.Scope] == nil {
				held[e.Scope] = make(map[string]bool)
			}
			held[e.Scope][a] = true
		}
	}
	for scope, addrs := range s.allowed {
		for a, spans := range addrs {
			if n := len(spans); n > 0 && spans[n-1].until.IsZero() && !held[scope][a] {
				spans[n-1].until = now
			}
		}
	}
	for scope, addrs := range held {
		if s.allowed[scope] == nil {
			s.allowed[scope] = make(map[string][]dnsAllowSpan)
		}
		for a := range addrs {
			spans := s.allowed[scope][a]
			if n := len(spans); n == 0 || !spans[n-1].until.IsZero() {
				s.allowed[scope][a] = append(spans, dnsAllowSpan{from: now})
			}
		}
	}
	forget := now.Add(-dnsAllowMemory)
	for scope, addrs := range s.allowed {
		for a, spans := range addrs {
			spans = slices.DeleteFunc(spans, func(sp dnsAllowSpan) bool {
				return !sp.until.IsZero() && sp.until.Before(forget)
			})
			if len(spans) > dnsAllowSpansMax {
				spans = spans[len(spans)-dnsAllowSpansMax:]
			}
			if len(spans) == 0 {
				delete(addrs, a)
			} else {
				addrs[a] = spans
			}
		}
		if len(addrs) == 0 {
			delete(s.allowed, scope)
		}
	}
}

// dnsAllowedAt reports whether nginx allowed addr through a file of scope
// when a request came in at at: a reload nginx took more than dnsAllowSlack
// before at held it, and no reload nginx took before at had dropped it. An
// address the record does not hold is allowed while its removal waits for
// nginx: a reload whose acceptance was not seen may have added it. The
// fail2ban gate asks this from the log goroutine: memory only.
func (s *DNSEntryService) dnsAllowedAt(scope, addr string, at time.Time) bool {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	if spans, ok := s.allowed[scope][addr]; ok {
		for _, sp := range spans {
			started := sp.from.IsZero() || sp.from.Before(at.Add(-dnsAllowSlack))
			if started && (sp.until.IsZero() || at.Before(sp.until)) {
				return true
			}
		}
		return false
	}
	for _, e := range s.pendingRevoke {
		if e.Scope == scope && slices.Contains(e.Addrs, addr) {
			return true
		}
	}
	return false
}
