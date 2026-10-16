package dnsentry

import (
	"sort"

	"nginx-proxy-guard/internal/model"
)

// FamilyObs is one address family's outcome after the address
// policy ran.
type FamilyObs struct {
	Outcome string // "ok" | "notfound" | "transient" | "rejected"
	// Code: transient -> timeout|servfail|refused|network; notfound ->
	// not_found; rejected -> reserved|loopback|private|link_local|multicast|
	// cdn|too_many (the first refused address's code).
	Code  string
	Addrs []string // "ok" only: policy-passed addresses as netip.Addr.String(), sorted, unique, non-empty
}

// Observation is one resolution of one name, through the policy.
type Observation struct {
	V4, V6    FamilyObs
	CNAMEOK   bool   // both CNAME chain walks succeeded and ended at the same name
	Canonical string // the agreed canonical name when CNAMEOK, else ""
}

// ObserveNotes are what Observe saw besides the outcome, for the warnings: the
// policy dropped part of an answer (partial_rejected), or a kept address is in
// 100.64.0.0/10 (cgnat).
type ObserveNotes struct {
	PartialRejected bool
	CGNAT           bool
}

// Observe puts an Answer through the address policy, family by family. An
// "ok" family's addresses are unmapped and deduplicated, then:
//   - more than maxPerFamily: the whole family is refused as "too_many", before
//     the policy looks at any of them (a large answer is not partly trusted);
//   - each address the policy refuses is dropped (an address of the other
//     family, such as a mapped IPv4 address in an AAAA answer, is "reserved");
//   - nothing left: the family is "rejected" with the first refused address's
//     code; something left: "ok" with what is left, and PartialRejected when
//     something was dropped.
//
// Refused addresses are not kept anywhere, only the code (they may describe a
// private network). "notfound" and "transient" pass through with their codes.
// p nil is the default policy; maxPerFamily below 1 is the default limit.
func Observe(a Answer, p *model.AddressPolicy, maxPerFamily int) (Observation, ObserveNotes) {
	if maxPerFamily < 1 {
		maxPerFamily = model.DefaultDNSEntrySettings().MaxAddressesPerFamily
	}
	var notes ObserveNotes
	o := Observation{
		V4: observeFamily(a.V4, true, p, maxPerFamily, &notes),
		V6: observeFamily(a.V6, false, p, maxPerFamily, &notes),
	}
	before, after := NormalizeCanonical(a.CNAMEBefore), NormalizeCanonical(a.CNAMEAfter)
	if before != "" && before == after {
		o.CNAMEOK, o.Canonical = true, before
	}
	return o, notes
}

func observeFamily(f FamilyAnswer, ipv4 bool, p *model.AddressPolicy, maxPerFamily int, notes *ObserveNotes) FamilyObs {
	switch f.Outcome {
	case outcomeOK:
	case outcomeNotFound:
		return FamilyObs{Outcome: outcomeNotFound, Code: codeNotFound}
	default: // transient, or an outcome this version does not know
		code := f.Code
		if code == "" {
			code = codeNetwork
		}
		return FamilyObs{Outcome: outcomeTransient, Code: code}
	}
	addrs := unmapSorted(f.Addrs)
	if len(addrs) == 0 {
		return FamilyObs{Outcome: outcomeNotFound, Code: codeNotFound}
	}
	if len(addrs) > maxPerFamily {
		return FamilyObs{Outcome: outcomeRejected, Code: codeTooMany}
	}
	var kept []string
	first := ""
	for _, a := range addrs {
		code := codeReserved
		if a.Is4() == ipv4 {
			code = p.Classify(a)
		}
		if code != "" {
			if first == "" {
				first = code
			}
			continue
		}
		if model.IsCGNAT(a) {
			notes.CGNAT = true
		}
		kept = append(kept, a.String())
	}
	if len(kept) == 0 {
		return FamilyObs{Outcome: outcomeRejected, Code: first}
	}
	if len(kept) < len(addrs) {
		notes.PartialRejected = true
	}
	sort.Strings(kept)
	return FamilyObs{Outcome: outcomeOK, Addrs: kept}
}
