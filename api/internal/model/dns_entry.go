package model

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Domain entries (#320). An operator may put a domain name where a list
// takes addresses. NPG resolves it on a schedule and writes the addresses it
// accepted into one include file per (scope, name) that nginx reads; the
// rendered config holds only the file's path. This file holds the name rules,
// the scope grammar, the state row and the API shapes. Behaviour lives in
// internal/dnsentry and the DNS entry service.

// Scope kinds. A scope is one use of a name: an access list, or a host's or
// the global copy of an exception list. Only access lists use them so far.
const (
	DNSScopeKindAccessList = "acl"     // "acl:<access_list_id>"
	DNSScopeKindURIBlock   = "uri"     // "uri:<proxy_host_id>" or "uri:global"
	DNSScopeKindPriority   = "prio"    // "prio:<proxy_host_id>" or "prio:global"
	DNSScopeKindRateLimit  = "rl"      // "rl:<proxy_host_id>" or "rl:global"
	DNSScopeKindTrusted    = "trusted" // "trusted"
)

// dnsScopeOwner is a UUID as PostgreSQL prints one: lower case, 8-4-4-4-12.
// A scope is hashed into a file name, so an owner has exactly one spelling.
var dnsScopeOwner = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// AccessListDNSScope returns the scope of an access list's domain rows.
func AccessListDNSScope(listID string) string {
	return DNSScopeKindAccessList + ":" + listID
}

// ParseDNSScope splits a scope into its kind and owner. Only the canonical
// spellings parse: "acl:<uuid>"; "uri:", "prio:" or "rl:" followed by a uuid
// or "global"; and "trusted" (owner ""). Anything else, an upper-case uuid or
// surrounding space included, gives ok=false.
func ParseDNSScope(scope string) (kind, owner string, ok bool) {
	if scope == DNSScopeKindTrusted {
		return DNSScopeKindTrusted, "", true
	}
	kind, owner, found := strings.Cut(scope, ":")
	if !found {
		return "", "", false
	}
	switch kind {
	case DNSScopeKindAccessList:
		if dnsScopeOwner.MatchString(owner) {
			return kind, owner, true
		}
	case DNSScopeKindURIBlock, DNSScopeKindPriority, DNSScopeKindRateLimit:
		if owner == "global" || dnsScopeOwner.MatchString(owner) {
			return kind, owner, true
		}
	}
	return "", "", false
}

// NormalizeDNSName returns s as a domain name is stored: without surrounding
// space, with ASCII letters in lower case, and without one trailing dot
// ("Partner.Example.COM." becomes "partner.example.com"). Only ASCII letters
// are lowered, so a non-ASCII letter is never turned into an ASCII one (the
// Kelvin sign U+212A lowers to "k" with strings.ToLower) and
// ValidateDNSName still refuses it. It does not check the name.
func NormalizeDNSName(s string) string {
	b := []byte(strings.TrimSpace(s))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return strings.TrimSuffix(string(b), ".")
}

// Codes of DNSNameError. The API returns them as "code" next to the English
// sentence, and the UI words its own message from them.
const (
	dnsNameEmpty          = "empty"
	dnsNameTooLong        = "too_long"
	dnsNameLabel          = "label"
	dnsNameHyphen         = "hyphen"
	dnsNameSingleLabel    = "single_label"
	dnsNameTLD            = "tld"
	dnsNameLooksLikeIP    = "looks_like_ip"
	dnsNameWildcard       = "wildcard"
	dnsNameUnderscore     = "underscore"
	dnsNameURLOrPort      = "url_or_port"
	dnsNameWhitespace     = "whitespace"
	dnsNameNonASCII       = "non_ascii"
	dnsNameInternalSuffix = "internal_suffix"
)

var dnsNameSentences = map[string]string{
	dnsNameEmpty:          "a domain name is required",
	dnsNameTooLong:        "a domain name can be at most 253 characters long",
	dnsNameLabel:          "each part of a domain name between the dots must be 1 to 63 letters, digits or hyphens",
	dnsNameHyphen:         "a part of a domain name must not start or end with a hyphen",
	dnsNameSingleLabel:    "a domain name needs at least one dot; a single name such as a container name cannot be used",
	dnsNameTLD:            "the last part of a domain name must be letters, or an xn-- name",
	dnsNameLooksLikeIP:    "this is an IP address, a CIDR range or \"all\" (or a mistyped one), not a domain name",
	dnsNameWildcard:       "a domain name must not contain a wildcard (*)",
	dnsNameUnderscore:     "a domain name must not contain an underscore (_)",
	dnsNameURLOrPort:      "enter the domain name only, without a scheme, port, path or user name",
	dnsNameWhitespace:     "a domain name must not contain spaces, line breaks or control characters",
	dnsNameNonASCII:       "a domain name must be plain ASCII; write an internationalized name in its xn-- form",
	dnsNameInternalSuffix: "a name under a local suffix such as .local, .lan, .internal or .home.arpa only resolves inside a network and cannot be used",
}

// DNSNameError is why ValidateDNSName refused a name. Code is one of
// "empty", "too_long", "label", "hyphen", "single_label", "tld",
// "looks_like_ip", "wildcard", "underscore", "url_or_port", "whitespace",
// "non_ascii" and "internal_suffix". Name is the name as it was checked.
type DNSNameError struct {
	Code string
	Name string
}

// Error returns one English sentence for the code. It leaves the name out:
// callers put the field path in front ("items[2].address: ...") and log the
// name themselves.
func (e *DNSNameError) Error() string {
	if s, ok := dnsNameSentences[e.Code]; ok {
		return s
	}
	return "not a usable domain name"
}

// IsDNSNameError returns the *DNSNameError in err's chain.
func IsDNSNameError(err error) (*DNSNameError, bool) {
	var e *DNSNameError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// dnsInternalSuffixes only resolve inside a network (mDNS, home routers,
// split DNS) or never resolve. A name that is one of them or ends in one is
// refused: its answer is a private address, or whatever the local resolver
// says. ".example" stays allowed for tests ("partner.e2e.example").
var dnsInternalSuffixes = []string{
	"localhost", "local", "localdomain", "internal", "lan", "home", "home.arpa",
	"arpa", "invalid", "test", "onion", "corp", "intranet", "private",
}

// ValidateDNSName checks a name NormalizeDNSName has already normalized and
// returns a *DNSNameError for the first rule it breaks, in this order:
//
//  1. empty
//  2. looks_like_ip: an IP address, a CIDR range, "all", digits and dots only
//     ("203.0.113.300"), or a last label of digits only. It comes first so an
//     address typed as a name is reported as an address.
//  3. whitespace: a space, a line break or another control character
//  4. non_ascii: any byte outside ASCII (the UI sends the xn-- form)
//  5. wildcard: "*"
//  6. underscore: "_"
//  7. url_or_port: one of : / ? # @ [ ] \
//  8. too_long: more than 253 characters
//  9. label, hyphen: each label is 1 to 63 of a-z, 0-9 and "-", and does
//     not start or end with "-" (an upper-case letter is a label error:
//     the name was not normalized)
//  10. single_label: no dot
//  11. tld: the last label is neither letters only nor an xn-- label
//  12. internal_suffix: the name is, or ends in, one of dnsInternalSuffixes
//
// Every name it accepts matches ^[a-z0-9.-]{1,253}$, the CHECK on
// access_list_items.hostname and dns_entry_states.hostname, so storing an
// accepted name never fails on the CHECK.
func ValidateDNSName(name string) error {
	fail := func(code string) error { return &DNSNameError{Code: code, Name: name} }
	if name == "" {
		return fail(dnsNameEmpty)
	}
	if dnsNameLooksLikeAddress(name) {
		return fail(dnsNameLooksLikeIP)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || isLineBreakOrControl(r) {
			return fail(dnsNameWhitespace)
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return fail(dnsNameNonASCII)
		}
	}
	switch {
	case strings.Contains(name, "*"):
		return fail(dnsNameWildcard)
	case strings.Contains(name, "_"):
		return fail(dnsNameUnderscore)
	case strings.ContainsAny(name, `:/?#@[]\`):
		return fail(dnsNameURLOrPort)
	case len(name) > 253:
		return fail(dnsNameTooLong)
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fail(dnsNameLabel)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return fail(dnsNameLabel)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fail(dnsNameHyphen)
		}
	}
	if len(labels) < 2 {
		return fail(dnsNameSingleLabel)
	}
	if tld := labels[len(labels)-1]; !strings.HasPrefix(tld, "xn--") && !dnsLettersOnly(tld) {
		return fail(dnsNameTLD)
	}
	for _, suffix := range dnsInternalSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return fail(dnsNameInternalSuffix)
		}
	}
	return nil
}

// dnsNameLooksLikeAddress reports whether name reads as an address: what an
// access list takes in an address row, or a mistyped IPv4 address. No
// delegated top-level domain is all digits, so a numeric last label is
// always an address typo ("203.0.113.300", "partner.example.123").
func dnsNameLooksLikeAddress(name string) bool {
	if name == "all" || net.ParseIP(name) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(name); err == nil {
		return true
	}
	if dnsDigitsOnly(name[strings.LastIndexByte(name, '.')+1:]) {
		return true
	}
	return strings.Trim(name, "0123456789.") == "" && strings.ContainsAny(name, "0123456789")
}

func dnsDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func dnsLettersOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return s != ""
}

// Name status (dns_entry_states.status).
const (
	DNSStatusPending     = "pending"      // new name, nothing published yet
	DNSStatusOK          = "ok"           // published from a current answer
	DNSStatusStale       = "stale"        // a family failed for a while; its last addresses stay (grace)
	DNSStatusExpired     = "expired"      // the grace ran out; that family is empty
	DNSStatusRejected    = "rejected"     // the policy refused the answer
	DNSStatusNotFound    = "not_found"    // NXDOMAIN/NODATA for both families
	DNSStatusNeedsReview = "needs_review" // closed until an operator confirms
)

// Review reasons (dns_entry_states.review_reason).
const (
	DNSReviewCNAMEChanged = "cname_changed" // the CNAME target moved away from the pinned one
	DNSReviewReappeared   = "reappeared"    // came back from empty with addresses it never had
	DNSReviewUnstable     = "unstable"      // more applied changes in 24 hours than max_changes_per_day
)

// Why Published is empty (dns_entry_states.empty_cause).
const (
	DNSEmptyReplace  = "replace"  // a replacement revoked the old addresses and waits to add the new ones
	DNSEmptyLapse    = "lapse"    // not found, refused or past the grace
	DNSEmptyDisabled = "disabled" // the feature is off
	DNSEmptyRestored = "restored" // restored from a backup, nothing published yet
	DNSEmptyUnused   = "unused"   // no list uses the name any more
)

// Warnings (dns_entry_states.warnings). They never close a name.
const (
	DNSWarnSelfIP          = "self_ip"          // an address is NPG's own public address (DDNS last_ip)
	DNSWarnBanned          = "banned"           // an address is banned; the ban still wins
	DNSWarnCGNAT           = "cgnat"            // an address is in 100.64.0.0/10
	DNSWarnPartialRejected = "partial_rejected" // the policy dropped some of the answer
	DNSWarnIPv6Listen      = "ipv6_listen"      // nothing for IPv6 while NPG listens on IPv6
	DNSWarnDuplicate       = "duplicate"        // another name of the same scope publishes the same address
)

// DNSFamilyState is one address family's part of a dns_entry_states row
// (the v4_* or v6_* columns).
type DNSFamilyState struct {
	State    string     // "" | "ok" | "notfound" | "transient" | "rejected"
	Code     string     // classification code (timeout, not_found, private, ...) or ""
	Observed []string   // policy-passed addresses of the last ok answer (display)
	AnswerAt *time.Time // last definitive answer (ok, notfound, rejected)
	NotFound int        // consecutive notfound answers
}

// DNSEntryState is one dns_entry_states row. "" and nil stand for SQL NULL in
// the nullable columns. Error text is never stored, only codes.
type DNSEntryState struct {
	Hostname           string
	Status             string // DNSStatus*
	ReviewReason       string // DNSReview* while Status is needs_review
	Disabled           bool   // the feature is off; a flag, not a status
	UnusedSince        *time.Time
	Published          []string // addresses the files must hold now
	LastApplied        []string // last non-empty Published
	EmptyCause         string   // DNSEmpty* while Published is empty
	Generation         int64    // +1 whenever the files' content changes
	AppliedGeneration  int64    // generation an accepted reload read
	RevokePendingSince *time.Time
	Candidate          []string // nil = NULL
	CandidateSeen      int
	ReplaceOpen        bool // a replacement revoked addresses and has not finished adding
	V4, V6             DNSFamilyState
	CanonicalName      string // pinned CNAME target
	CanonicalSeen      string // target both CNAME lookups agreed on in the last check
	Warnings           []string
	ChangeTimes        []time.Time // applied changes in the last 24 hours
	LastCheckedAt      *time.Time
	LastChangedAt      *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// DNSReference is one use of a name: the name in one scope, with the owner
// (the list) the scope belongs to.
type DNSReference struct {
	Scope     string
	Name      string
	OwnerID   string
	OwnerName string
}

// DNSEntryStatus is a name's state as the API shows it. The service builds
// it; handlers only filter it by the caller's permissions (the banned
// warning needs waf:read, the self_ip warning ddns:read, blocking_file
// proxy:read).
type DNSEntryStatus struct {
	Hostname              string                     `json:"hostname"`
	Status                string                     `json:"status"`
	ReviewReason          *string                    `json:"review_reason"`
	Disabled              bool                       `json:"disabled"`
	Addresses             []string                   `json:"addresses"`
	PendingAddresses      []string                   `json:"pending_addresses"`
	NextApplyAt           *time.Time                 `json:"next_apply_at"`
	Applied               bool                       `json:"applied"`
	RevokePending         bool                       `json:"revoke_pending"`
	BlockedReason         *string                    `json:"blocked_reason"`
	BlockingFile          *string                    `json:"blocking_file"`
	ObservedAddresses     []string                   `json:"observed_addresses"`
	CanonicalName         *string                    `json:"canonical_name"`
	ObservedCanonicalName *string                    `json:"observed_canonical_name"`
	Families              map[string]DNSFamilyStatus `json:"families"` // keys "ipv4", "ipv6"
	Warnings              []string                   `json:"warnings"`
	ErrorCode             *string                    `json:"error_code"`
	StaleUntil            *time.Time                 `json:"stale_until"`
	LastCheckedAt         *time.Time                 `json:"last_checked_at"`
	LastChangedAt         *time.Time                 `json:"last_changed_at"`
}

// DNSFamilyStatus is one family in DNSEntryStatus.Families.
type DNSFamilyStatus struct {
	State string  `json:"state"`
	Code  *string `json:"code,omitempty"`
}

// DNSHostRef names a proxy host by its first domain name.
type DNSHostRef struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

// DNSStatusView says which caller-dependent parts of a status may be shown
// to the caller. The handler fills it with HasPermissionFromContext: Banned
// is waf:read, SelfIP ddns:read (the warning reveals NPG's own public
// address), BlockingFile proxy:read. A hidden part is removed (the warning
// dropped, the field null), never replaced.
type DNSStatusView struct {
	Banned       bool
	SelfIP       bool
	BlockingFile bool
}

// DNSEntryUse is one use of a name the caller may read, in the overview.
type DNSEntryUse struct {
	Scope     string `json:"scope"` // "acl:<id>"
	Kind      string `json:"kind"`  // "access_list"
	Key       string `json:"key"`   // its include file is npg_dns/<key>.allow
	OwnerID   string `json:"owner_id"`
	OwnerName string `json:"owner_name"`
}

// DNSEntryOverviewEntry is one name in the overview. The status fields are
// inlined next to the uses.
type DNSEntryOverviewEntry struct {
	DNSEntryStatus
	Uses             []DNSEntryUse `json:"uses"`               // only scopes the caller may read
	HiddenUses       int           `json:"hidden_uses"`        // uses in scopes the caller may not read
	LoginBypassHosts int           `json:"login_bypass_hosts"` // hosts where a satisfy-any list with this name skips the login
}

// DNSApplyState is the in-memory apply state the overview shows.
type DNSApplyState struct {
	LastDNSReloadAt  *time.Time `json:"last_dns_reload_at"`
	PendingAdditions int        `json:"pending_additions"` // rows with generation > applied_generation and no revoke pending
	RevokePending    int        `json:"revoke_pending"`    // rows with revoke_pending_since set
	BlockedOutcome   *string    `json:"blocked_outcome"`   // last failed outcome while failing: blocked|failed|rejected|not_up
	BlockedDetail    *string    `json:"blocked_detail"`
	BlockingFile     *string    `json:"blocking_file"`
	NextRetryAt      *time.Time `json:"next_retry_at"`
}

// DNSApplyResponse is the 200 body of POST /dns-entries/apply.
type DNSApplyResponse struct {
	Outcome      string  `json:"outcome"`
	Detail       *string `json:"detail"`
	BlockingFile *string `json:"blocking_file"`
}
