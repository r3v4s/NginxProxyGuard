package model

import (
	"fmt"
	"strings"
)

// The IP fields of the four exception lists (#320) and the domain names that
// get typed into them. Each list has a field of its own for domain names
// (exception_hostnames, allowed_hostnames, whitelist_hostnames,
// global_trusted_hostnames); a domain name in the IP field is refused with
// the field it goes in, and never moved there by the server.

// CodeHostnameInIPField is the code of a 400 for a domain name in an IP
// field. The sentence names the field that takes domain names.
const CodeHostnameInIPField = "hostname_in_ip_field"

// IPEntryError is a refused entry of an IP field. Field is its path in the
// request: "allowed_ips[2]" for a list, "global_trusted_ips[3]" for the
// fourth line of the global trusted list, "whitelist_ips" for the rate limit
// exceptions (one text of entries). Code is CodeHostnameInIPField or "", and
// Message the sentence, which starts with Field.
type IPEntryError struct {
	Field   string
	Code    string
	Message string
}

func (e *IPEntryError) Error() string { return ErrInvalidInput.Error() + ": " + e.Message }

// Unwrap makes errors.Is(err, ErrInvalidInput) match.
func (e *IPEntryError) Unwrap() error { return ErrInvalidInput }

// HostnameInIPField returns the refusal of entry, sent in the IP field
// field, when it is a domain name (ValidateDNSName accepts it once
// normalized): a domain name goes in nameField. It returns nil for anything
// else, which the caller refuses in its own words.
func HostnameInIPField(field, entry, nameField string) *IPEntryError {
	if ValidateDNSName(NormalizeDNSName(entry)) != nil {
		return nil
	}
	return &IPEntryError{
		Field:   field,
		Code:    CodeHostnameInIPField,
		Message: fmt.Sprintf("%s %.60q: a domain name goes in %s", field, strings.TrimSpace(entry), nameField),
	}
}

// ValidateChangedTrustedIPs checks the global trusted IP list (one entry per
// line) a save sends, against the stored one. A blank line, a # comment, an
// IP address or a CIDR range passes, and so does a line the stored list
// holds already: the field was not checked before #320, so a stored list
// can hold anything (a name, two addresses on one line), the configs leave
// such a line out, and one of them must not block a save of the rest. A new
// line that is a domain name is refused with CodeHostnameInIPField (it goes
// in global_trusted_hostnames); any other new line is refused too. Lines are
// compared without the whitespace around them, and the field is
// global_trusted_ips[i], i the line's position from 0.
func ValidateChangedTrustedIPs(raw, stored string) error {
	kept := make(map[string]bool)
	for _, line := range strings.Split(stored, "\n") {
		kept[strings.TrimSpace(line)] = true
	}
	for i, line := range strings.Split(raw, "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") || kept[entry] {
			continue
		}
		if _, ok := NormalizeIPOrCIDR(entry); ok {
			continue
		}
		field := fmt.Sprintf("global_trusted_ips[%d]", i)
		if e := HostnameInIPField(field, entry, "global_trusted_hostnames"); e != nil {
			return e
		}
		return &IPEntryError{Field: field, Message: fmt.Sprintf("%s %.60q is not an IP address or CIDR range", field, entry)}
	}
	return nil
}

// IgnoredIPEntries returns the entries of an IP field that the configs
// leave out: those that are not an IP address or a CIDR range once the
// whitespace around them is removed, in order and as trimmed. A blank entry
// and a # comment (the global trusted list allows them) are not entries. It
// takes a list field as it is, and the global trusted list split into its
// lines. nil when every entry is used.
func IgnoredIPEntries(entries []string) []string {
	var out []string
	for _, e := range entries {
		entry := strings.TrimSpace(e)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, ok := NormalizeIPOrCIDR(entry); !ok {
			out = append(out, entry)
		}
	}
	return out
}
