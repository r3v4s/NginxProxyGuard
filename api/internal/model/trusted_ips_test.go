package model

import (
	"errors"
	"reflect"
	"testing"
)

// The entries the configs leave out, which the screens show as not applied
// (#320): blank entries and # comments are not entries, and an address or a
// range with spaces around it is used.
func TestIgnoredIPEntriesListsWhatTheConfigsLeaveOut(t *testing.T) {
	got := IgnoredIPEntries([]string{"192.0.2.1", " partner.example.com ", "", "  ", "# office", "192.0.2.64/26", "192.0.2.77/24", "192.0.2.300"})
	if want := []string{"partner.example.com", "192.0.2.300"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IgnoredIPEntries = %q, want %q", got, want)
	}
	if got := IgnoredIPEntries([]string{"192.0.2.0/24", "# all good"}); got != nil {
		t.Errorf("a list the configs use whole = %q, want nil", got)
	}
}

// A stored line of the global trusted list passes whatever it holds, also
// with other whitespace or line endings around it; the line position names
// a new one.
func TestValidateChangedTrustedIPsComparesLinesWithoutTheirWhitespace(t *testing.T) {
	stored := "192.0.2.0/24\r\nlegacy.example.com\r\n 192.0.2.1 192.0.2.2"
	if err := ValidateChangedTrustedIPs("# kept\r\n  legacy.example.com\r\n192.0.2.1 192.0.2.2 \r\n\r\n192.0.2.9", stored); err != nil {
		t.Fatalf("stored lines sent back refused: %v", err)
	}
	err := ValidateChangedTrustedIPs("192.0.2.0/24\nPartner.Example.com.", stored)
	var e *IPEntryError
	if !errors.As(err, &e) || e.Field != "global_trusted_ips[1]" || e.Code != CodeHostnameInIPField || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a new domain line: %#v", err)
	}
}
