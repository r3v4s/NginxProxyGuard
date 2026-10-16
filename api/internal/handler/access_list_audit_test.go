package handler

import (
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestAccessListChangesNamesAddedAndRemovedRules(t *testing.T) {
	before := &model.AccessList{Name: "partners", SatisfyAny: true, Items: []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.0/24"},
		{Directive: "allow", Address: "198.51.100.7"},
		{Directive: "deny", Address: "all"},
	}}
	after := &model.AccessList{Name: "partners", SatisfyAny: false, Items: []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.0/24"},
		{Directive: "allow", Address: "203.0.113.9"},
		{Directive: "deny", Address: "all"},
	}}
	got := accessListChanges(before, after)
	want := map[string]interface{}{
		"added":       []string{"allow 203.0.113.9"},
		"removed":     []string{"allow 198.51.100.7"},
		"satisfy_any": []bool{true, false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %#v, want %#v", got, want)
	}
}

func TestAccessListChangesIsEmptyWhenNothingChanged(t *testing.T) {
	l := &model.AccessList{Name: "x", Items: []model.AccessListItem{{Directive: "deny", Address: "all"}}}
	if got := accessListChanges(l, l); len(got) != 0 {
		t.Errorf("changes = %#v, want none", got)
	}
}

// The audit service writes the list's current name into the entry's "name"
// detail, so a rename is kept under "renamed": under "name" the old name
// would be overwritten.
func TestAccessListChangesRecordsARenameUnderRenamed(t *testing.T) {
	before := &model.AccessList{Name: "partners"}
	after := &model.AccessList{Name: "vendors"}
	got := accessListChanges(before, after)
	want := map[string]interface{}{"renamed": []string{"partners", "vendors"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %#v, want %#v", got, want)
	}
}

// allow and deny lines are first-match, so a new order of the same rules
// changes which clients get in: it is recorded as "reordered".
func TestAccessListChangesRecordsAReorder(t *testing.T) {
	before := &model.AccessList{Name: "office", Items: []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "deny", Address: "192.0.2.0/24"},
		{Directive: "deny", Address: "all"},
	}}
	after := &model.AccessList{Name: "office", Items: []model.AccessListItem{
		{Directive: "deny", Address: "192.0.2.0/24"},
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "deny", Address: "all"},
	}}
	if got, want := accessListChanges(before, after), (map[string]interface{}{"reordered": true}); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %#v, want %#v", got, want)
	}
}

// A domain rule is stored as (deny, all, name): the audit names it by its
// domain, so adding or removing one is not lost among "deny all"
// rules.
func TestAccessListChangesNameDomainRulesByTheirDomain(t *testing.T) {
	before := &model.AccessList{Name: "partners", Items: []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "deny", Address: "all", Hostname: "old.example.com"},
	}}
	after := &model.AccessList{Name: "partners", Items: []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.10"},
		{Directive: "deny", Address: "all", Hostname: "new.example.com"},
	}}
	want := map[string]interface{}{
		"added":   []string{"allow new.example.com (domain)"},
		"removed": []string{"allow old.example.com (domain)"},
	}
	if got := accessListChanges(before, after); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %#v, want %#v", got, want)
	}
}

// Moving a legacy rule to a domain is what turns an old name into a working
// one, so it is recorded as moved_to_domain.
func TestAccessListChangesRecordALegacyRuleMovedToADomain(t *testing.T) {
	before := &model.AccessList{Name: "partners", Items: []model.AccessListItem{
		{Directive: "allow", Address: "Partner.Example.com"},
	}}
	after := &model.AccessList{Name: "partners", Items: []model.AccessListItem{
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}}
	want := map[string]interface{}{
		"added":           []string{"allow partner.example.com (domain)"},
		"removed":         []string{"allow Partner.Example.com"},
		"moved_to_domain": []string{"partner.example.com"},
	}
	if got := accessListChanges(before, after); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %#v, want %#v", got, want)
	}
}
