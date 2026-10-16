package handler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// restoreDNSFake records what a restore asks of the DNS entry service.
type restoreDNSFake struct {
	calls     []string
	locked    bool
	reconcile error
}

func (f *restoreDNSFake) RunExclusive(fn func() error) error {
	f.calls = append(f.calls, "lock")
	f.locked = true
	defer func() { f.locked = false }()
	return fn()
}

func (f *restoreDNSFake) ReconcileFiles(_ context.Context, scanDisk bool) error {
	f.calls = append(f.calls, fmt.Sprintf("reconcile scanDisk=%v", scanDisk))
	return f.reconcile
}

func (f *restoreDNSFake) Kick() { f.calls = append(f.calls, "kick") }

// The import runs under the DNS entry service's lock and keeps its error;
// the files are reconciled with a disk scan, and a failure there does not
// stop the restore; only a database restore asks for an early tick.
// Without the service every step but the import is skipped.
func TestRestoreDNSEntrySteps(t *testing.T) {
	fake := &restoreDNSFake{reconcile: errors.New("disk full")}
	h := &SettingsHandler{dnsEntries: fake}

	ranLocked := false
	if err := h.underDNSLock(func() error { ranLocked = fake.locked; return nil }); err != nil || !ranLocked {
		t.Fatalf("underDNSLock: err %v, ran under the lock %v", err, ranLocked)
	}
	importErr := errors.New("import failed")
	if err := h.underDNSLock(func() error { return importErr }); err != importErr {
		t.Errorf("underDNSLock returned %v, want the import's error", err)
	}
	h.reconcileDNSEntryFiles(context.Background())
	h.kickDNSEntriesAfterRestore(&model.RestoreResult{DatabaseRestored: false})
	h.kickDNSEntriesAfterRestore(&model.RestoreResult{DatabaseRestored: true})
	if want := []string{"lock", "lock", "reconcile scanDisk=true", "kick"}; !reflect.DeepEqual(fake.calls, want) {
		t.Errorf("calls = %q, want %q", fake.calls, want)
	}

	bare := &SettingsHandler{}
	bare.SetDNSEntries(nil)
	if bare.dnsEntries != nil {
		t.Fatal("SetDNSEntries(nil) left a non-nil service behind")
	}
	ran := false
	if err := bare.underDNSLock(func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("without the service: err %v, import ran %v", err, ran)
	}
	bare.reconcileDNSEntryFiles(context.Background())
	bare.kickDNSEntriesAfterRestore(&model.RestoreResult{DatabaseRestored: true})
}

// The restore audit names the restored domain names and those waiting for
// review, at most restoreAuditNameCap of each, with the total; nothing when
// the restore brought back no names.
func TestDNSRestoreAuditExtra(t *testing.T) {
	if got := dnsRestoreAuditExtra(model.DNSRestoreSummary{}); got != nil {
		t.Errorf("no names: %v, want nil", got)
	}
	got := dnsRestoreAuditExtra(model.DNSRestoreSummary{Names: []string{"partner.example.com"}})
	want := map[string]interface{}{
		"dns_names": []string{"partner.example.com"}, "dns_names_total": 1, "dns_needs_review": []string{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("one name: %v, want %v", got, want)
	}

	var many []string
	for i := 0; i < 60; i++ {
		many = append(many, fmt.Sprintf("n%02d.example.com", i))
	}
	got = dnsRestoreAuditExtra(model.DNSRestoreSummary{Names: many, NeedsReview: many})
	if names := got["dns_names"].([]string); len(names) != 50 || names[49] != "n49.example.com" {
		t.Errorf("dns_names holds %d names ending %q, want the first 50", len(names), names[len(names)-1])
	}
	if n := len(got["dns_needs_review"].([]string)); n != 50 {
		t.Errorf("dns_needs_review holds %d names, want 50", n)
	}
	if got["dns_names_total"] != 60 {
		t.Errorf("dns_names_total = %v, want 60", got["dns_names_total"])
	}
}
