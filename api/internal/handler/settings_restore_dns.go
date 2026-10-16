package handler

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/model"
)

// Backup restore and domain entries (#320). A restore replaces the access
// lists, so every domain name gets new (scope, name) files; the DNS entry
// service writes them, and the restore must not let its ticks interleave.

// restoreDNSEntries is what a restore needs of service.DNSEntryService.
type restoreDNSEntries interface {
	RunExclusive(fn func() error) error
	ReconcileFiles(ctx context.Context, scanDisk bool) error
	Kick()
}

// restoreAuditNameCap bounds each name list in the restore audit's details.
const restoreAuditNameCap = 50

// importBackupDatabase runs ImportAllData and then reads back the restored
// domain entries for the audit. With the DNS entry service wired both run
// under its lock: a tick can neither change a name's state between the
// import's merge and the read, nor write files from the rows the import is
// replacing. A failed read is logged and the restore goes on.
func (h *SettingsHandler) importBackupDatabase(ctx context.Context, data *model.ExportData) (map[string]string, model.DNSRestoreSummary, error) {
	var certIDMap map[string]string
	var dns model.DNSRestoreSummary
	err := h.underDNSLock(func() error {
		var err error
		if certIDMap, err = h.backupRepo.ImportAllData(ctx, data); err != nil {
			return err
		}
		if dns, err = h.backupRepo.RestoredDNSEntries(ctx); err != nil {
			log.Printf("[Backup] Warning: failed to read the restored domain entries for the audit log: %v", err)
		}
		return nil
	})
	return certIDMap, dns, err
}

// underDNSLock runs fn under the DNS entry service's lock, or directly when
// the service is not wired.
func (h *SettingsHandler) underDNSLock(fn func() error) error {
	if h.dnsEntries == nil {
		return fn()
	}
	return h.dnsEntries.RunExclusive(fn)
}

// reconcileDNSEntryFiles writes the include files of the restored domain
// entries, and creates empty the ones the restored configs name but the
// database does not know (a config-only restore, a host missing from the
// database), before nginx -t reads them. A failure is logged: nginx -t then
// names the file it could not open.
func (h *SettingsHandler) reconcileDNSEntryFiles(ctx context.Context) {
	if h.dnsEntries == nil {
		return
	}
	if err := h.dnsEntries.ReconcileFiles(ctx, true); err != nil {
		log.Printf("[Backup] Warning: failed to write the domain entry files after restore: %v", err)
	}
}

// kickDNSEntriesAfterRestore asks for a tick now, so the names a database
// restore brought back are resolved without waiting for the next interval.
func (h *SettingsHandler) kickDNSEntriesAfterRestore(result *model.RestoreResult) {
	if h.dnsEntries != nil && result.DatabaseRestored {
		h.dnsEntries.Kick()
	}
}

// dnsRestoreAuditExtra is what the restore audit records about domain
// entries: the names the restored access lists use, those of them waiting
// for review (each list cut at restoreAuditNameCap) and how many names there
// are. nil when the restore brought back no names.
func dnsRestoreAuditExtra(s model.DNSRestoreSummary) map[string]interface{} {
	if len(s.Names) == 0 {
		return nil
	}
	return map[string]interface{}{
		"dns_names":        restoreAuditNames(s.Names),
		"dns_names_total":  len(s.Names),
		"dns_needs_review": restoreAuditNames(s.NeedsReview),
	}
}

// restoreAuditNames is names cut at restoreAuditNameCap, never nil (JSON []).
func restoreAuditNames(names []string) []string {
	if len(names) > restoreAuditNameCap {
		names = names[:restoreAuditNameCap]
	}
	return append([]string{}, names...)
}
