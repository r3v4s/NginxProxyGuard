package handler

import (
	"context"
	"encoding/json"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// The domain entry tunables in PUT /system-settings (#320). A request
// carries a partial object; the row always holds the whole
// one. A change is recorded as [before, after] per key and handed to the DNS
// entry service, which switches every name off or on at once and wakes its
// scheduler. nginx takes the files in the background, so this save never
// answers 409 for them: a failure shows in GET /dns-entries and in
// the dns_entry.apply_failed alert.

// dnsSettingsChanger is what a settings save needs of
// service.DNSEntryService: the tunables, and the global trusted domain
// names (scope trusted).
type dnsSettingsChanger interface {
	SettingsChanged(ctx context.Context, before, after model.DNSEntrySettings)
	dnsScopeSyncer
}

// dnsSettingsAuditor records a change of the tunables (service.AuditService).
type dnsSettingsAuditor interface {
	LogDNSEntrySettingsChanged(ctx context.Context, changes map[string]interface{}) error
}

// SetDNSEntries wires the DNS entry service: a save that changes the domain
// entry tunables hands the change to it. Without it the tunables are only
// stored, and nothing switches the names at once.
func (h *SystemSettingsHandler) SetDNSEntries(svc *service.DNSEntryService) {
	if svc != nil {
		h.dnsEntries = svc
	}
}

// dnsSettingsSave carries the tunables of one PUT from the check before the
// save to the work after it.
type dnsSettingsSave struct {
	set           bool // the request carried dns_entry_settings
	before, after model.DNSEntrySettings
}

// prepareDNSEntrySettings merges the request's partial dns_entry_settings
// over the stored value in cur and puts the whole result back into the
// request, so the row always holds every key. The base is the stored value:
// not the defaults (an omitted "enabled" would turn the feature back on),
// and not the value NPG_DNS_ENTRIES_DISABLED makes effective (saving it
// would keep the feature off after the switch is removed). An unknown key, a
// value of the wrong type or a number out of range is an ErrInvalidInput
// naming the key, and the request is left as it was.
func prepareDNSEntrySettings(req *model.UpdateSystemSettingsRequest, cur *model.SystemSettings) (dnsSettingsSave, error) {
	if req.DNSEntrySettings == nil {
		return dnsSettingsSave{}, nil
	}
	var stored json.RawMessage
	if cur != nil {
		stored = cur.DNSEntrySettings
	}
	before := model.ParseDNSEntrySettings(stored)
	after, err := model.MergeDNSEntrySettings(before, *req.DNSEntrySettings)
	if err != nil {
		return dnsSettingsSave{}, err
	}
	whole, err := json.Marshal(after)
	if err != nil {
		return dnsSettingsSave{}, err
	}
	raw := json.RawMessage(whole)
	req.DNSEntrySettings = &raw
	return dnsSettingsSave{set: true, before: before, after: after}, nil
}

// finishDNSEntrySettingsSave runs once the row is saved. When a key changed,
// it records {key: [before, after]} for the changed keys
// (dns_entry_settings_changed) in auditCtx, the request's user, and then
// hands both values to the DNS entry service. It returns the changes, nil
// when nothing changed. audit and svc may be nil. Both run to the end when
// the client has left: the row is saved, and a switch-off left undone would
// wait for the next check.
func finishDNSEntrySettingsSave(ctx, auditCtx context.Context, save dnsSettingsSave, audit dnsSettingsAuditor, svc dnsSettingsChanger) map[string]interface{} {
	if !save.set {
		return nil
	}
	changes := model.DiffDNSEntrySettings(save.before, save.after)
	if len(changes) == 0 {
		return nil
	}
	ctx, auditCtx = context.WithoutCancel(ctx), context.WithoutCancel(auditCtx)
	if audit != nil {
		audit.LogDNSEntrySettingsChanged(auditCtx, changes)
	}
	if svc != nil {
		svc.SettingsChanged(ctx, save.before, save.after)
	}
	return changes
}

// afterDNSEntrySettingsSave is finishDNSEntrySettingsSave with this
// handler's audit service and DNS entry service.
func (h *SystemSettingsHandler) afterDNSEntrySettingsSave(c echo.Context, save dnsSettingsSave) {
	var audit dnsSettingsAuditor
	if h.audit != nil {
		audit = h.audit
	}
	ctx := c.Request().Context()
	finishDNSEntrySettingsSave(ctx, service.ContextWithAudit(ctx, c), save, audit, h.dnsEntries)
}

// systemSettingsAuditDetails are the details of the settings_updated entry a
// PUT records. A switch of global_trusted_ips_bypass_waf, which decides
// whether the global trusted IPs skip the WAF, is recorded as
// [before, after]; sending the stored value back records
// nothing for it. cur is the stored row, read whenever the request carries
// that field.
func systemSettingsAuditDetails(req *model.UpdateSystemSettingsRequest, cur *model.SystemSettings) map[string]interface{} {
	details := map[string]interface{}{"action": "update"}
	if req.GlobalTrustedIPsBypassWAF != nil && cur != nil && *req.GlobalTrustedIPsBypassWAF != cur.GlobalTrustedIPsBypassWAF {
		details["global_trusted_ips_bypass_waf"] = []bool{cur.GlobalTrustedIPsBypassWAF, *req.GlobalTrustedIPsBypassWAF}
	}
	return details
}
