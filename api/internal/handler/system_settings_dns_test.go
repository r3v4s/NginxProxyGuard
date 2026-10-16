package handler

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// fakeSettingsChanger records what a save hands to the DNS entry service,
// and whether each call came on a context already cancelled.
type fakeSettingsChanger struct {
	calls     [][2]model.DNSEntrySettings
	cancelled []bool
}

func (f *fakeSettingsChanger) SettingsChanged(ctx context.Context, before, after model.DNSEntrySettings) {
	f.calls = append(f.calls, [2]model.DNSEntrySettings{before, after})
	f.cancelled = append(f.cancelled, ctx.Err() != nil)
}

// fakeSettingsAudit records the dns_entry_settings_changed entries, and
// whether each came on a context already cancelled.
type fakeSettingsAudit struct {
	changes   []map[string]interface{}
	cancelled []bool
}

func (f *fakeSettingsAudit) LogDNSEntrySettingsChanged(ctx context.Context, changes map[string]interface{}) error {
	f.changes = append(f.changes, changes)
	f.cancelled = append(f.cancelled, ctx.Err() != nil)
	return nil
}

// A PUT's partial dns_entry_settings is merged over the STORED value and put
// back whole: a key the form leaves out keeps what is stored, so a save of
// the interval alone never turns a switched-off feature back on, and the row
// always holds all nine keys.
func TestPrepareDNSEntrySettingsMergesOverTheStoredValue(t *testing.T) {
	cur := &model.SystemSettings{DNSEntrySettings: json.RawMessage(`{"enabled": false, "check_interval_seconds": 120}`)}
	partial := json.RawMessage(`{"check_interval_seconds": 90}`)
	req := &model.UpdateSystemSettingsRequest{DNSEntrySettings: &partial}

	save, err := prepareDNSEntrySettings(req, cur)
	if err != nil {
		t.Fatal(err)
	}
	before := model.DefaultDNSEntrySettings()
	before.Enabled, before.CheckIntervalSeconds = false, 120
	after := before
	after.CheckIntervalSeconds = 90
	if !save.set || save.before != before || save.after != after {
		t.Fatalf("save = %+v, want before %+v and after %+v", save, before, after)
	}
	var written map[string]interface{}
	if err := json.Unmarshal(*req.DNSEntrySettings, &written); err != nil {
		t.Fatal(err)
	}
	if len(written) != 9 || written["enabled"] != false || written["check_interval_seconds"] != float64(90) {
		t.Fatalf("the request now carries %s, want all nine keys with enabled false and the interval 90", *req.DNSEntrySettings)
	}

	// A stored value outside its range is read clamped and does not block a
	// save that leaves it alone.
	cur = &model.SystemSettings{DNSEntrySettings: json.RawMessage(`{"max_total": 999}`)}
	partial = json.RawMessage(`{"max_per_list": 8}`)
	req = &model.UpdateSystemSettingsRequest{DNSEntrySettings: &partial}
	if save, err := prepareDNSEntrySettings(req, cur); err != nil || save.after.MaxTotal != 256 || save.after.MaxPerList != 8 {
		t.Fatalf("over a hand-edited max_total: after %+v, err %v", save.after, err)
	}

	// No field, nothing to do.
	plain := &model.UpdateSystemSettingsRequest{}
	if save, err := prepareDNSEntrySettings(plain, cur); err != nil || save.set || plain.DNSEntrySettings != nil {
		t.Fatalf("without the field: save %+v, err %v, field %v", save, err, plain.DNSEntrySettings)
	}
}

// A refused object names the key in the 400 sentence, and the request keeps
// what it carried, so nothing half-merged reaches the row.
func TestPrepareDNSEntrySettingsRefusesWithTheKey(t *testing.T) {
	for body, want := range map[string]string{
		`{"check_interval": 30}`: `dns_entry_settings: unknown key "check_interval"`,
		`{"max_total": 999}`:     "dns_entry_settings.max_total must be between 1 and 256 (got 999)",
	} {
		raw := json.RawMessage(body)
		req := &model.UpdateSystemSettingsRequest{DNSEntrySettings: &raw}
		_, err := prepareDNSEntrySettings(req, &model.SystemSettings{})
		if err == nil || trimInvalidInputPrefix(err) != want {
			t.Errorf("%s: error %v, want %q", body, err, want)
		}
		if string(*req.DNSEntrySettings) != body {
			t.Errorf("%s: the request now carries %s", body, *req.DNSEntrySettings)
		}
	}
}

// A save records only the keys that changed, as [before, after], and hands
// both values to the DNS entry service once; a save that changes nothing
// does neither.
func TestFinishDNSEntrySettingsSave(t *testing.T) {
	before := model.DefaultDNSEntrySettings()
	after := before
	after.Enabled = false
	audit, svc := &fakeSettingsAudit{}, &fakeSettingsChanger{}
	ctx := context.Background()
	want := map[string]interface{}{"enabled": []interface{}{true, false}}

	changes := finishDNSEntrySettingsSave(ctx, ctx, dnsSettingsSave{set: true, before: before, after: after}, audit, svc)
	if !reflect.DeepEqual(changes, want) || len(audit.changes) != 1 || !reflect.DeepEqual(audit.changes[0], want) {
		t.Fatalf("changes %v, audited %v, want %v once", changes, audit.changes, want)
	}
	if len(svc.calls) != 1 || svc.calls[0] != [2]model.DNSEntrySettings{before, after} {
		t.Fatalf("the DNS entry service got %+v, want (before, after) once", svc.calls)
	}

	for _, save := range []dnsSettingsSave{{set: true, before: after, after: after}, {}} {
		if got := finishDNSEntrySettingsSave(ctx, ctx, save, audit, svc); got != nil || len(audit.changes) != 1 || len(svc.calls) != 1 {
			t.Errorf("save %+v: changes %v, %d audits, %d service calls; want nothing more", save, got, len(audit.changes), len(svc.calls))
		}
	}
	if got := finishDNSEntrySettingsSave(ctx, ctx, dnsSettingsSave{set: true, before: before, after: after}, nil, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("without an audit or DNS entry service: changes %v, want %v", got, want)
	}
}

// The row is saved: a client that leaves now loses neither the audit nor the
// switch. A switch-off it lost would wait for the next check to empty the
// files.
func TestFinishDNSEntrySettingsSaveOutlivesTheRequest(t *testing.T) {
	before := model.DefaultDNSEntrySettings()
	after := before
	after.Enabled = false
	audit, svc := &fakeSettingsAudit{}, &fakeSettingsChanger{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client left after the UPDATE

	finishDNSEntrySettingsSave(ctx, ctx, dnsSettingsSave{set: true, before: before, after: after}, audit, svc)

	if !reflect.DeepEqual(audit.cancelled, []bool{false}) || !reflect.DeepEqual(svc.cancelled, []bool{false}) {
		t.Errorf("audit on a cancelled context %v, switch %v; want both done on a live one", audit.cancelled, svc.cancelled)
	}
}

// settings_updated names a switch of the WAF bypass as [before, after]; the
// stored value sent back, or no value, adds nothing.
func TestSystemSettingsAuditDetailsRecordTheWAFBypassSwitch(t *testing.T) {
	on, off := true, false
	cur := &model.SystemSettings{GlobalTrustedIPsBypassWAF: false}
	plain := map[string]interface{}{"action": "update"}
	cases := []struct {
		name string
		req  model.UpdateSystemSettingsRequest
		want map[string]interface{}
	}{
		{"not sent", model.UpdateSystemSettingsRequest{}, plain},
		{"sent back unchanged", model.UpdateSystemSettingsRequest{GlobalTrustedIPsBypassWAF: &off}, plain},
		{"switched on", model.UpdateSystemSettingsRequest{GlobalTrustedIPsBypassWAF: &on},
			map[string]interface{}{"action": "update", "global_trusted_ips_bypass_waf": []bool{false, true}}},
	}
	for _, c := range cases {
		if got := systemSettingsAuditDetails(&c.req, cur); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
