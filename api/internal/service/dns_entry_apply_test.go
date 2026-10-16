package service

import (
	"context"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// dnsBackingOffRig is partner.example.com in list A, published at 203.0.113.10
// with an addition nginx has not taken, after five failed applies: the loop
// backs off and its next retry is 10 minutes away. The sixth apply answers
// then.
func dnsBackingOffRig(t *testing.T, failure, then nginx.DNSApplyResult) *dnsTestRig {
	t.Helper()
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"))
	row := dnsOKRow("partner.example.com", 2, "203.0.113.10")
	row.AppliedGeneration = 1
	r.store.put(row)
	r.lookup.set("partner.example.com", "203.0.113.10")
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.nginx.results = []nginx.DNSApplyResult{failure, failure, failure, failure, failure, then}
	for _, wait := range []time.Duration{0, 61 * time.Second, 121 * time.Second, 241 * time.Second, 481 * time.Second} {
		r.clock.Advance(wait)
		r.tick(t)
	}
	if n := r.nginx.applyCount(); n != 5 {
		t.Fatalf("applies = %d while backing off, want 5", n)
	}
	r.clock.Advance(time.Second)
	if wait := r.svc.applyView.retryAt.Sub(r.clock.Now()); wait < 9*time.Minute {
		t.Fatalf("next retry in %v, want the loop backing off for about 10 minutes", wait)
	}
	return r
}

// dnsSwitchOff stores "off" and switches every name off, as a settings save
// does, and checks that the switch woke the scheduler.
func dnsSwitchOff(t *testing.T, r *dnsTestRig) {
	t.Helper()
	on := model.DefaultDNSEntrySettings()
	off := on
	off.Enabled = false
	r.settings.set(`{"enabled":false}`, nil)
	r.svc.SettingsChanged(context.Background(), on, off)
	select {
	case <-r.svc.Wake():
	default:
		t.Fatal("switching off must wake the scheduler")
	}
}

// The emergency switch while the apply loop backs off. The switch empties
// the files itself, so the check it wakes finds nothing to write; that check
// must still have nginx drop the addresses, not the retry 10 minutes later,
// and a blocked apply raises the revoke alert at that check. Retrying the
// same failure backs off again.
func TestDNSSwitchOffDuringABackoffIsAppliedAtOnce(t *testing.T) {
	blocked := nginx.DNSApplyResult{Outcome: "blocked", BlockingFile: "proxy_host_x.conf"}
	cases := []struct {
		name          string
		failure, then nginx.DNSApplyResult
	}{
		{"failed, then accepted", nginx.DNSApplyResult{Outcome: "failed"}, nginx.DNSApplyResult{Outcome: "accepted"}},
		{"blocked", blocked, blocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := dnsBackingOffRig(t, c.failure, c.then)
			alertsBefore := len(r.events.snapshot().alerts)

			dnsSwitchOff(t, r)
			if got := r.partnerFile(t); len(got) != 0 {
				t.Fatalf("file = %v, want it emptied by the switch", got)
			}
			r.tick(t) // the check the switch asked for

			if n := r.nginx.applyCount(); n != 6 {
				t.Fatalf("applies = %d, want the switch-off applied by the check it woke (6)", n)
			}
			st, _ := r.store.row("partner.example.com")
			var after []dnsApplyAlert
			for _, a := range r.events.snapshot().alerts[alertsBefore:] {
				if a.Subject == "revoke" {
					after = append(after, a)
				}
			}
			if c.then.Outcome == "accepted" {
				if st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation || r.svc.dnsAllows(dnsACL(dnsTestListA), "203.0.113.10") {
					t.Fatalf("row %+v; want the revocation in nginx after the accepted apply", st)
				}
				return
			}
			if len(after) != 1 || !after[0].Failing || after[0].Outcome != "blocked" {
				t.Fatalf("revoke alerts after the switch = %+v, want it failing at the check the switch woke", after)
			}
			r.clock.Advance(time.Minute)
			r.tick(t)
			if n := r.nginx.applyCount(); n != 6 {
				t.Fatalf("applies = %d a minute later, want the blocked retry to back off again", n)
			}
		})
	}
}

// A list save that takes the name out while the loop backs off, whose own
// reload failed: the emptied file is applied by the next check, not when the
// retry falls due.
func TestDNSListRemovalDuringABackoffIsAppliedAtTheNextCheck(t *testing.T) {
	r := dnsBackingOffRig(t, nginx.DNSApplyResult{Outcome: "failed"}, nginx.DNSApplyResult{Outcome: "accepted"})
	r.store.setRefs() // the list no longer holds the name
	if err := r.svc.SyncScope(context.Background(), dnsACL(dnsTestListA), nil); err != nil {
		t.Fatal(err)
	}
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("file = %v, want it emptied by the save", got)
	}

	r.tick(t)

	st, _ := r.store.row("partner.example.com")
	if n := r.nginx.applyCount(); n != 6 || st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation {
		t.Fatalf("row %+v after %d applies; want the removal applied by the next check", st, n)
	}
}

// The switch-off while the check of an older reload is open: a host save's
// reload that came back unconfirmed, or one a failed operation signalled
// (not checked). nginx took that reload, which read the files before the
// switch. Finding it taken must not stand for the switch-off: the check the
// switch woke has nginx read the emptied files.
func TestDNSSwitchOffAfterAnOlderReloadIsAppliedAtOnce(t *testing.T) {
	for _, outcome := range []nginx.ReloadOutcome{nginx.ReloadUnconfirmed, nginx.ReloadNotChecked} {
		t.Run(string(outcome), func(t *testing.T) {
			r := dnsPartnerRig(t, "203.0.113.10")
			r.svc.reconciled.Store(true)
			r.tick(t) // a regular check: nothing to apply
			r.clock.Advance(20 * time.Second)
			hooks := r.svc.ReloadHooks()
			hooks.After(hooks.Before(), outcome, &nginx.ReloadSnapshot{})
			r.settle()
			r.nginx.mu.Lock()
			r.nginx.taken = true // nginx took it
			r.nginx.mu.Unlock()
			r.clock.Advance(30 * time.Second)

			dnsSwitchOff(t, r)
			r.clock.Advance(time.Second)
			r.tick(t) // the check the switch asked for

			st, _ := r.store.row("partner.example.com")
			if n := r.nginx.applyCount(); n != 1 || st.RevokePendingSince != nil || st.AppliedGeneration != st.Generation {
				t.Fatalf("row %+v after %d applies; want the switch-off applied by the check it woke", st, n)
			}
			if r.svc.dnsAllows(dnsACL(dnsTestListA), "203.0.113.10") {
				t.Fatal("203.0.113.10 is still counted as allowed after the switch-off was applied")
			}
		})
	}
}

// A removal the save's own reload carried to nginx is not applied again by
// the next check.
func TestDNSRemovalASaveReloadTookIsNotAppliedAgain(t *testing.T) {
	r := newDNSTestRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	r.lookup.set("partner.example.com", "203.0.113.10")
	if err := r.svc.ReconcileFiles(ctx, false); err != nil {
		t.Fatal(err)
	}
	r.store.setRefs(dnsRef(dnsTestListB, "partner.example.com")) // list A saved without the name
	if err := r.svc.SyncScope(ctx, dnsACL(dnsTestListA), nil); err != nil {
		t.Fatal(err)
	}
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // the save's regeneration reload
	r.settle()

	r.clock.Advance(time.Minute)
	r.tick(t)

	if st, _ := r.store.row("partner.example.com"); st.RevokePendingSince != nil || r.nginx.applyCount() != 0 {
		t.Fatalf("row %+v after %d applies; want the removal applied by the save's reload and no second one", st, r.nginx.applyCount())
	}
}
