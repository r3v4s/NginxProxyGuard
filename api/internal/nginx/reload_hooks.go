package nginx

import (
	"context"
	"errors"
)

// ReloadOutcome is what became of one reload signal, as the reload hooks
// hear of it.
type ReloadOutcome string

const (
	// ReloadAccepted: nginx started new workers (or a new master), so it
	// loaded the files that were on disk when the signal was sent, or newer
	// ones.
	ReloadAccepted ReloadOutcome = "accepted"
	// ReloadRejected: nginx logged an [emerg] and kept its workers; it runs
	// its previous configuration (*ReloadRejectedError).
	ReloadRejected ReloadOutcome = "rejected"
	// ReloadUnconfirmed: nginx showed neither within the wait, or its
	// processes could not be read before the signal. Saves report it as
	// applied.
	ReloadUnconfirmed ReloadOutcome = "unconfirmed"
	// ReloadNotChecked: the operation that signalled the reload failed
	// afterwards (a rollback, a failed health probe), so nobody waited for
	// nginx's answer. nginx may well have taken it.
	ReloadNotChecked ReloadOutcome = "not_checked"
	// ReloadSuperseded: a later signal in the same nginx operation replaced
	// this one before it was confirmed (that one, which reads newer files,
	// reports for both), or the operation panicked.
	ReloadSuperseded ReloadOutcome = "superseded"
	// ReloadSignalled: the signal was delivered and confirmation is off
	// (NPG_HEALTH_PROBE=false). Taken as applied, as saves do.
	ReloadSignalled ReloadOutcome = "signalled"
)

// ReloadSnapshot is nginx's process tree just before a reload signal. A
// hook keeps it to ask ReloadTakenSince later whether nginx has loaded its
// files since. Opaque.
type ReloadSnapshot struct {
	before reloadSnapshot
}

// ReloadHooks lets one other part of the API hear of every reload signal,
// whichever path sends it: saves, SyncAll, rollbacks, DeferredSteps and the
// DNS include applier all reach nginx through reloadNginxInternal.
type ReloadHooks struct {
	// Before runs inside globalNginxMutex right before the pre-signal
	// process snapshot (also when confirmation is off), so whatever it
	// records is no newer than the files nginx can read when it takes the
	// signal. It may take only a leaf mutex. Its return value is handed back
	// to After as token.
	Before func() any
	// After runs once per signalled reload, once its outcome is known. A
	// reload signalled inside executeWithLock and confirmed there is
	// reported after the lock is released (accepted, rejected, unconfirmed,
	// not_checked). Outcomes known at the signal are reported where they
	// happen, inside the lock for in-lock reloads: signalled, unconfirmed
	// without a snapshot, superseded. So, like Before, it may take only a
	// leaf mutex, and anything slower must run in a goroutine of its own.
	// snap is nil unless the outcome is unconfirmed or not_checked and a
	// snapshot exists. A signal that failed (nothing was sent) gets no After
	// call.
	After func(token any, outcome ReloadOutcome, snap *ReloadSnapshot)
}

// before calls h.Before, if set.
func (h ReloadHooks) before() any {
	if h.Before == nil {
		return nil
	}
	return h.Before()
}

// after calls h.After, if set.
func (h ReloadHooks) after(token any, outcome ReloadOutcome, snap *ReloadSnapshot) {
	if h.After != nil {
		h.After(token, outcome, snap)
	}
}

// SetReloadHooks wires the reload hooks. Call it once at bootstrap, before
// the first reload.
func (m *Manager) SetReloadHooks(h ReloadHooks) {
	m.reloadHooks = h
}

// report tells the hooks the reload p was signalled for what became of it.
// The snapshot goes along when nginx's answer is still open.
func (p *pendingReload) report(outcome ReloadOutcome) {
	var snap *ReloadSnapshot
	if outcome == ReloadUnconfirmed || outcome == ReloadNotChecked {
		snap = &ReloadSnapshot{before: p.before}
	}
	p.hooks.after(p.token, outcome, snap)
}

// ReloadTakenSince reports whether nginx has loaded its files since snap was
// taken: a new master, or a child of the master that was not there. One read
// of nginx's processes, without the nginx lock, so it may run while another
// reload is being signalled or confirmed. A later reload that nginx took
// also counts: the files on disk only move forward.
//
// It is an error when confirmation is off (NPG_HEALTH_PROBE=false) or snap
// is nil: nothing can be compared.
func (m *Manager) ReloadTakenSince(ctx context.Context, snap *ReloadSnapshot) (bool, error) {
	if snap == nil {
		return false, errors.New("no process snapshot to compare with")
	}
	probe := m.reloadProbe
	if probe == nil {
		return false, errors.New("nginx reload confirmation is off")
	}
	master, children, err := probe.Children(ctx)
	if err != nil {
		return false, err
	}
	return snap.before.tookReload(master, children), nil
}
