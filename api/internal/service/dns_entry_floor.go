package service

import (
	"context"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// A name's generation is how a reload token says which content of the name's
// files nginx read, so one generation must never stand for two contents. A
// row starts again at generation 0 when its name is added back after the
// cleanup deleted the old row, and a restore can write a row with a lower
// generation, while files of the old row still carry its generations. A
// reload that read one of those files would then be taken for having read
// the new row's content: MarkApplied would record the new row as applied, or
// clear its revocation, while nginx still runs the old file. So the
// service's transactions never let a row's generation sit below the highest
// generation the process still holds for its name, in the disk table or in
// nginxView, and a row they create starts above it. A row that goes back is
// raised above it too, not to it: a generation the old files carry must
// not name the new row's content.

// dnsFloorStore is the state store as the service uses it: its transactions
// hand their callbacks a dnsFloorTx.
type dnsFloorStore struct {
	dnsStateStore
	svc *DNSEntryService
}

// WithTx runs fn on a dnsFloorTx. The service calls it under dnsMu, so the
// disk table does not change while the transaction runs.
func (f *dnsFloorStore) WithTx(ctx context.Context, fn func(tx repository.DNSEntryTx) error) error {
	held := f.svc.heldGenerations()
	return f.dnsStateStore.WithTx(ctx, func(tx repository.DNSEntryTx) error {
		return fn(&dnsFloorTx{DNSEntryTx: tx, held: held, read: make(map[string]bool)})
	})
}

// dnsFloorTx raises generations that would go back. A row read below the
// highest generation held for its name is raised above it, and written so
// whether or not the transaction writes the row again. A row the transaction
// creates (one it did not read) is written above it. Rows at or above it, and
// names nothing is held for, keep their generation. A raise changes the
// generation only: the row reads as not applied until a reload reads files
// written with the new generation.
type dnsFloorTx struct {
	repository.DNSEntryTx
	held map[string]int64 // name → the highest generation held for it
	read map[string]bool  // names this transaction read a row of
}

func (t *dnsFloorTx) GetStates(ctx context.Context, names []string) (map[string]model.DNSEntryState, error) {
	rows, err := t.DNSEntryTx.GetStates(ctx, names)
	if err != nil {
		return nil, err
	}
	for name, st := range rows {
		t.read[name] = true
		if h, ok := t.held[name]; ok && st.Generation < h {
			st.Generation = h + 1
			if err := t.DNSEntryTx.UpsertState(ctx, st); err != nil {
				return nil, err
			}
			rows[name] = st
		}
	}
	return rows, nil
}

func (t *dnsFloorTx) UpsertState(ctx context.Context, st model.DNSEntryState) error {
	if h, ok := t.held[st.Hostname]; ok && !t.read[st.Hostname] && st.Generation <= h {
		st.Generation = h + 1
	}
	return t.DNSEntryTx.UpsertState(ctx, st)
}

// heldGenerations returns, per name, the highest generation the process
// holds for it: in the disk table (a file it wrote, or found as it was when
// a write failed) and in nginxView. Caller holds dnsMu.
func (s *DNSEntryService) heldGenerations() map[string]int64 {
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	held := make(map[string]int64, len(s.nginxView))
	for _, e := range s.disk {
		if g, ok := held[e.Name]; !ok || e.Gen > g {
			held[e.Name] = e.Gen
		}
	}
	for name, v := range s.nginxView {
		if g, ok := held[name]; !ok || v.Gen > g {
			held[name] = v.Gen
		}
	}
	return held
}

// dnsNewRow is dnsNewState for a row tx creates. In a dnsFloorTx the row
// starts above the generations held for name, as the transaction writes it,
// so the files written from it carry the generation it is stored with.
func dnsNewRow(tx repository.DNSEntryTx, name string, now time.Time, sw dnsSwitch) model.DNSEntryState {
	st := dnsNewState(name, now, sw)
	if ft, ok := tx.(*dnsFloorTx); ok {
		if h, held := ft.held[name]; held && st.Generation <= h {
			st.Generation = h + 1
		}
	}
	return st
}
