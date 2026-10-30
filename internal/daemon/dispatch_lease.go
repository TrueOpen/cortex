package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// DispatchLeases is the Worker TaskProfileLease ledger (CD §5.2 W3, §10): one
// lease per accepted, not yet released ticket, never more than capacity. It
// answers H3 (S3's HandraiseLocal.FreeSlots). One ledger per store.
type DispatchLeases struct {
	st       *store.Store
	capacity uint32

	mu   sync.Mutex
	held uint32
}

// NewDispatchLeases counts the leases already held, so a restart resumes
// with the right free slot count.
func NewDispatchLeases(ctx context.Context, st *store.Store, capacity uint32) (*DispatchLeases, error) {
	if st == nil {
		return nil, errors.New("dispatch leases: store is required")
	}
	if capacity == 0 {
		return nil, errors.New("dispatch leases: capacity must be at least 1")
	}
	held, err := layout.CountWorkerLeases(ctx, st)
	if err != nil {
		return nil, fmt.Errorf("dispatch leases: count: %w", err)
	}
	return &DispatchLeases{st: st, capacity: capacity, held: held}, nil
}

// Acquire takes lease if a slot is free; idempotent per ticket.
func (l *DispatchLeases) Acquire(ctx context.Context, lease layout.WorkerLease) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ok, created, err := layout.AcquireWorkerLease(ctx, l.st, lease, l.capacity)
	if err != nil {
		return false, err
	}
	if created {
		l.held++
	}
	return ok, nil
}

// Release returns ticket's lease; released reports it was held.
func (l *DispatchLeases) Release(ctx context.Context, ticket layout.StoredHash) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	released, err := layout.ReleaseWorkerLease(ctx, l.st, ticket)
	if err != nil {
		return false, err
	}
	if released && l.held > 0 {
		l.held--
	}
	return released, nil
}

// Rebind moves ticket's lease to (task_id, WORKER) once the record lands; the
// slot count is unchanged.
func (l *DispatchLeases) Rebind(ctx context.Context, ticket, taskID layout.StoredHash) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return layout.RebindWorkerLease(ctx, l.st, ticket, taskID)
}

// ReleaseTask returns a recorded task's (task_id, WORKER) lease; released
// reports it was held.
func (l *DispatchLeases) ReleaseTask(ctx context.Context, taskID layout.StoredHash) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	released, err := layout.ReleaseWorkerTaskLease(ctx, l.st, taskID)
	if err != nil {
		return false, err
	}
	if released && l.held > 0 {
		l.held--
	}
	return released, nil
}

// FreeSlots is capacity minus held leases (CD §4.2.0 free_slot_count). It
// reads only the in-memory count, so it takes no context; WithLeaseSlots adapts
// it to HandraiseLocal.FreeSlots(ctx).
func (l *DispatchLeases) FreeSlots() (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held >= l.capacity {
		return 0, true
	}
	return l.capacity - l.held, true
}

// WithLeaseSlots is the lease-backed HandraiseLocal.FreeSlots(ctx) (Q10, Q18):
// H3 comes from the ledger while base still decides readiness, so base not
// ready keeps the offer at zero. S9 wires it as the StandingHandraiser's Local.
func WithLeaseSlots(base HandraiseLocal, leases *DispatchLeases) HandraiseLocal {
	return leaseSlotsLocal{HandraiseLocal: base, leases: leases}
}

type leaseSlotsLocal struct {
	HandraiseLocal
	leases *DispatchLeases
}

func (l leaseSlotsLocal) FreeSlots(ctx context.Context) (uint32, bool) {
	if _, ok := l.HandraiseLocal.FreeSlots(ctx); !ok {
		return 0, false
	}
	return l.leases.FreeSlots()
}
