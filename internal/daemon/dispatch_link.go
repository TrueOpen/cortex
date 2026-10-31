package daemon

import (
	"context"
	"sync/atomic"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// DispatchLink lets the TaskRunner, built before the Dispatcher and the
// OmissionWatcher that take it as their Infer, reach them: TaskRunnerConfig
// takes the link (DispatchRecords, DispatchEvents, ReleaseDispatchLease) and
// Bind attaches the plane before any runner or poller starts. Unbound, every
// call is retryable.
type DispatchLink struct{ plane atomic.Pointer[DispatchPlane] }

func NewDispatchLink() *DispatchLink { return &DispatchLink{} }

// Bind attaches the plane; call it before any runner or poller starts.
func (l *DispatchLink) Bind(p *DispatchPlane) { l.plane.Store(p) }

func (l *DispatchLink) bound() (*DispatchPlane, error) {
	if p := l.plane.Load(); p != nil {
		return p, nil
	}
	return nil, chainclient.Retryable(builderclient.Retryable(errPlaneNotBound))
}

func (l *DispatchLink) ObserveDispatchRecorded(ctx context.Context, f DispatchRecordedFact) error {
	p, err := l.bound()
	if err != nil {
		return err
	}
	return p.records.ObserveDispatchRecorded(ctx, f)
}

func (l *DispatchLink) ObserveDispatchEvent(ctx context.Context, f DispatchEventFact) error {
	p, err := l.bound()
	if err != nil {
		return err
	}
	return p.events.ObserveDispatchEvent(ctx, f)
}

// ReleaseTaskLease is TaskRunnerConfig.ReleaseDispatchLease (S5); it takes
// no runner lock.
func (l *DispatchLink) ReleaseTaskLease(ctx context.Context, taskID layout.StoredHash) error {
	p, err := l.bound()
	if err != nil {
		return err
	}
	return p.dispatcher.ReleaseTaskLease(ctx, taskID)
}

var (
	_ DispatchRecordObserver = (*DispatchLink)(nil)
	_ DispatchEventObserver  = (*DispatchLink)(nil)
)
