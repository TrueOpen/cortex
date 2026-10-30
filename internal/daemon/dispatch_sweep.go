package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// deadlineMemory is how long past its C4 deadline an in-memory deadline is
// kept. Persisted records carry their own; this only bounds the entries of
// offers that were never persisted (dropped, or failed before W1).
const deadlineMemory = 10 * time.Minute

// Run sweeps every SweepEvery and on Rebound until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) error {
	tick := time.NewTicker(d.cfg.SweepEvery)
	defer tick.Stop()
	for {
		if err := d.Sweep(ctx); err != nil && ctx.Err() == nil {
			d.cfg.Logger.Warn("dispatch sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		case <-d.wake:
		}
	}
}

// Rebound asks for the input of builder's open tickets again on the new
// binding. S9 composes it with StandingHandraiser.Rebound as the Session's
// OnBound; it never blocks.
func (d *Dispatcher) Rebound(builder string) {
	d.mu.Lock()
	d.rebound[builder] = true
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Sweep walks accepted tickets whose input is not committed:
//   - accept not enqueued yet and the deadline not passed: enqueue it (and the
//     first input request);
//   - accept certainly never transmitted and the deadline passed:
//     accept-unsent, lease released, never resent (C4);
//   - accept that may have been transmitted (WasSent, or an enqueue whose
//     outcome was never recorded, Q9): re-request input after
//     InputRetryEvery or a rebind. It stays accepted past the deadline; S6
//     settles it at D_ticket.
func (d *Dispatcher) Sweep(ctx context.Context) error {
	d.work.Lock()
	defer d.work.Unlock()
	recs, err := layout.OpenDispatches(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: open tickets: %w", err)
	}
	d.mu.Lock()
	rebound := d.rebound
	d.rebound = map[string]bool{}
	d.mu.Unlock()
	now := d.cfg.Now()
	var errs []error
	for _, rec := range recs {
		enq, ok := d.cfg.Builders[rec.Builder]
		if !ok {
			continue
		}
		maybeSent := (rec.AcceptSeq != 0 && enq.WasSent(rec.AcceptSeq)) || (rec.AcceptSeq == 0 && rec.AcceptEnqueuing)
		live := now.Before(d.acceptDeadline(rec))
		var err error
		switch {
		case rec.AcceptSeq == 0 && live:
			err = d.sendAccept(ctx, enq, rec)
		case !maybeSent && !live:
			err = d.release(ctx, rec, layout.DispatchAcceptUnsent, "the accept was never transmitted before the accept deadline (C4); it is not resent")
		case maybeSent && (rebound[rec.Builder] || now.Sub(time.UnixMilli(rec.InputRequestedAtUnixMs)) >= d.cfg.InputRetryEvery):
			err = d.requestInput(ctx, enq, rec, now.Add(d.cfg.InputRequestTTL))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	d.pruneDeadlines(now)
	return errors.Join(errs...)
}

// pruneDeadlines drops in-memory C4 deadlines long past.
func (d *Dispatcher) pruneDeadlines(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for ticket, at := range d.deadline {
		if now.Sub(at) > deadlineMemory {
			delete(d.deadline, ticket)
		}
	}
}

// recoverLeases releases pre-record leases whose ticket is not accepted: a
// crash between a state change and its release, or an offer that will be
// redelivered and re-evaluated anyway. An accepted ticket keeps its lease
// whatever became of its accept: after a restart an earlier process may have
// sent it (Q9).
func (d *Dispatcher) recoverLeases(ctx context.Context) error {
	tickets, err := layout.WorkerTicketLeases(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: list leases: %w", err)
	}
	for _, ticket := range tickets {
		rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("dispatcher: lease %s: %w", ticket, err)
		}
		if err == nil && rec.State == layout.DispatchAccepted {
			continue
		}
		if _, err := d.cfg.Leases.Release(ctx, ticket); err != nil {
			return fmt.Errorf("dispatcher: release lease %s: %w", ticket, err)
		}
		d.cfg.Logger.Info("released a lease left by an interrupted dispatch", "ticket", ticket.String())
	}
	return nil
}
