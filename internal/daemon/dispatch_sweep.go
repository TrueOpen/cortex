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

// Sweep walks accepted tickets whose input is not committed, from the slim
// open index (M5), loading a full record only for a ticket it acts on:
//   - accept not enqueued yet and the deadline not passed: enqueue it (and the
//     first input request);
//   - accept certainly never transmitted and the deadline passed:
//     accept-unsent, lease released, never resent (C4);
//   - accept that may have been transmitted (WasSent, or an enqueue whose
//     outcome was never recorded, Q9), or a ticket past accepted
//     (pending-claim, recorded), whose accept the Builder holds: re-request
//     input after InputRetryEvery or a rebind, until the committed height
//     reaches D_ticket, or infer_deadline_height once recorded. It stays
//     accepted past the deadline; S6 settles it.
//
// Then it gives back the lease of any ticket that holds no duty and whose
// deadline passed: an offer left unanswered by a failed attempt (I1). Last,
// it re-asks the chain for the record of tickets whose Builder said
// RECORDED (sweepRecords).
func (d *Dispatcher) Sweep(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	entries, err := layout.OpenDispatchEntries(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: open tickets: %w", err)
	}
	d.mu.Lock()
	rebound := d.rebound
	d.rebound = map[string]bool{}
	d.mu.Unlock()
	now := d.cfg.Now()
	var errs []error
	// The claim-height stop needs the chain height; without it no input is
	// re-requested this pass.
	height, herr := d.chain.CommittedHeight(ctx)
	if herr != nil {
		errs = append(errs, fmt.Errorf("committed height: %w", herr))
	}
	for _, e := range entries {
		enq, ok := d.cfg.Builders[e.Builder]
		if !ok {
			continue
		}
		maybeSent := e.State != layout.DispatchAccepted || (e.AcceptSeq != 0 && enq.WasSent(e.AcceptSeq)) || (e.AcceptSeq == 0 && e.AcceptEnqueuing)
		live := now.Before(d.deadlineOf(e.TicketHash, e.AcceptDeadlineUnixMs))
		due := rebound[e.Builder] || now.Sub(time.UnixMilli(e.InputRequestedAtUnixMs)) >= d.cfg.InputRetryEvery
		// TODO(S6): at D_ticket (ClaimFromHeight) a ticket whose input never
		// arrived becomes S6's (PENDING_CLAIM); the sweep stops asking (I8).
		stop := e.ClaimFromHeight
		if e.InferDeadlineHeight != 0 {
			stop = e.InferDeadlineHeight // recorded: the input is due until the infer deadline
		}
		claimable := herr != nil || height >= stop
		var act func(layout.DispatchRecord) error
		switch {
		case e.State == layout.DispatchAccepted && e.AcceptSeq == 0 && live:
			act = func(rec layout.DispatchRecord) error { return d.sendAccept(ctx, enq, rec) }
		case !maybeSent && !live:
			act = func(rec layout.DispatchRecord) error {
				return d.release(ctx, rec, layout.DispatchAcceptUnsent, "the accept was never transmitted before the accept deadline (C4); it is not resent")
			}
		case maybeSent && due && !claimable:
			act = func(rec layout.DispatchRecord) error {
				return d.requestInput(ctx, enq, rec, now.Add(d.cfg.InputRequestTTL))
			}
		}
		if act == nil {
			continue
		}
		rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, e.TicketHash)
		if err == nil {
			err = act(rec)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", e.TicketHash, err))
		}
	}
	if err := d.releaseStaleLeases(ctx, now); err != nil {
		errs = append(errs, err)
	}
	d.pruneDeadlines(now)
	if herr == nil {
		if err := d.sweepRecords(ctx, height); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// releaseStaleLeases applies recoverLeases' rule while running, but only past
// the deadline: before it a redelivered offer may still reuse the lease.
func (d *Dispatcher) releaseStaleLeases(ctx context.Context, now time.Time) error {
	tickets, err := layout.WorkerTicketLeases(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: list leases: %w", err)
	}
	var errs []error
	for _, ticket := range tickets {
		rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
		switch {
		case err != nil && !errors.Is(err, store.ErrNotFound):
			errs = append(errs, fmt.Errorf("lease %s: %w", ticket, err))
			continue
		case err == nil && (rec.State.HoldsDuty() || now.Before(d.acceptDeadline(rec))):
			continue
		}
		if err := d.releaseLease(ctx, ticket); err != nil {
			errs = append(errs, fmt.Errorf("lease %s: %w", ticket, err))
			continue
		}
		d.cfg.Logger.Info("released the lease of an offer left unanswered", "ticket", ticket.String())
	}
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

// recoverLeases releases pre-record leases whose ticket holds no duty: a
// crash between a state change and its release, or an offer that will be
// redelivered and re-evaluated anyway. An accepted ticket keeps its lease
// whatever became of its accept: after a restart an earlier process may have
// sent it (Q9). A recorded ticket whose lease a crash left on the ticket key
// finishes its move to (task_id, WORKER).
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
		if err == nil && rec.State == layout.DispatchRecorded {
			if _, err := d.cfg.Leases.Rebind(ctx, ticket, rec.TaskID); err != nil {
				return fmt.Errorf("dispatcher: rebind lease %s: %w", ticket, err)
			}
			continue
		}
		if err == nil && rec.State.HoldsDuty() {
			continue
		}
		if _, err := d.cfg.Leases.Release(ctx, ticket); err != nil {
			return fmt.Errorf("dispatcher: release lease %s: %w", ticket, err)
		}
		d.cfg.Logger.Info("released a lease left by an interrupted dispatch", "ticket", ticket.String())
	}
	return nil
}
