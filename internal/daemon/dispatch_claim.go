package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Alerts of the compensation claim path (CD §8.6, §14).
const (
	AlertDispatchFalseNotice    = "dispatch_false_reject_notice"
	AlertDispatchClaimRefused   = "dispatch_compensation_claim_refused"
	AlertDispatchClaimMissed    = "dispatch_compensation_window_missed"
	AlertDispatchClaimDismissed = "dispatch_compensation_dismissed"

	alertChainObservationConflict = "dispatch_chain_observation_conflict"
)

// errClaimMoved stops a claim write whose record moved under it.
var errClaimMoved = errors.New("claim state moved")

// settleDeadlines decides, once per committed height, every accepted or
// pending-claim ticket whose D_ticket = ClaimFromHeight the height reached
// (CD §8.6, C3: the ticket's bound_change_height, never StreamState). At
// H >= D no record entry can land any more (KC §10.1.1 step 8), so
// QueryDispatchRecord is final (S6 Q1). The caller holds the work lock.
func (d *Dispatcher) settleDeadlines(ctx context.Context, height uint64) error {
	d.mu.Lock()
	fresh := height > d.settledAt
	if fresh {
		d.settledAt = height
	}
	d.mu.Unlock()
	if !fresh {
		return nil
	}
	recs, err := layout.AwaitingRecordDispatches(ctx, d.cfg.Store)
	if err != nil {
		d.retrySettlement()
		return fmt.Errorf("dispatcher: awaiting record: %w", err)
	}
	var params *chainclient.DispatchParamsSnapshot
	var errs []error
	for _, rec := range recs {
		if rec.ClaimFromHeight == 0 || height < rec.ClaimFromHeight {
			continue
		}
		if err := d.settleDeadline(ctx, rec, height, &params); err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	err = joinDispatchErrs(errs)
	if builderclient.IsRetryable(err) {
		// Retry on the next sweep, same height or not. A permanent refusal
		// (a ChainObservationConflict) is asked again at the next height.
		d.retrySettlement()
	}
	return err
}

func (d *Dispatcher) retrySettlement() {
	d.mu.Lock()
	d.settledAt = 0
	d.mu.Unlock()
}

func (d *Dispatcher) settleDeadline(ctx context.Context, rec layout.DispatchRecord, height uint64, params **chainclient.DispatchParamsSnapshot) error {
	snap, err := d.cfg.Chain.DispatchRecord(ctx, rec.SessionID[:], rec.OrderSequence)
	var why string
	switch {
	case err == nil:
		if winner, _ := hash32(snap.TicketHash); winner == rec.TicketHash {
			if snap.Winner != d.cfg.Operator {
				// Our ticket under another operator: never claimable, never
				// ours to deliver (M4).
				return d.conflictGrace(ctx, rec, snap, height, fmt.Errorf("ChainObservationConflict: the record names ticket %s with winner %s, not %s",
					rec.TicketHash, snap.Winner, d.cfg.Operator))
			}
			err := d.applyRecord(ctx, rec, snap, 0) // this ticket won: delivery resumes
			if err == nil || builderclient.IsRetryable(err) {
				return err
			}
			return d.conflictGrace(ctx, rec, snap, height, err)
		}
		why = fmt.Sprintf("order recorded with ticket %x for %s by D_ticket %d", snap.TicketHash, snap.Winner, rec.ClaimFromHeight)
	case errors.Is(err, chainclient.ErrNotFound):
		why = fmt.Sprintf("order not recorded by D_ticket %d", rec.ClaimFromHeight)
	default:
		return builderclient.Retryable(fmt.Errorf("query dispatch record: %w", err))
	}
	if *params == nil {
		// The claim window of the settling height (S6 Q2).
		p, err := d.cfg.Chain.DispatchParamsAt(ctx, height)
		if err != nil {
			return builderclient.Retryable(fmt.Errorf("dispatch params: %w", err))
		}
		*params = &p
	}
	return d.makeClaimable(ctx, rec, **params, why)
}

// conflictGrace handles a ticket the record names as winner but that cannot
// be applied for good (a ChainObservationConflict: the task view keeps
// disagreeing, or the record names another operator). It is asked again once
// per height and alerted once; once the height reaches
// max(D_ticket, recorded_height) + ConflictGraceBlocks it fails closed:
// inference stopped, ticket and task leases released, state Conflict. The
// record and its evidence are kept (the GC never drops a conflict's scope).
func (d *Dispatcher) conflictGrace(ctx context.Context, rec layout.DispatchRecord, snap chainclient.DispatchRecordSnapshot, height uint64, cause error) error {
	cur, err := layout.GetDispatchRecord(ctx, d.cfg.Store, rec.TicketHash)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	if cur.State != layout.DispatchAccepted && cur.State != layout.DispatchPendingClaim {
		return cause // already failed closed (applyRecord's own conflict) or settled
	}
	until := hrAddSat(max(rec.ClaimFromHeight, snap.RecordedHeight), d.cfg.ConflictGraceBlocks)
	if height >= until {
		return d.conflict(ctx, cur, fmt.Sprintf("fail-closed at %d after the conflict outlived its grace (until %d): %v", height, until, cause))
	}
	d.mu.Lock()
	first := !d.conflictAlerted[rec.TicketHash]
	d.conflictAlerted[rec.TicketHash] = true
	d.mu.Unlock()
	if first {
		d.cfg.Logger.Error("dispatch chain observation conflict", "alert", alertChainObservationConflict,
			"ticket", rec.TicketHash.String(), "fail_closed_at", until, "why", cause.Error())
	}
	return cause
}

// makeClaimable is CD §8.6 CLAIMABLE: stop inference (cancelling the
// execution in flight, without waiting for it, S6 Q8), release the lease and
// drop staged input. No receipt exists to void (S5 Q1: a ticket that is not
// the winner never signs one); the pre-record frames stay in the ticket
// scope until GC (S6 Q3). A winner-ineligible marker makes the ticket not
// claimable (KC §10.2 2c).
func (d *Dispatcher) makeClaimable(ctx context.Context, rec layout.DispatchRecord, p chainclient.DispatchParamsSnapshot, why string) error {
	row, err := d.cfg.Chain.DispatchWinnerIneligible(ctx, rec.TicketHash[:])
	switch {
	case err == nil:
		return d.release(ctx, rec, layout.DispatchNotClaimable,
			fmt.Sprintf("%s; DispatchWinnerIneligibleState %s at %d: not claimable", why, row.Reason, row.RejectedHeight))
	case !errors.Is(err, chainclient.ErrNotFound):
		return builderclient.Retryable(fmt.Errorf("query winner ineligibility: %w", err))
	}
	closeAt := hrAddSat(rec.ClaimFromHeight, p.CompensationClaimWindowBlocks)
	if closeAt <= rec.ClaimFromHeight {
		return d.release(ctx, rec, layout.DispatchNotClaimable, why+"; dispatch_compensation_claim_window_blocks is 0")
	}
	if err := d.releaseWith(ctx, rec, layout.DispatchClaimable, why, func(r *layout.DispatchRecord) { r.ClaimWindowCloseHeight = closeAt }); err != nil {
		return err
	}
	d.cfg.Logger.Warn("dispatch ticket claimable", "ticket", rec.TicketHash.String(), "builder", rec.Builder, "close", closeAt, "why", why)
	return nil
}

// updateLocked is UpdateDispatch under the work lock, for the paths that run
// outside it (SweepClaims, events). fn returning errClaimMoved leaves the
// record as it is and reports moved=true.
func (d *Dispatcher) updateLocked(ctx context.Context, ticket layout.StoredHash, fn func(*layout.DispatchRecord) error) (rec layout.DispatchRecord, moved bool, err error) {
	if err := d.lock(ctx); err != nil {
		return layout.DispatchRecord{}, false, err
	}
	defer d.unlock()
	rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, ticket, fn)
	if errors.Is(err, errClaimMoved) || errors.Is(err, store.ErrNotFound) {
		// Moved, or collected since it was read: nothing to write.
		return layout.DispatchRecord{}, true, nil
	}
	if err != nil {
		return layout.DispatchRecord{}, false, builderclient.Retryable(err)
	}
	return rec, false, nil
}

// onlyClaimable guards a write that is only right for a ticket still
// claimable.
func onlyClaimable(fn func(*layout.DispatchRecord)) func(*layout.DispatchRecord) error {
	return func(r *layout.DispatchRecord) error {
		if r.State != layout.DispatchClaimable {
			return errClaimMoved
		}
		fn(r)
		return nil
	}
}

// SweepClaims drives every unsettled claim one step (CD §8.6). Run calls it
// after Sweep, never concurrently with itself. It takes the work lock only
// around store writes: a claim Tx waits for inclusion and must not stall
// offers.
func (d *Dispatcher) SweepClaims(ctx context.Context) error {
	height, err := d.cfg.Chain.CommittedHeight(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("dispatcher: committed height: %w", err))
	}
	recs, err := layout.ClaimDispatches(ctx, d.cfg.Store)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("dispatcher: claims: %w", err))
	}
	var errs []error
	if err := d.recoverClaims(ctx, recs); err != nil {
		// Logged and carried on: a Builder whose pending list cannot be read
		// must not stop any claim from being submitted or settled.
		d.cfg.Logger.Warn("dispatch claim recovery incomplete", "err", err)
		errs = append(errs, err)
	}
	if recs, err = layout.ClaimDispatches(ctx, d.cfg.Store); err != nil {
		return builderclient.Retryable(fmt.Errorf("dispatcher: claims: %w", err))
	}
	for _, rec := range recs {
		var err error
		switch rec.State {
		case layout.DispatchClaimable:
			err = d.advanceClaim(ctx, rec, height)
		case layout.DispatchClaimPending:
			// Events are hints and may be lost; past the rebuttal deadline
			// the claim is re-read every ClaimRecheckBlocks (S6 Q7).
			if height > rec.RebuttalDeadlineHeight && height >= hrAddSat(rec.ClaimCheckedHeight, d.cfg.ClaimRecheckBlocks) {
				_, err = d.syncClaim(ctx, rec)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	return joinDispatchErrs(errs)
}

func (d *Dispatcher) advanceClaim(ctx context.Context, rec layout.DispatchRecord, height uint64) error {
	if rec.ClaimAttemptHeight != 0 {
		// An earlier submission may have landed though its outcome was lost.
		if landed, err := d.syncClaim(ctx, rec); err != nil || landed {
			return err
		}
		if height < hrAddSat(rec.ClaimAttemptHeight, d.cfg.ClaimRetryBlocks) {
			return nil
		}
	}
	if height >= rec.ClaimWindowCloseHeight {
		// A Tx lands at height+1 at the earliest: past the close (KC §10.2 2b).
		d.cfg.Logger.Error("compensation claim window missed", "alert", AlertDispatchClaimMissed, "ticket", rec.TicketHash.String())
		_, _, err := d.updateLocked(ctx, rec.TicketHash, onlyClaimable(func(r *layout.DispatchRecord) {
			r.State, r.StateReason = layout.DispatchNotClaimable, fmt.Sprintf("claim window closed at %d before a claim landed", rec.ClaimWindowCloseHeight)
		}))
		return err
	}
	if d.cfg.Tx == nil {
		// S6 Q12: stay claimable, warn once.
		d.mu.Lock()
		warn := !d.claimTxWarned
		d.claimTxWarned = true
		d.mu.Unlock()
		if warn {
			d.cfg.Logger.Error("claimable dispatch tickets but no Tx client: nothing is claimed", "ticket", rec.TicketHash.String())
		}
		return nil
	}
	if _, moved, err := d.updateLocked(ctx, rec.TicketHash, onlyClaimable(func(r *layout.DispatchRecord) { r.ClaimAttemptHeight = height })); err != nil || moved {
		return err
	}
	obs, err := d.submitClaim(ctx, rec)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("submit claim: %w", err))
	}
	if obs.Rejected {
		if !claimRefused(obs.RejectReason) {
			d.cfg.Logger.Warn("compensation claim not accepted; retrying", "ticket", rec.TicketHash.String(), "reason", obs.RejectReason)
			return nil
		}
		d.cfg.Logger.Error("chain refused the compensation claim", "alert", AlertDispatchClaimRefused, "ticket", rec.TicketHash.String(), "reason", obs.RejectReason)
		d.cfg.Logger.Error("dispatch chain observation conflict", "alert", alertChainObservationConflict,
			"ticket", rec.TicketHash.String(), "why", "the chain refused a claim this node settled as claimable: "+obs.RejectReason)
		_, _, err := d.updateLocked(ctx, rec.TicketHash, onlyClaimable(func(r *layout.DispatchRecord) {
			r.State, r.StateReason = layout.DispatchNotClaimable, "ChainObservationConflict: the chain refused the claim: "+obs.RejectReason
		}))
		return err
	}
	if _, moved, err := d.updateLocked(ctx, rec.TicketHash, onlyClaimable(func(r *layout.DispatchRecord) { r.ClaimTxHash = obs.TxHash })); err != nil || moved {
		return err
	}
	_, err = d.syncClaim(ctx, rec)
	return err
}

// submitClaim broadcasts MsgClaimDispatchCompensation from the three stored
// originals, under the current service address (CD §8.6). A rotated key
// activates only after every claim window (PHASE1_CONTRACT "Delayed key
// cutover", S6 Q10), so the current key is the one the ticket was accepted
// under.
func (d *Dispatcher) submitClaim(ctx context.Context, rec layout.DispatchRecord) (txclient.Observation, error) {
	msg := &taskv1.MsgClaimDispatchCompensation{Order: &taskv1.SignedOrderV2{}, Ticket: &taskv1.DispatchTicketV1{},
		Accept: &taskv1.DispatchAcceptV1{}, SubmitterAddress: d.cfg.ServiceAddress}
	for _, p := range []struct {
		raw []byte
		m   proto.Message
	}{{rec.SignedOrder, msg.Order}, {rec.Ticket, msg.Ticket}, {rec.Accept, msg.Accept}} {
		if err := proto.Unmarshal(p.raw, p.m); err != nil {
			return txclient.Observation{}, fmt.Errorf("stored %T: %w", p.m, err)
		}
	}
	payload, err := txclient.MarshalDispatchMessage(txclient.MsgClaimDispatchCompensation, msg)
	if err != nil {
		return txclient.Observation{}, err
	}
	return d.cfg.Tx.Submit(ctx, txclient.Request{
		TaskID: hex.EncodeToString(rec.TaskID[:]), SessionID: hex.EncodeToString(rec.SessionID[:]),
		Kind: txclient.MsgClaimDispatchCompensation, Payload: payload, DeadlineHeight: rec.ClaimWindowCloseHeight,
		MaterialDigest: codec.HashWithDomain("TRUEOPEN_DISPATCH_COMPENSATION_CLAIM_V1", rec.TicketHash[:]),
	})
}

// claimRefused reports a rejection the chain will repeat for this claim
// (S6 Q5). The ERR_* literals are not frozen in wire yet.
func claimRefused(reason string) bool {
	return strings.Contains(reason, "ERR_COMPENSATION_NOT_CLAIMABLE") || strings.Contains(reason, "ERR_COMPENSATION_RECORD_PRUNED")
}

// syncClaim reads QueryDispatchCompensationClaim, the authority, and moves
// rec to it. landed=false: no claim on chain.
func (d *Dispatcher) syncClaim(ctx context.Context, rec layout.DispatchRecord) (bool, error) {
	c, err := d.cfg.Chain.DispatchCompensationClaim(ctx, rec.TicketHash[:])
	if errors.Is(err, chainclient.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, builderclient.Retryable(fmt.Errorf("query claim: %w", err))
	}
	return true, d.applyClaim(ctx, rec, c)
}

var claimStates = map[taskv1.DispatchCompensationClaimStatusV1]layout.DispatchState{
	taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL: layout.DispatchClaimPending,
	taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID:             layout.DispatchClaimPaid,
	taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_DISMISSED:        layout.DispatchClaimDismissed,
}

func (d *Dispatcher) applyClaim(ctx context.Context, rec layout.DispatchRecord, c chainclient.DispatchClaimSnapshot) error {
	if !bytes.Equal(c.TaskID, rec.TaskID[:]) || c.Worker != d.cfg.Operator || c.Builder != rec.Builder || c.OrderSequence != rec.OrderSequence {
		d.cfg.Logger.Error("dispatch chain observation conflict", "alert", "dispatch_chain_observation_conflict",
			"ticket", rec.TicketHash.String(), "why", "compensation claim names another task, worker or Builder")
		return fmt.Errorf("ChainObservationConflict: claim of ticket %s names task %x, worker %s, Builder %s", rec.TicketHash, c.TaskID, c.Worker, c.Builder)
	}
	next, ok := claimStates[c.Status]
	if !ok {
		return fmt.Errorf("compensation claim of ticket %s has status %s", rec.TicketHash, c.Status)
	}
	var before layout.DispatchState
	stored, moved, err := d.updateLocked(ctx, rec.TicketHash, func(r *layout.DispatchRecord) error {
		before = r.State
		if !r.State.Claiming() {
			return errClaimMoved // settled already
		}
		r.ClaimCheckedHeight = c.Height
		if r.State == next {
			return nil
		}
		r.State, r.StateReason = next, fmt.Sprintf("compensation claim %s at height %d", c.Status, c.Height)
		r.ClaimedHeight, r.RebuttalDeadlineHeight, r.ClaimAmount = c.ClaimedHeight, c.RebuttalDeadlineHeight, c.Amount
		r.PaidAmount, r.UnfilledAmount, r.RebuttedBy, r.ClaimResolvedHeight = c.PaidAmount, c.UnfilledAmount, c.RebuttedBy, c.ResolvedHeight
		return nil
	})
	if err != nil || moved {
		return err
	}
	if stored.State == layout.DispatchClaimDismissed && before != layout.DispatchClaimDismissed {
		// This node never signs both accept and reject (CD §4.2.0), so a
		// rebuttal claims TIMEOUT or REVOKED: recorded and alerted, never
		// claimed again (S6 Q6).
		d.cfg.Logger.Warn("compensation claim dismissed", "alert", AlertDispatchClaimDismissed, "ticket", rec.TicketHash.String(), "rebutted_by", c.RebuttedBy)
	}
	return nil
}

// recoverClaims runs once per process: every page of
// DispatchCompensationClaimsByBuilder at one height per Builder with local
// claims, then a single read of each local pending claim the list no longer
// shows (PHASE1_CONTRACT "Event routing and gap recovery", S6 Q7).

var _ DispatchEventObserver = (*Dispatcher)(nil)

// ObserveDispatchEvent applies a compensation event for this node's tickets
// by re-reading the claim (CD §8.6: the status comes from the Query, events
// are hints). A claim event the Query does not show yet is retryable, so the
// poller page is retried.
func (d *Dispatcher) ObserveDispatchEvent(ctx context.Context, f DispatchEventFact) error {
	switch f.Type {
	case chainclient.KeeperEventDispatchCompensationClaimed, chainclient.KeeperEventDispatchCompensationPaid, chainclient.KeeperEventDispatchCompensationRebutted:
	default:
		return nil
	}
	if f.Worker != d.cfg.Operator {
		return nil
	}
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, f.TicketHash)
	if errors.Is(err, store.ErrNotFound) {
		d.cfg.Logger.Warn("compensation event for a ticket this node does not hold", "ticket", f.TicketHash.String(), "event", f.Type)
		return nil
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	if !rec.State.Claiming() {
		return nil
	}
	landed, err := d.syncClaim(ctx, rec)
	if err != nil {
		return err
	}
	if !landed {
		return builderclient.Retryable(fmt.Errorf("%s for ticket %s at %d: the claim query lags", f.Type, f.TicketHash, f.Height))
	}
	return nil
}

// recoverClaims covers the gap of a restart, once per process: the Builders
// with local claims at the first sweep are planned, and for each every page
// of DispatchCompensationClaimsByBuilder is read at one height, then each
// local pending claim the list no longer shows is read singly
// (PHASE1_CONTRACT "Event routing and gap recovery", S6 Q7). Claims this
// process makes later need no recovery. A Builder whose recovery failed
// transiently stays planned for the next sweep; a malformed Keeper answer or
// a permanent refusal is reported and not retried. Errors never hold the
// advance of other claims back.
func (d *Dispatcher) recoverClaims(ctx context.Context, recs []layout.DispatchRecord) error {
	d.mu.Lock()
	if d.recoveryDue == nil {
		d.recoveryDue = map[string]bool{}
		for _, rec := range recs {
			if rec.State == layout.DispatchClaimPending || rec.ClaimAttemptHeight != 0 {
				d.recoveryDue[rec.Builder] = true
			}
		}
	}
	byBuilder := map[string][]layout.DispatchRecord{}
	for _, rec := range recs {
		if (rec.State == layout.DispatchClaimPending || rec.ClaimAttemptHeight != 0) && d.recoveryDue[rec.Builder] {
			byBuilder[rec.Builder] = append(byBuilder[rec.Builder], rec)
		}
	}
	for builder := range d.recoveryDue {
		if len(byBuilder[builder]) == 0 {
			delete(d.recoveryDue, builder) // its claims settled meanwhile
		}
	}
	d.mu.Unlock()
	var errs []error
	for builder, local := range byBuilder {
		err := d.recoverBuilderClaims(ctx, builder, local)
		if !builderclient.IsRetryable(err) {
			d.mu.Lock()
			delete(d.recoveryDue, builder)
			d.mu.Unlock()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("recover claims of %s: %w", builder, err))
		}
	}
	return joinDispatchErrs(errs)
}

func (d *Dispatcher) recoverBuilderClaims(ctx context.Context, builder string, local []layout.DispatchRecord) error {
	_, pending, err := d.cfg.Chain.DispatchCompensationClaimsByBuilder(ctx, builder)
	switch {
	case errors.Is(err, chainclient.ErrInvalidClaimAnswer):
		return err // the same answer comes back: permanent
	case err != nil:
		return builderclient.Retryable(err)
	}
	open := map[layout.StoredHash]chainclient.DispatchClaimSnapshot{}
	for _, c := range pending {
		if t, ok := hash32(c.TicketHash); ok && c.Worker == d.cfg.Operator {
			open[t] = c
		}
	}
	var errs []error
	for _, rec := range local {
		var err error
		if c, ok := open[rec.TicketHash]; ok {
			if rec.State != layout.DispatchClaimPending {
				err = d.applyClaim(ctx, rec, c) // landed while away
			}
		} else if rec.State == layout.DispatchClaimPending {
			_, err = d.syncClaim(ctx, rec) // resolved while away
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	return joinDispatchErrs(errs)
}
