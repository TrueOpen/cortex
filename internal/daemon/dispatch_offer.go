package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// HandleOffer answers one DispatchOfferV1 from builder, the stream's
// authenticated peer (CD §5.1 checks 1–7, §5.2 W1–W4). Every chain fact is
// read at one committed height, before the work lock is taken (I3); under the
// lock the record is checked again and the answer is persisted and enqueued.
func (d *Dispatcher) HandleOffer(ctx context.Context, builder string, offer *nexusv1.DispatchOfferV1) error {
	enq, ok := d.cfg.Builders[builder]
	if !ok {
		return d.drop(ctx, builder, layout.StoredHash{}, fmt.Errorf("offer from unconfigured Builder %s", builder))
	}
	t, so := offer.GetTicket(), offer.GetSignedOrder()
	if t == nil || so.GetOrder() == nil {
		return d.drop(ctx, builder, layout.StoredHash{}, errors.New("offer carries no ticket or no signed order"))
	}
	digest, err := dispatchwire.Digest(t)
	if err != nil {
		return d.drop(ctx, builder, layout.StoredHash{}, err)
	}
	ticket := layout.StoredHash(digest)
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
	switch {
	case err == nil && rec.State != layout.DispatchOffered:
		// The first answer is final; a redelivery is answered from the
		// record and never re-evaluated (CD §7.2 I1a).
		if err := d.lock(ctx); err != nil {
			return err
		}
		defer d.unlock()
		return d.resumeCurrent(ctx, enq, ticket)
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	deadline := d.noteReceipt(ticket, t.GetAcceptDeadlineMs(), rec, err == nil)
	if !d.cfg.Now().Add(d.cfg.AcceptSignMargin).Before(deadline) {
		// C4, before any chain read: nothing could be signed in time.
		if err := d.lock(ctx); err != nil {
			return err
		}
		defer d.unlock()
		return d.drop(ctx, builder, ticket, fmt.Errorf("accept_deadline_ms %d leaves no time to answer (C4)", t.GetAcceptDeadlineMs()))
	}
	ev, dropErr, err := d.evaluateOffer(ctx, builder, t, so)
	if err != nil {
		return err
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if dropErr != nil {
		return d.drop(ctx, builder, ticket, dropErr)
	}
	switch rec, err = layout.GetDispatchRecord(ctx, d.cfg.Store, ticket); {
	case err == nil && rec.State != layout.DispatchOffered:
		return d.resume(ctx, enq, rec) // answered or revoked while we read
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}

	// W1: ticket and order are durable before any answer.
	rec, err = d.persistOffer(ctx, builder, ticket, t, so.GetOrder(), ev, deadline)
	if errors.Is(err, layout.ErrConflict) {
		return d.drop(ctx, builder, ticket, err)
	}
	if err != nil {
		return builderclient.Retryable(err)
	}
	if rec.State != layout.DispatchOffered {
		return d.resume(ctx, enq, rec) // its revoke arrived first
	}
	if ev.verdict != nil {
		return d.reject(ctx, enq, rec, t, ev.nonce, ev.verdict)
	}
	// W3: only a round that passed every check replaces an older one, and
	// before capacity is judged (M2).
	if err := d.supersede(ctx, builder, t, ticket); err != nil {
		return err
	}

	// Check 5 and W3: the lease is the capacity reservation.
	ok, err = d.cfg.Leases.Acquire(ctx, layout.WorkerLease{
		TicketHash: ticket, TaskID: rec.TaskID, ModelID: rec.ModelID, ProfileVersion: rec.ProfileVersion,
		Builder: builder, ExpiryHeight: rec.ClaimFromHeight,
	})
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("acquire lease: %w", err))
	}
	if !ok {
		// CD §5.1: a capacity change re-signs the standing handraise before
		// the reject, so a reject never contradicts the newest offer. Only
		// this Builder's handraise matters here.
		if cur, found := d.cfg.Handraise.Current(builder); found && !cur.Withdrawn && cur.State.FreeSlots > 0 {
			if err := d.cfg.Handraise.Refresh(ctx, builder); err != nil {
				return builderclient.Retryable(fmt.Errorf("re-sign the standing handraise before a capacity reject: %w", err))
			}
		}
		return d.reject(ctx, enq, rec, t, ev.nonce, refuse(reasonNoCapacity, classNoFreeSlot, "no free slot"))
	}
	return d.accept(ctx, enq, rec, t, ev.nonce)
}

// offerEval is what one offer evaluation read and decided before the lock.
type offerEval struct {
	traw, oraw []byte // ticket and order exactly as received, encoded once
	params     chainclient.DispatchParamsSnapshot
	nonce      uint64   // this node's current service_authorization_nonce
	verdict    *verdict // nil: accept if capacity allows
}

// evaluateOffer runs check 1, the rotation stop (issue #83) and checks 2–7
// at one committed height, without the work lock. drop is a check-1 failure
// (no reject is signed); err is a failed read (retryable).
func (d *Dispatcher) evaluateOffer(ctx context.Context, builder string, t *taskv1.DispatchTicketV1, so *taskv1.SignedOrderV2) (ev offerEval, drop, err error) {
	height, err := d.chain.CommittedHeight(ctx)
	if err != nil {
		return ev, nil, builderclient.Retryable(fmt.Errorf("committed height: %w", err))
	}
	// Check 1: legitimacy.
	if err := d.checkHandraise(builder, height); err != nil {
		return ev, err, nil
	}
	tc, err := d.ticketContext(ctx, builder, t, so.GetOrder(), height)
	if err != nil {
		if builderclient.IsRetryable(err) {
			return ev, nil, err
		}
		return ev, err, nil
	}
	if err := dispatchwire.CheckTicket(t, tc); err != nil {
		return ev, err, nil
	}
	if ev.traw, err = dispatchwire.Raw(t); err != nil {
		return ev, err, nil
	}
	if ev.oraw, err = dispatchwire.Raw(so); err != nil {
		return ev, err, nil
	}
	if ev.params, err = d.chain.DispatchParamsAt(ctx, height); err != nil {
		return ev, nil, builderclient.Retryable(fmt.Errorf("dispatch params: %w", err))
	}
	// issue #83: after check 1, before any accept. A pending rotation of this
	// node's service key refuses new tickets with a signed NO_CAPACITY reject
	// (Q3); accepted ones finish under the current (old) key.
	key, err := d.chain.CurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, d.cfg.Operator, height)
	if err != nil {
		return ev, nil, builderclient.Retryable(fmt.Errorf("Cortex service key: %w", err))
	}
	if key.Status != "ACTIVE" {
		return ev, fmt.Errorf("this node's service key is %s; nothing can be signed", key.Status), nil
	}
	ev.nonce = key.AuthorizationNonce.Uint64()
	if key.HasPendingRotation {
		ev.verdict = refuse(reasonNoCapacity, classRotationPending,
			"service key rotation pending (effective at %d)", key.PendingRotation.EffectiveHeight)
		return ev, nil, nil
	}
	// Checks 2, 2a, 3, 4, 6, 7.
	ev.verdict, err = d.prechecks(ctx, t, so, ev.oraw, height)
	return ev, nil, err
}

// checkHandraise is check 1's "the Builder is in this node's valid standing
// handraise set": the last handraise sent to it, a withdrawal included, has
// not expired by height (Q4).
func (d *Dispatcher) checkHandraise(builder string, height uint64) error {
	cur, ok := d.cfg.Handraise.Current(builder)
	if !ok {
		return fmt.Errorf("no standing handraise was sent to %s", builder)
	}
	if height > cur.ExpiryHeight {
		return fmt.Errorf("the last standing handraise to %s expired at %d", builder, cur.ExpiryHeight)
	}
	return nil
}

// ticketContext builds CheckTicket's inputs at height from chain authority
// and this node's own roots. Read failures are retryable; anything else drops.
func (d *Dispatcher) ticketContext(ctx context.Context, builder string, t *taskv1.DispatchTicketV1, o *taskv1.TaskOrderV3, height uint64) (dispatchwire.TicketContext, error) {
	var tc dispatchwire.TicketContext
	key, err := d.chain.CurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, builder, height)
	if errors.Is(err, chainclient.ErrNotFound) {
		return tc, fmt.Errorf("Builder %s has no service key on chain: %w", builder, err) // check-1 drop (I6)
	}
	if err != nil {
		return tc, builderclient.Retryable(fmt.Errorf("Builder %s service key: %w", builder, err))
	}
	if key.Status != "ACTIVE" {
		return tc, fmt.Errorf("Builder %s service key is %s; it authorizes no live ticket", builder, key.Status)
	}
	pub, err := hex.DecodeString(key.ServicePubkey)
	if err != nil {
		return tc, fmt.Errorf("Builder %s service key: %w", builder, err)
	}
	vrf, err := d.chain.BuilderVrfKeyAt(ctx, builder, height)
	if errors.Is(err, chainclient.ErrNotFound) {
		return tc, fmt.Errorf("Builder %s has no VRF key on chain: %w", builder, err) // check-1 drop (I6)
	}
	if err != nil {
		return tc, builderclient.Retryable(fmt.Errorf("Builder %s VRF key: %w", builder, err))
	}
	ep, err := d.chain.DispatchEpochAt(ctx, o.GetEarliestSubmitHeight(), height)
	if err != nil {
		return tc, builderclient.Retryable(fmt.Errorf("epoch beacon: %w", err))
	}
	// HoldsRoot, not HeldRootDigests: any retained root counts, and the
	// store validates the record it answers from.
	var root [32]byte
	copy(root[:], t.GetHandraiseRootDigest())
	held, err := d.cfg.Handraise.HoldsRoot(ctx, builder, root)
	if err != nil {
		return tc, builderclient.Retryable(fmt.Errorf("handraise roots: %w", err))
	}
	vrfKey := vrf.ActivePubkey
	epoch := o.GetEarliestSubmitHeight() / ep.EpochLengthBlocks
	if vrf.PendingPubkey != nil && epoch >= vrf.PendingFromEpoch {
		vrfKey = vrf.PendingPubkey
	} else if epoch < vrf.ActiveFromEpoch {
		return tc, fmt.Errorf("Builder %s VRF key is active from epoch %d; the key for epoch %d is not readable", builder, vrf.ActiveFromEpoch, epoch)
	}
	tc = dispatchwire.TicketContext{
		ChainID: d.cfg.ChainID, BuilderOperator: builder, SelfOperator: d.cfg.Operator,
		BuilderServicePubKey: pub, BuilderVRFPubKey: vrfKey, EpochLengthBlocks: ep.EpochLengthBlocks,
		EarliestSubmitHeight: o.GetEarliestSubmitHeight(), HeldRootDigests: map[[32]byte]bool{root: held},
	}
	if ep.Verified {
		tc.Beacon = dispatchwire.NewVerifiedBeacon(ep.BeaconHeight, ep.Randomness)
	}
	return tc, nil
}

func (d *Dispatcher) persistOffer(ctx context.Context, builder string, ticket layout.StoredHash, t *taskv1.DispatchTicketV1,
	order *taskv1.TaskOrderV3, ev offerEval, deadline time.Time) (layout.DispatchRecord, error) {
	traw, oraw, p := ev.traw, ev.oraw, ev.params
	rec := layout.DispatchRecord{
		TicketHash: ticket, OrderSequence: t.GetOrderSequence(), DispatchRound: t.GetDispatchRound(), Builder: builder,
		ModelID: hex.EncodeToString(order.GetModelId()), ProfileVersion: order.GetProfileVersion(), InputSizeBytes: order.GetInputSizeBytes(),
		Ticket: traw, SignedOrder: oraw, ReceivedAtUnixMs: d.cfg.Now().UnixMilli(), AcceptDeadlineUnixMs: deadline.UnixMilli(),
		ClaimFromHeight: hrAddSat(max(order.GetEarliestSubmitHeight(), t.GetBoundChangeHeight()), p.RecordDeadlineBlocks),
	}
	copy(rec.TaskID[:], t.GetTaskId())
	copy(rec.TaskHash[:], t.GetTaskHash())
	copy(rec.SessionID[:], t.GetSessionId())
	copy(rec.InputHash[:], t.GetInputHash())
	stored, _, err := layout.PutDispatchOffer(ctx, d.cfg.Store, rec)
	return stored, err
}

// resumeCurrent re-reads ticket's record under the work lock and resumes it.
func (d *Dispatcher) resumeCurrent(ctx context.Context, enq DispatchEnqueuer, ticket layout.StoredHash) error {
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	return d.resume(ctx, enq, rec)
}

// resume answers a redelivered offer from its record. The caller holds the
// work lock.
func (d *Dispatcher) resume(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord) error {
	switch rec.State {
	case layout.DispatchRejected:
		// A crash may have come between the reject and its lease release.
		if err := d.releaseLease(ctx, rec.TicketHash); err != nil {
			return err
		}
		return d.sendReject(ctx, enq, rec)
	case layout.DispatchAccepted:
		if rec.InputCommitted {
			return nil
		}
		return d.sendAccept(ctx, enq, rec)
	}
	return d.drop(ctx, rec.Builder, rec.TicketHash, fmt.Errorf("ticket is already %s", rec.State))
}

func (d *Dispatcher) reject(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord, t *taskv1.DispatchTicketV1, nonce uint64, v *verdict) error {
	if !d.cfg.Now().Before(d.acceptDeadline(rec)) {
		return d.drop(ctx, rec.Builder, rec.TicketHash, fmt.Errorf("%s, but the accept deadline passed; nothing is signed", v.detail))
	}
	m := &taskv1.DispatchRejectV1{
		SchemaVersion: dispatchMessageSchemaVersion, ChainId: d.cfg.ChainID,
		TaskId: bytes.Clone(t.GetTaskId()), TaskHash: bytes.Clone(t.GetTaskHash()), DispatchTicketHash: bytes.Clone(rec.TicketHash[:]),
		Member: proto.Clone(t.GetTarget()).(*taskv1.CandidateMemberRefV1), ServiceAuthorizationNonce: nonce, RejectReason: v.reason,
	}
	if err := dispatchwire.SignReject(ctx, m, d.cfg.Sign); err != nil {
		return builderclient.Retryable(err)
	}
	raw, err := dispatchwire.Raw(m)
	if err != nil {
		return err
	}
	stored, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.State, r.Reject, r.RejectReason, r.RejectClass, r.RejectBuilderSide, r.StateReason =
			layout.DispatchRejected, raw, int32(v.reason), v.class, v.builderSide, v.detail
		return nil
	})
	if errors.Is(err, layout.ErrConflict) {
		return fmt.Errorf("refusing to reject ticket %s: %w", rec.TicketHash, err)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("persist reject: %w", err))
	}
	d.cfg.Logger.Info("dispatch ticket rejected", "builder", rec.Builder, "ticket", rec.TicketHash.String(),
		"reason", v.reason.String(), "class", v.class, "builder_side", v.builderSide, "detail", v.detail)
	// A lease an earlier attempt took for this ticket goes back (I1).
	if err := d.releaseLease(ctx, rec.TicketHash); err != nil {
		return err
	}
	return d.sendReject(ctx, enq, stored)
}

func (d *Dispatcher) sendReject(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord) error {
	if rec.RejectSeq != 0 {
		return nil
	}
	deadline := d.acceptDeadline(rec)
	if !d.cfg.Now().Before(deadline) {
		return nil // CD §4.2.0: a reject past the accept deadline is not sent or resent
	}
	m := &taskv1.DispatchRejectV1{}
	if err := proto.Unmarshal(rec.Reject, m); err != nil {
		return fmt.Errorf("stored reject: %w", err)
	}
	seq, err := enq.Enqueue(ctx, dispatchstream.Outgoing{Message: m, ExpiresAtUnixMilli: deadline.UnixMilli()})
	if err != nil {
		return enqueueErr("reject", err)
	}
	if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.RejectSeq = seq
		return nil
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("record reject seq: %w", err))
	}
	d.forgetDeadline(rec.TicketHash)
	return nil
}

func (d *Dispatcher) accept(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord, t *taskv1.DispatchTicketV1, nonce uint64) error {
	// W4: never sign after the deadline (C4); the lease taken for it goes back.
	if !d.cfg.Now().Add(d.cfg.AcceptSignMargin).Before(d.acceptDeadline(rec)) {
		return d.drop(ctx, rec.Builder, rec.TicketHash, errors.New("accept deadline passed before the accept was signed (C4)"))
	}
	m := &taskv1.DispatchAcceptV1{
		SchemaVersion: dispatchMessageSchemaVersion, ChainId: d.cfg.ChainID,
		TaskId: bytes.Clone(t.GetTaskId()), TaskHash: bytes.Clone(t.GetTaskHash()), DispatchTicketHash: bytes.Clone(rec.TicketHash[:]),
		Member: proto.Clone(t.GetTarget()).(*taskv1.CandidateMemberRefV1), ServiceAuthorizationNonce: nonce,
	}
	if err := dispatchwire.SignAccept(ctx, m, d.cfg.Sign); err != nil {
		return builderclient.Retryable(err) // the lease stays; the redelivered offer reuses it
	}
	digest, err := dispatchwire.Digest(m)
	if err != nil {
		return err
	}
	raw, err := dispatchwire.Raw(m)
	if err != nil {
		return err
	}
	stored, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.State, r.Accept, r.AcceptDigest = layout.DispatchAccepted, raw, layout.StoredHash(digest)
		return nil
	})
	if errors.Is(err, layout.ErrConflict) {
		if rerr := d.releaseLease(ctx, rec.TicketHash); rerr != nil {
			return rerr
		}
		return fmt.Errorf("refusing to accept ticket %s: %w", rec.TicketHash, err)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("persist accept: %w", err))
	}
	d.cfg.Handraise.Notify() // W4: one slot fewer; the standing handraise re-signs
	d.cfg.Logger.Info("dispatch ticket accepted", "builder", rec.Builder, "ticket", rec.TicketHash.String(), "task_hash", rec.TaskHash.String())
	return d.sendAccept(ctx, enq, stored)
}

// sendAccept enqueues the stored accept (never re-signed) and the first
// input request behind it.
func (d *Dispatcher) sendAccept(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord) error {
	deadline := d.acceptDeadline(rec)
	if rec.AcceptSeq == 0 {
		if !d.cfg.Now().Before(deadline) {
			if rec.AcceptEnqueuing {
				// An enqueue was started and its outcome never recorded: the
				// accept may be in the outbox and may have been sent, so it
				// stands (Q9). S6 settles it at D_ticket.
				return nil
			}
			// Signed but never handed to the stream before the deadline: not
			// sent, not resent on reconnect, and the lease goes back (C4).
			return d.release(ctx, rec, layout.DispatchAcceptUnsent, "accept signed but not enqueued before the accept deadline")
		}
		m := &taskv1.DispatchAcceptV1{}
		if err := proto.Unmarshal(rec.Accept, m); err != nil {
			return fmt.Errorf("stored accept: %w", err)
		}
		// While AcceptEnqueuing is set the accept may already be in the
		// outbox; enqueueing the same signed bytes again is harmless (the
		// Builder dedupes by digest, and acks the copy) and is the only way
		// to be sure it is there before the deadline (M7).
		if !rec.AcceptEnqueuing {
			var err error
			if rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
				r.AcceptEnqueuing = true
				return nil
			}); err != nil {
				return builderclient.Retryable(fmt.Errorf("record accept enqueue: %w", err))
			}
		}
		seq, err := enq.Enqueue(ctx, dispatchstream.Outgoing{Message: m, ExpiresAtUnixMilli: deadline.UnixMilli()})
		if err != nil {
			// The outbox refused it, so it is certainly not there.
			if _, uerr := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
				r.AcceptEnqueuing = false
				return nil
			}); uerr != nil {
				return builderclient.Retryable(fmt.Errorf("enqueue accept: %w", errors.Join(err, uerr)))
			}
			return enqueueErr("accept", err)
		}
		if rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.AcceptSeq, r.AcceptEnqueuing = seq, false
			return nil
		}); err != nil {
			return builderclient.Retryable(fmt.Errorf("record accept seq: %w", err))
		}
	}
	if rec.InputRequestSeq == 0 {
		// W5: the first input request rides right behind the accept and
		// expires with it, so it never goes out without the accept.
		return d.requestInput(ctx, enq, rec, deadline)
	}
	return nil
}

// requestInput signs and enqueues a DispatchInputRequestV1 bound to the
// stored accept. The nonce is the accept's: accepted work finishes under the
// key it was accepted with (issue #83).
func (d *Dispatcher) requestInput(ctx context.Context, enq DispatchEnqueuer, rec layout.DispatchRecord, expires time.Time) error {
	acc := &taskv1.DispatchAcceptV1{}
	if err := proto.Unmarshal(rec.Accept, acc); err != nil {
		return fmt.Errorf("stored accept: %w", err)
	}
	m := &nexusv1.DispatchInputRequestV1{
		TaskId: bytes.Clone(acc.GetTaskId()), DispatchTicketHash: bytes.Clone(acc.GetDispatchTicketHash()), Member: acc.GetMember(),
		ServiceAuthorizationNonce: acc.GetServiceAuthorizationNonce(), DispatchAcceptDigest: bytes.Clone(rec.AcceptDigest[:]),
	}
	if err := dispatchwire.SignInputRequest(ctx, m, d.cfg.Sign); err != nil {
		return builderclient.Retryable(err)
	}
	seq, err := enq.Enqueue(ctx, dispatchstream.Outgoing{Message: m, ExpiresAtUnixMilli: expires.UnixMilli()})
	if err != nil {
		return enqueueErr("input request", err)
	}
	now := d.cfg.Now().UnixMilli()
	if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.InputRequestSeq, r.InputRequestedAtUnixMs = seq, now
		return nil
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("record input request: %w", err))
	}
	return nil
}
