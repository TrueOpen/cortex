package layout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/store"
)

// Phase 1 dispatch keys (CD §10 DispatchRecord, TaskProfileLease). Before the
// record entry everything is keyed by dispatch_ticket_hash. S5 moves the
// Worker lease to its task_id key at record time (RebindWorkerLease).
// Settled records, their indexes and staged input are deleted by
// DeleteDispatchRecord, which the S6 GC calls once retention has passed.
const (
	dispatchTicketPrefix    = "dispatch-ticket/"
	dispatchTaskPrefix      = "dispatch-task/"
	dispatchOpenPrefix      = "dispatch-open/"
	dispatchInputPrefix     = "dispatch-input/"
	workerLeasePrefix       = "lease/worker/"
	workerTicketLeasePrefix = "lease/worker/ticket/"
	workerTaskLeasePrefix   = "lease/worker/task/"
	dispatchAwaitPrefix     = "dispatch-await/"
	dispatchReceiptPrefix   = "dispatch-receipt/"
	dispatchClaimPrefix     = "dispatch-claim/"
	dispatchCollectPrefix   = "dispatch-gc/"
)

// DispatchRecordSchemaVersion is the current DispatchRecord schema.
const DispatchRecordSchemaVersion = uint16(1)

func DispatchTicketKey(ticket StoredHash) []byte {
	return join([]byte(dispatchTicketPrefix), ticket[:])
}

func dispatchTaskIndexPrefix(taskID StoredHash) []byte {
	return join([]byte(dispatchTaskPrefix), taskID[:], slash())
}

// DispatchTaskKey indexes a ticket under its task_id (round replacement).
func DispatchTaskKey(taskID, ticket StoredHash) []byte {
	return join(dispatchTaskIndexPrefix(taskID), ticket[:])
}

// DispatchOpenKey marks an accepted ticket whose input is not committed yet.
func DispatchOpenKey(ticket StoredHash) []byte { return join([]byte(dispatchOpenPrefix), ticket[:]) }

func dispatchInputTicketPrefix(ticket StoredHash) []byte {
	return join([]byte(dispatchInputPrefix), ticket[:], slash())
}

// DispatchInputChunkKey holds one received DispatchInputResponseV1 chunk.
func DispatchInputChunkKey(ticket StoredHash, index uint32) []byte {
	return binary.BigEndian.AppendUint32(dispatchInputTicketPrefix(ticket), index)
}

// WorkerTicketLeaseKey is the pre-record lease key (ticket, WORKER).
func WorkerTicketLeaseKey(ticket StoredHash) []byte {
	return join([]byte(workerTicketLeasePrefix), ticket[:])
}

// WorkerTaskLeaseKey is the post-record lease key (task_id, WORKER).
func WorkerTaskLeaseKey(taskID StoredHash) []byte {
	return join([]byte(workerTaskLeasePrefix), taskID[:])
}

// DispatchAwaitKey marks an accepted ticket whose record is not settled yet.
func DispatchAwaitKey(ticket StoredHash) []byte { return join([]byte(dispatchAwaitPrefix), ticket[:]) }

// DispatchReceiptKey marks a recorded ticket whose signed receipt the chain has
// not been seen to accept (self-rescue candidates, CD W13).
func DispatchReceiptKey(ticket StoredHash) []byte {
	return join([]byte(dispatchReceiptPrefix), ticket[:])
}

// DispatchState is the local state of one received ticket.
type DispatchState string

const (
	DispatchOffered      DispatchState = "offered"       // W1 durable; no answer signed yet
	DispatchRejected     DispatchState = "rejected"      // DispatchRejectV1 signed
	DispatchAccepted     DispatchState = "accepted"      // DispatchAcceptV1 signed
	DispatchAcceptUnsent DispatchState = "accept-unsent" // signed, never transmitted before the deadline (C4)
	DispatchRevoked      DispatchState = "revoked"       // DispatchRevokeV1 (RBF) received
	DispatchSuperseded   DispatchState = "superseded"    // a newer round of the same task arrived
	// DispatchPendingClaim: a REJECTED notice, or another ticket recorded for
	// the order. Delivery is paused, inference continues; S6 settles it at
	// D_ticket (CD §8.6).
	DispatchPendingClaim DispatchState = "pending-claim"
	DispatchRecorded     DispatchState = "recorded" // QueryDispatchRecord: this ticket is the winner
	// DispatchConflict: recorded with this ticket, but the chain disagrees
	// with the local facts (ChainObservationConflict). Fails closed.
	DispatchConflict DispatchState = "conflict"

	// Compensation claim (S6, CD §8.6).
	DispatchClaimable      DispatchState = "claimable"       // D_ticket passed, this ticket not the winner: inference stopped, lease released, claim due
	DispatchClaimPending   DispatchState = "claim-pending"   // chain: PENDING_REBUTTAL
	DispatchClaimPaid      DispatchState = "claim-paid"      // chain: PAID
	DispatchClaimDismissed DispatchState = "claim-dismissed" // chain: DISMISSED (rebutted)
	DispatchNotClaimable   DispatchState = "not-claimable"   // winner-ineligible marker, window missed, or the chain refused the claim
)

// dispatchTransitions lists the states each state may move to.
var dispatchTransitions = map[DispatchState][]DispatchState{
	DispatchOffered: {DispatchRejected, DispatchAccepted, DispatchRevoked, DispatchSuperseded},
	DispatchAccepted: {DispatchAcceptUnsent, DispatchRevoked, DispatchSuperseded, DispatchPendingClaim, DispatchRecorded, DispatchConflict,
		DispatchClaimable, DispatchNotClaimable},
	DispatchAcceptUnsent: {DispatchRevoked},
	DispatchSuperseded:   {DispatchRevoked},
	DispatchPendingClaim: {DispatchRecorded, DispatchSuperseded, DispatchConflict, DispatchClaimable, DispatchNotClaimable},
	DispatchClaimable:    {DispatchClaimPending, DispatchClaimPaid, DispatchClaimDismissed, DispatchNotClaimable},
	DispatchClaimPending: {DispatchClaimPaid, DispatchClaimDismissed},
}

// Claiming reports a ticket whose compensation claim is not settled.
func (s DispatchState) Claiming() bool { return s == DispatchClaimable || s == DispatchClaimPending }

// Collectable reports a state the S6 GC may delete once retention ends.
func (s DispatchState) Collectable() bool {
	switch s {
	case DispatchOffered, DispatchRejected, DispatchAcceptUnsent, DispatchRevoked, DispatchSuperseded, DispatchConflict,
		DispatchRecorded, DispatchNotClaimable, DispatchClaimPaid, DispatchClaimDismissed:
		return true
	}
	return false
}

// HoldsDuty reports an accepted ticket not yet released: it holds a lease and
// keeps fetching its input whether or not the record has landed.
func (s DispatchState) HoldsDuty() bool {
	return s == DispatchAccepted || s == DispatchPendingClaim || s == DispatchRecorded
}

// DispatchRecord is one received DispatchTicketV1 and what this node did with
// it (CD §10 DispatchRecord, TD §3). Ticket, SignedOrder, Accept, Reject and
// Revoke are the exact bytes received or signed and are write-once; Accept and
// Reject never coexist. S6 claims from Ticket + Accept + SignedOrder.
type DispatchRecord struct {
	SchemaVersion uint16 `json:"schema_version"`

	TicketHash     StoredHash `json:"dispatch_ticket_hash"`
	TaskID         StoredHash `json:"task_id"`
	TaskHash       StoredHash `json:"task_hash"`
	SessionID      StoredHash `json:"session_id"`
	OrderSequence  uint64     `json:"order_sequence"`
	DispatchRound  uint32     `json:"dispatch_round"`
	Builder        string     `json:"builder_operator"`
	ModelID        string     `json:"model_id"`
	ProfileVersion uint32     `json:"profile_version"`
	InputHash      StoredHash `json:"input_hash"`
	InputSizeBytes uint64     `json:"input_size_bytes"`

	Ticket      []byte `json:"ticket,omitempty"`
	SignedOrder []byte `json:"signed_order,omitempty"`

	// ReceivedAtUnixMs and AcceptDeadlineUnixMs are local wall-clock values
	// (C4): they only decide "do not sign or send late" after a restart.
	ReceivedAtUnixMs     int64 `json:"received_at_unix_ms,omitempty"`
	AcceptDeadlineUnixMs int64 `json:"accept_deadline_unix_ms,omitempty"`
	// ClaimFromHeight is D_ticket = max(order.earliest_submit_height,
	// ticket.bound_change_height) + record_deadline_blocks (C3), the start of
	// the compensation claim window (S6).
	ClaimFromHeight uint64 `json:"claim_from_height,omitempty"`

	State       DispatchState `json:"state"`
	StateReason string        `json:"state_reason,omitempty"`

	Reject            []byte `json:"reject,omitempty"`
	RejectReason      int32  `json:"reject_reason,omitempty"`
	RejectClass       string `json:"reject_class,omitempty"`
	RejectBuilderSide bool   `json:"reject_builder_side,omitempty"` // CD §5.1 2a: not counted toward this node
	RejectSeq         uint64 `json:"reject_seq,omitempty"`

	Accept       []byte     `json:"accept,omitempty"`
	AcceptDigest StoredHash `json:"accept_digest"`
	AcceptSeq    uint64     `json:"accept_seq,omitempty"`
	// AcceptEnqueuing is set before the accept is handed to the outbox and
	// cleared once that enqueue is known to have failed. Set while AcceptSeq is
	// still 0, the accept may be in the outbox (the process stopped before the
	// sequence was recorded): its fate is unknown, so it is never treated as
	// unsent (C4, Q9).
	AcceptEnqueuing bool `json:"accept_enqueuing,omitempty"`

	InputRequestSeq        uint64 `json:"input_request_seq,omitempty"`
	InputRequestedAtUnixMs int64  `json:"input_requested_at_unix_ms,omitempty"`
	InputChunkCount        uint32 `json:"input_chunk_count,omitempty"`
	// InputChunksReceived and InputStagedBytes count the distinct chunks
	// staged so far and their bytes. They change in the same batch as the
	// chunk itself, so completeness is read from them, never from a scan.
	InputChunksReceived uint32 `json:"input_chunks_received,omitempty"`
	InputStagedBytes    uint64 `json:"input_staged_bytes,omitempty"`
	InputCommitted      bool   `json:"input_committed,omitempty"`

	Revoke []byte `json:"revoke,omitempty"`

	// Record observation (S5). RecordNotice and NoticeStatus are the
	// dispatching Builder's RecordResultNoticeV1, a hint only; the rest are
	// chain facts read through QueryDispatchRecord and Query/TaskAssignment.
	RecordNotice        []byte     `json:"record_notice,omitempty"`
	NoticeStatus        int32      `json:"notice_status,omitempty"`
	WinnerTicketHash    StoredHash `json:"winner_ticket_hash"`
	RecordHash          StoredHash `json:"record_hash"`
	RecordedHeight      uint64     `json:"recorded_height,omitempty"`
	InferDeadlineHeight uint64     `json:"infer_deadline_height,omitempty"`
	// Receipt is the signed InferReceiptV3 (builderclient JSON); self-rescue
	// submits exactly these bytes. S6 keeps it when it voids the receipt.
	Receipt         []byte `json:"receipt,omitempty"`
	ReceiptAccepted bool   `json:"receipt_accepted,omitempty"`
	RescueTxHash    string `json:"rescue_tx_hash,omitempty"`

	// Compensation claim (S6, CD §8.6). ClaimWindowCloseHeight = D_ticket +
	// claim_window, write-once. The chain fields mirror
	// DispatchCompensationClaimState.
	ClaimWindowCloseHeight uint64 `json:"claim_window_close_height,omitempty"`
	ClaimAttemptHeight     uint64 `json:"claim_attempt_height,omitempty"`
	ClaimTxHash            string `json:"claim_tx_hash,omitempty"`
	ClaimedHeight          uint64 `json:"claimed_height,omitempty"`
	RebuttalDeadlineHeight uint64 `json:"rebuttal_deadline_height,omitempty"`
	ClaimCheckedHeight     uint64 `json:"claim_checked_height,omitempty"`
	ClaimAmount            string `json:"claim_amount,omitempty"`
	PaidAmount             string `json:"paid_amount,omitempty"`
	UnfilledAmount         string `json:"unfilled_amount,omitempty"`
	RebuttedBy             string `json:"rebutted_by,omitempty"`
	ClaimResolvedHeight    uint64 `json:"claim_resolved_height,omitempty"`
	// FalseNotice: a REJECTED notice for a ticket the chain recorded (CD §8.6a).
	FalseNotice bool `json:"false_notice,omitempty"`
	// GCFromHeight anchors retention of a record without ClaimFromHeight (a
	// revoke tombstone): the height the GC first saw it at. Write-once.
	GCFromHeight uint64 `json:"gc_from_height,omitempty"`
}

// WorkerLease is a TaskProfileLease (CD §5.2 W3). Before the record entry it
// is keyed by dispatch_ticket_hash; S5 rebinds it to (task_id, WORKER).
type WorkerLease struct {
	SchemaVersion  uint16     `json:"schema_version"`
	TicketHash     StoredHash `json:"dispatch_ticket_hash"`
	TaskID         StoredHash `json:"task_id"`
	ModelID        string     `json:"model_id"`
	ProfileVersion uint32     `json:"profile_version"`
	Builder        string     `json:"builder_operator"`
	// ExpiryHeight bounds a pre-record lease: D_ticket.
	ExpiryHeight uint64 `json:"expiry_height"`
}

// DispatchOpenEntry is the open index value: what the sweep decides on, so
// it loads a full record only for a ticket it acts on.
type DispatchOpenEntry struct {
	TicketHash             StoredHash    `json:"-"`
	State                  DispatchState `json:"state"`
	Builder                string        `json:"builder_operator"`
	AcceptDeadlineUnixMs   int64         `json:"accept_deadline_unix_ms,omitempty"`
	AcceptSeq              uint64        `json:"accept_seq,omitempty"`
	AcceptEnqueuing        bool          `json:"accept_enqueuing,omitempty"`
	InputRequestSeq        uint64        `json:"input_request_seq,omitempty"`
	InputRequestedAtUnixMs int64         `json:"input_requested_at_unix_ms,omitempty"`
	ClaimFromHeight        uint64        `json:"claim_from_height,omitempty"`
	InferDeadlineHeight    uint64        `json:"infer_deadline_height,omitempty"`
}

func putDispatch(b *store.Batch, rec DispatchRecord) error {
	if err := putBatchJSON(b, DispatchTicketKey(rec.TicketHash), rec); err != nil {
		return err
	}
	var err error
	if rec.State.HoldsDuty() && !rec.InputCommitted {
		err = putBatchJSON(b, DispatchOpenKey(rec.TicketHash), DispatchOpenEntry{
			State: rec.State, Builder: rec.Builder, AcceptDeadlineUnixMs: rec.AcceptDeadlineUnixMs, AcceptSeq: rec.AcceptSeq,
			AcceptEnqueuing: rec.AcceptEnqueuing, InputRequestSeq: rec.InputRequestSeq,
			InputRequestedAtUnixMs: rec.InputRequestedAtUnixMs, ClaimFromHeight: rec.ClaimFromHeight,
			InferDeadlineHeight: rec.InferDeadlineHeight,
		})
	} else {
		err = b.Delete(DispatchOpenKey(rec.TicketHash))
	}
	if err != nil {
		return err
	}
	for _, ix := range []struct {
		key []byte
		on  bool
	}{
		{DispatchAwaitKey(rec.TicketHash), rec.State == DispatchAccepted || rec.State == DispatchPendingClaim},
		{DispatchReceiptKey(rec.TicketHash), rec.State == DispatchRecorded && len(rec.Receipt) > 0 && !rec.ReceiptAccepted},
		{DispatchClaimKey(rec.TicketHash), rec.State.Claiming()},
		{DispatchCollectKey(rec.TicketHash), rec.State.Collectable()},
	} {
		if ix.on {
			err = b.Set(ix.key, []byte{})
		} else {
			err = b.Delete(ix.key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// checkDispatchUpdate enforces identity, write-once bytes, accept-xor-reject
// and the state machine.
func checkDispatchUpdate(cur, next DispatchRecord) error {
	if next.TicketHash != cur.TicketHash || next.TaskID != cur.TaskID || next.Builder != cur.Builder {
		return fmt.Errorf("%w: dispatch record identity is immutable", ErrConflict)
	}
	for _, f := range []struct {
		name      string
		cur, next []byte
	}{
		{"ticket", cur.Ticket, next.Ticket}, {"signed order", cur.SignedOrder, next.SignedOrder},
		{"accept", cur.Accept, next.Accept}, {"reject", cur.Reject, next.Reject}, {"revoke", cur.Revoke, next.Revoke},
		{"record notice", cur.RecordNotice, next.RecordNotice}, {"receipt", cur.Receipt, next.Receipt},
	} {
		if len(f.cur) > 0 && !bytes.Equal(f.cur, f.next) {
			return fmt.Errorf("%w: dispatch %s is write-once", ErrConflict, f.name)
		}
	}
	if !cur.AcceptDigest.IsZero() && next.AcceptDigest != cur.AcceptDigest {
		return fmt.Errorf("%w: dispatch accept digest is write-once", ErrConflict)
	}
	for _, f := range []struct {
		name      string
		cur, next StoredHash
	}{{"winner ticket", cur.WinnerTicketHash, next.WinnerTicketHash}, {"record hash", cur.RecordHash, next.RecordHash}} {
		if !f.cur.IsZero() && f.next != f.cur {
			return fmt.Errorf("%w: dispatch %s is write-once", ErrConflict, f.name)
		}
	}
	for _, f := range []struct {
		name      string
		cur, next uint64
	}{{"recorded height", cur.RecordedHeight, next.RecordedHeight}, {"infer deadline", cur.InferDeadlineHeight, next.InferDeadlineHeight}} {
		if f.cur != 0 && f.next != f.cur {
			return fmt.Errorf("%w: dispatch %s is write-once", ErrConflict, f.name)
		}
	}
	for _, f := range []struct {
		name      string
		cur, next uint64
	}{{"claim window", cur.ClaimWindowCloseHeight, next.ClaimWindowCloseHeight}, {"GC anchor", cur.GCFromHeight, next.GCFromHeight}} {
		if f.cur != 0 && f.next != f.cur {
			return fmt.Errorf("%w: dispatch %s is write-once", ErrConflict, f.name)
		}
	}
	switch next.State {
	case DispatchClaimable:
		if next.ClaimWindowCloseHeight <= next.ClaimFromHeight || len(next.Receipt) > 0 {
			return fmt.Errorf("%w: a claimable ticket needs its claim window and carries no receipt", ErrConflict)
		}
	case DispatchClaimPending, DispatchClaimPaid, DispatchClaimDismissed:
		if next.ClaimedHeight == 0 {
			return fmt.Errorf("%w: dispatch state %s needs the chain's claimed height", ErrConflict, next.State)
		}
	}
	if next.State == DispatchRecorded && (next.RecordedHeight == 0 || next.InferDeadlineHeight <= next.RecordedHeight || next.WinnerTicketHash != next.TicketHash) {
		return fmt.Errorf("%w: a recorded ticket needs its record height, its infer deadline and itself as the winner", ErrConflict)
	}
	if len(next.Receipt) > 0 && next.State != DispatchRecorded {
		return fmt.Errorf("%w: a receipt is only signed for a recorded ticket (S5 Q1)", ErrConflict)
	}
	if next.ReceiptAccepted && len(next.Receipt) == 0 {
		return fmt.Errorf("%w: an accepted receipt needs the receipt", ErrConflict)
	}
	if len(next.Accept) > 0 && len(next.Reject) > 0 {
		return fmt.Errorf("%w: a ticket is accepted or rejected, never both (CD §4.2.0)", ErrConflict)
	}
	if next.State != cur.State && !slices.Contains(dispatchTransitions[cur.State], next.State) {
		return fmt.Errorf("%w: dispatch state %s cannot become %s", ErrConflict, cur.State, next.State)
	}
	switch {
	case next.State == DispatchAccepted && (len(next.Accept) == 0 || next.AcceptDigest.IsZero()),
		next.State == DispatchRejected && len(next.Reject) == 0,
		next.State == DispatchRevoked && len(next.Revoke) == 0:
		return fmt.Errorf("%w: dispatch state %s needs its signed message", ErrConflict, next.State)
	}
	return nil
}

// PutDispatchOffer records a received ticket and its order (CD §5.2 W1).
// created reports a new record. An existing record is returned as is: the
// same ticket bytes are a redelivery, different ones a conflict. A revoke
// tombstone (the revoke outran the offer) gains the offer fields and stays
// revoked.
func PutDispatchOffer(ctx context.Context, s *store.Store, rec DispatchRecord) (DispatchRecord, bool, error) {
	if rec.TicketHash.IsZero() || rec.TaskID.IsZero() || rec.TaskHash.IsZero() || rec.Builder == "" || len(rec.Ticket) == 0 || len(rec.SignedOrder) == 0 {
		return DispatchRecord{}, false, fmt.Errorf("dispatch offer record is incomplete")
	}
	rec.SchemaVersion = DispatchRecordSchemaVersion
	rec.State = DispatchOffered
	var out DispatchRecord
	created := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var cur DispatchRecord
		err := getBatchJSON(b, DispatchTicketKey(rec.TicketHash), &cur)
		switch {
		case errors.Is(err, store.ErrNotFound):
			out, created = rec, true
		case err != nil:
			return err
		case len(cur.Ticket) == 0:
			if cur.Builder != rec.Builder || cur.TaskID != rec.TaskID {
				return fmt.Errorf("%w: dispatch offer does not match its revoke", ErrConflict)
			}
			out = rec
			out.State, out.StateReason, out.Revoke = cur.State, cur.StateReason, cur.Revoke
		case !bytes.Equal(cur.Ticket, rec.Ticket):
			return fmt.Errorf("%w: dispatch ticket %s arrived with different bytes", ErrConflict, rec.TicketHash)
		default:
			out = cur
			return nil
		}
		if err := putDispatch(b, out); err != nil {
			return err
		}
		return b.Set(DispatchTaskKey(rec.TaskID, rec.TicketHash), []byte{})
	})
	if err != nil {
		return DispatchRecord{}, false, err
	}
	return out, created, nil
}

// UpdateDispatch applies fn to the stored record atomically, refusing any
// change checkDispatchUpdate forbids, and keeps the open index current.
func UpdateDispatch(ctx context.Context, s *store.Store, ticket StoredHash, fn func(*DispatchRecord) error) (DispatchRecord, error) {
	return updateDispatch(ctx, s, ticket, false, fn)
}

// UpdateDispatchDroppingInput is UpdateDispatch that also deletes the
// ticket's staged input chunks in the same batch: for a terminal state, or
// once the input is committed.
func UpdateDispatchDroppingInput(ctx context.Context, s *store.Store, ticket StoredHash, fn func(*DispatchRecord) error) (DispatchRecord, error) {
	return updateDispatch(ctx, s, ticket, true, fn)
}

func updateDispatch(ctx context.Context, s *store.Store, ticket StoredHash, dropInput bool, fn func(*DispatchRecord) error) (DispatchRecord, error) {
	var out DispatchRecord
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var cur DispatchRecord
		if err := getBatchJSON(b, DispatchTicketKey(ticket), &cur); err != nil {
			return err
		}
		next := cur
		if err := fn(&next); err != nil {
			return err
		}
		if err := checkDispatchUpdate(cur, next); err != nil {
			return err
		}
		out = next
		if dropInput {
			if err := deletePrefixedKeysInBatch(b, dispatchInputTicketPrefix(ticket)); err != nil {
				return err
			}
		}
		return putDispatch(b, next)
	})
	if err != nil {
		return DispatchRecord{}, err
	}
	return out, nil
}

// PutDispatchRevoke records a DispatchRevokeV1 (RBF). An unknown ticket gets a
// tombstone so the offer, if it still arrives, is dropped. A rejected ticket
// stays rejected; any other moves to revoked. Staged input is dropped in the
// same batch. Tombstones and revoked records are deleted by the S6 GC
// (DeleteDispatchRecord) once their retention has passed.
func PutDispatchRevoke(ctx context.Context, s *store.Store, ticket, taskID StoredHash, builder string, raw []byte) (DispatchRecord, error) {
	if ticket.IsZero() || taskID.IsZero() || builder == "" || len(raw) == 0 {
		return DispatchRecord{}, fmt.Errorf("dispatch revoke is incomplete")
	}
	var out DispatchRecord
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var cur DispatchRecord
		err := getBatchJSON(b, DispatchTicketKey(ticket), &cur)
		if errors.Is(err, store.ErrNotFound) {
			out = DispatchRecord{
				SchemaVersion: DispatchRecordSchemaVersion, TicketHash: ticket, TaskID: taskID, Builder: builder,
				State: DispatchRevoked, StateReason: "revoked before the offer arrived", Revoke: raw,
			}
			if err := putDispatch(b, out); err != nil {
				return err
			}
			return b.Set(DispatchTaskKey(taskID, ticket), []byte{})
		}
		if err != nil {
			return err
		}
		if cur.Builder != builder || cur.TaskID != taskID {
			return fmt.Errorf("%w: revoke for ticket %s names another Builder or task", ErrConflict, ticket)
		}
		next := cur
		next.Revoke = raw
		if cur.State != DispatchRejected && cur.State != DispatchRevoked {
			next.State, next.StateReason = DispatchRevoked, "revoked by the Builder (RBF)"
		}
		if err := checkDispatchUpdate(cur, next); err != nil {
			return err
		}
		out = next
		if err := deletePrefixedKeysInBatch(b, dispatchInputTicketPrefix(ticket)); err != nil {
			return err
		}
		return putDispatch(b, next)
	})
	if err != nil {
		return DispatchRecord{}, err
	}
	return out, nil
}

// GetDispatchRecord reads one record; store.ErrNotFound when absent.
func GetDispatchRecord(ctx context.Context, s *store.Store, ticket StoredHash) (DispatchRecord, error) {
	var rec DispatchRecord
	err := getJSON(ctx, s, DispatchTicketKey(ticket), &rec)
	return rec, err
}

func scanHashes(ctx context.Context, s *store.Store, prefix []byte) ([]StoredHash, error) {
	var out []StoredHash
	err := s.ScanPrefix(ctx, prefix, func(key, _ []byte) error {
		var h StoredHash
		if len(key) != len(prefix)+len(h) {
			return fmt.Errorf("malformed key under %q", prefix)
		}
		copy(h[:], key[len(prefix):])
		out = append(out, h)
		return nil
	})
	return out, err
}

func getDispatchRecords(ctx context.Context, s *store.Store, tickets []StoredHash) ([]DispatchRecord, error) {
	out := make([]DispatchRecord, 0, len(tickets))
	for _, t := range tickets {
		rec, err := GetDispatchRecord(ctx, s, t)
		if err != nil {
			return nil, fmt.Errorf("dispatch record %s: %w", t, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// DispatchRecordsForTask returns every ticket received for taskID.
func DispatchRecordsForTask(ctx context.Context, s *store.Store, taskID StoredHash) ([]DispatchRecord, error) {
	tickets, err := scanHashes(ctx, s, dispatchTaskIndexPrefix(taskID))
	if err != nil {
		return nil, err
	}
	return getDispatchRecords(ctx, s, tickets)
}

// AwaitingRecordDispatches lists accepted tickets whose record is not settled:
// accepted or pending-claim.
func AwaitingRecordDispatches(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
	tickets, err := scanHashes(ctx, s, []byte(dispatchAwaitPrefix))
	if err != nil {
		return nil, err
	}
	return getDispatchRecords(ctx, s, tickets)
}

// ReceiptRescueCandidates lists recorded tickets with a signed receipt the
// chain has not been seen to accept.
func ReceiptRescueCandidates(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
	tickets, err := scanHashes(ctx, s, []byte(dispatchReceiptPrefix))
	if err != nil {
		return nil, err
	}
	return getDispatchRecords(ctx, s, tickets)
}

// OpenDispatchEntries returns the open index: tickets holding a duty whose
// input is not committed, without loading their records.
func OpenDispatchEntries(ctx context.Context, s *store.Store) ([]DispatchOpenEntry, error) {
	prefix := []byte(dispatchOpenPrefix)
	var out []DispatchOpenEntry
	err := s.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		var e DispatchOpenEntry
		if len(key) != len(prefix)+len(e.TicketHash) {
			return fmt.Errorf("malformed key under %q", prefix)
		}
		if err := json.Unmarshal(value, &e); err != nil {
			return fmt.Errorf("open dispatch entry: %w", err)
		}
		copy(e.TicketHash[:], key[len(prefix):])
		out = append(out, e)
		return nil
	})
	return out, err
}

// openDispatches returns tickets holding a duty whose input is not committed.
func openDispatches(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
	tickets, err := scanHashes(ctx, s, []byte(dispatchOpenPrefix))
	if err != nil {
		return nil, err
	}
	return getDispatchRecords(ctx, s, tickets)
}

// AcquireWorkerLease takes the lease for lease.TicketHash if fewer than
// capacity Worker leases exist. acquired: held after the call; created: this
// call wrote it.
func AcquireWorkerLease(ctx context.Context, s *store.Store, lease WorkerLease, capacity uint32) (acquired, created bool, err error) {
	if lease.TicketHash.IsZero() {
		return false, false, fmt.Errorf("worker lease needs a dispatch_ticket_hash")
	}
	lease.SchemaVersion = defaultSchemaVersion(lease.SchemaVersion)
	err = s.ApplyBatch(ctx, func(b *store.Batch) error {
		if _, err := b.Get(WorkerTicketLeaseKey(lease.TicketHash)); err == nil {
			acquired = true
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		it, err := b.NewIter([]byte(workerLeasePrefix))
		if err != nil {
			return err
		}
		var held uint32
		for ok := it.First(); ok; ok = it.Next() {
			held++
		}
		if err := it.Close(); err != nil {
			return err
		}
		if held >= capacity {
			return nil
		}
		acquired, created = true, true
		return putBatchJSON(b, WorkerTicketLeaseKey(lease.TicketHash), lease)
	})
	if err != nil {
		return false, false, err
	}
	return acquired, created, nil
}

// ReleaseWorkerLease drops a pre-record lease; released reports it existed.
func ReleaseWorkerLease(ctx context.Context, s *store.Store, ticket StoredHash) (bool, error) {
	released := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		if _, err := b.Get(WorkerTicketLeaseKey(ticket)); errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		released = true
		return b.Delete(WorkerTicketLeaseKey(ticket))
	})
	if err != nil {
		return false, err
	}
	return released, nil
}

// RebindWorkerLease moves ticket's pre-record lease to (task_id, WORKER) in one
// batch (CD §5.2 W3). The count under lease/worker/ is unchanged. moved=false
// with no error: already rebound. A ticket with neither lease is a conflict:
// the record names a ticket this node never reserved capacity for.
func RebindWorkerLease(ctx context.Context, s *store.Store, ticket, taskID StoredHash) (moved bool, err error) {
	err = s.ApplyBatch(ctx, func(b *store.Batch) error {
		var held WorkerLease
		taskErr := getBatchJSON(b, WorkerTaskLeaseKey(taskID), &held)
		if taskErr != nil && !errors.Is(taskErr, store.ErrNotFound) {
			return taskErr
		}
		var lease WorkerLease
		err := getBatchJSON(b, WorkerTicketLeaseKey(ticket), &lease)
		switch {
		case errors.Is(err, store.ErrNotFound) && taskErr == nil:
			if held.TicketHash != ticket {
				return fmt.Errorf("%w: task %s holds the lease of ticket %s, not %s", ErrConflict, taskID, held.TicketHash, ticket)
			}
			return nil
		case errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("%w: ticket %s holds no lease to rebind", ErrConflict, ticket)
		case err != nil:
			return err
		case lease.TaskID != taskID:
			return fmt.Errorf("%w: ticket %s leases task %s, not %s", ErrConflict, ticket, lease.TaskID, taskID)
		case taskErr == nil:
			return fmt.Errorf("%w: task %s already holds a Worker lease", ErrConflict, taskID)
		}
		moved = true
		if err := putBatchJSON(b, WorkerTaskLeaseKey(taskID), lease); err != nil {
			return err
		}
		return b.Delete(WorkerTicketLeaseKey(ticket))
	})
	if err != nil {
		return false, err
	}
	return moved, nil
}

// ReleaseWorkerTaskLease drops a post-record lease; released reports it existed.
func ReleaseWorkerTaskLease(ctx context.Context, s *store.Store, taskID StoredHash) (bool, error) {
	released := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		if _, err := b.Get(WorkerTaskLeaseKey(taskID)); errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		released = true
		return b.Delete(WorkerTaskLeaseKey(taskID))
	})
	if err != nil {
		return false, err
	}
	return released, nil
}

// ReleaseWorkerTaskLeaseOf drops taskID's post-record lease only if ticket
// holds it; released reports it did.
func ReleaseWorkerTaskLeaseOf(ctx context.Context, s *store.Store, taskID, ticket StoredHash) (bool, error) {
	released := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var lease WorkerLease
		err := getBatchJSON(b, WorkerTaskLeaseKey(taskID), &lease)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		case lease.TicketHash != ticket:
			return nil
		}
		released = true
		return b.Delete(WorkerTaskLeaseKey(taskID))
	})
	if err != nil {
		return false, err
	}
	return released, nil
}

// hasWorkerTaskLease reports whether taskID holds a post-record lease.
func hasWorkerTaskLease(ctx context.Context, s *store.Store, taskID StoredHash) (bool, error) {
	_, err := s.GetRaw(ctx, WorkerTaskLeaseKey(taskID))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// DispatchEvidenceScope is the evidence-store namespace of one ticket's Worker
// material (S4 Q13, S5 Q8): frames, Fin, receipt, both bundles and the
// confirmations are signed for one dispatch_ticket_hash and never mix with
// another round of the same task. The verified input stays under the task
// hash.
func DispatchEvidenceScope(taskHash, ticket StoredHash) StoredHash {
	h := sha256.New()
	h.Write([]byte("CORTEX_DISPATCH_EVIDENCE_SCOPE_V1"))
	h.Write(taskHash[:])
	h.Write(ticket[:])
	var out StoredHash
	copy(out[:], h.Sum(nil))
	return out
}

// hasWorkerLease reports whether ticket holds a pre-record lease.
func hasWorkerLease(ctx context.Context, s *store.Store, ticket StoredHash) (bool, error) {
	_, err := s.GetRaw(ctx, WorkerTicketLeaseKey(ticket))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// CountWorkerLeases counts every Worker lease, pre- and post-record.
func CountWorkerLeases(ctx context.Context, s *store.Store) (uint32, error) {
	var n uint32
	err := s.ScanPrefix(ctx, []byte(workerLeasePrefix), func(_, _ []byte) error {
		n++
		return nil
	})
	return n, err
}

// WorkerTicketLeases lists the tickets holding a pre-record lease.
func WorkerTicketLeases(ctx context.Context, s *store.Store) ([]StoredHash, error) {
	return scanHashes(ctx, s, []byte(workerTicketLeasePrefix))
}

// ErrInputBound refuses a chunk that would leave too few bytes of
// input_size_bytes for the chunks still missing.
var ErrInputBound = errors.New("dispatch input chunk out of bounds")

// StageDispatchInputChunk stores chunk index of an accepted ticket's input and
// counts it, in one batch. A redelivered identical chunk is a no-op
// (stored=false); different bytes or a different chunk_count are ErrConflict;
// a chunk that would leave less than one byte for each chunk still missing
// (so also one that would take the staged total past input_size_bytes) is
// ErrInputBound and changes nothing. Wire fixes no chunking rule, so no
// per-chunk share is imposed: any split whose chunks are non-empty fits. A ticket
// that holds no duty, or whose input is committed, is returned unchanged.
func StageDispatchInputChunk(ctx context.Context, s *store.Store, ticket StoredHash, index, count uint32, data []byte) (DispatchRecord, bool, error) {
	var out DispatchRecord
	stored := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var rec DispatchRecord
		if err := getBatchJSON(b, DispatchTicketKey(ticket), &rec); err != nil {
			return err
		}
		out = rec
		if !rec.State.HoldsDuty() || rec.InputCommitted {
			return nil
		}
		if count == 0 || index >= count {
			return fmt.Errorf("%w: chunk %d of %d", ErrInputBound, index, count)
		}
		if rec.InputChunkCount != 0 && rec.InputChunkCount != count {
			return fmt.Errorf("%w: input chunk_count changed from %d to %d", ErrConflict, rec.InputChunkCount, count)
		}
		key := DispatchInputChunkKey(ticket, index)
		cur, err := b.Get(key)
		switch {
		case err == nil:
			if !bytes.Equal(cur, data) {
				return fmt.Errorf("%w: input chunk %d of ticket %s", ErrConflict, index, ticket)
			}
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		// Room = input_size_bytes - staged - one byte per other missing chunk.
		size := uint64(len(data))
		room := rec.InputSizeBytes - rec.InputStagedBytes
		if missing := uint64(count) - uint64(rec.InputChunksReceived) - 1; missing < room {
			room -= missing
		} else {
			room = 0
		}
		if size > room {
			return fmt.Errorf("%w: %d bytes with %d staged of %d leaves the other %d missing chunks no room",
				ErrInputBound, size, rec.InputStagedBytes, rec.InputSizeBytes, uint64(count)-uint64(rec.InputChunksReceived)-1)
		}
		if err := b.Set(key, data); err != nil {
			return err
		}
		rec.InputChunkCount = count
		rec.InputChunksReceived++
		rec.InputStagedBytes += size
		stored, out = true, rec
		return putDispatch(b, rec)
	})
	if err != nil {
		return DispatchRecord{}, false, err
	}
	return out, stored, nil
}

// AssembleDispatchInput reads ticket's count chunks in index order into one
// buffer of exactly size bytes: peak memory is the input once.
func AssembleDispatchInput(ctx context.Context, s *store.Store, ticket StoredHash, count uint32, size uint64) ([]byte, error) {
	prefix := dispatchInputTicketPrefix(ticket)
	out := make([]byte, 0, size)
	next := uint32(0)
	err := s.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		if len(key) != len(prefix)+4 {
			return fmt.Errorf("malformed input chunk key under %q", prefix)
		}
		if index := binary.BigEndian.Uint32(key[len(prefix):]); index != next || index >= count {
			return fmt.Errorf("input chunk %d where %d of %d was expected", index, next, count)
		}
		if uint64(len(value)) > size-uint64(len(out)) {
			return fmt.Errorf("input chunks exceed %d bytes", size)
		}
		out = append(out, value...)
		next++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if next != count || uint64(len(out)) != size {
		return nil, fmt.Errorf("input has %d of %d chunks and %d of %d bytes", next, count, len(out), size)
	}
	return out, nil
}

// ResetDispatchInput forgets ticket's staged input (chunks and counters) so
// it is requested again at once.
func ResetDispatchInput(ctx context.Context, s *store.Store, ticket StoredHash) (DispatchRecord, error) {
	return UpdateDispatchDroppingInput(ctx, s, ticket, func(r *DispatchRecord) error {
		r.InputChunkCount, r.InputChunksReceived, r.InputStagedBytes, r.InputRequestedAtUnixMs = 0, 0, 0, 0
		return nil
	})
}

// putDispatchInputChunk stores chunk index of ticket's input once: identical
// bytes are a no-op (stored=false), different bytes ErrConflict.
func putDispatchInputChunk(ctx context.Context, s *store.Store, ticket StoredHash, index uint32, data []byte) (bool, error) {
	stored := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		key := DispatchInputChunkKey(ticket, index)
		cur, err := b.Get(key)
		switch {
		case err == nil:
			if !bytes.Equal(cur, data) {
				return fmt.Errorf("%w: input chunk %d of ticket %s", ErrConflict, index, ticket)
			}
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		stored = true
		return b.Set(key, data)
	})
	if err != nil {
		return false, err
	}
	return stored, nil
}

// dispatchInputChunks returns ticket's stored chunks by index.
func dispatchInputChunks(ctx context.Context, s *store.Store, ticket StoredHash) (map[uint32][]byte, error) {
	prefix := dispatchInputTicketPrefix(ticket)
	out := map[uint32][]byte{}
	err := s.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		if len(key) != len(prefix)+4 {
			return fmt.Errorf("malformed input chunk key under %q", prefix)
		}
		out[binary.BigEndian.Uint32(key[len(prefix):])] = bytes.Clone(value)
		return nil
	})
	return out, err
}

// deleteDispatchInputChunks drops every chunk of ticket.
func deleteDispatchInputChunks(ctx context.Context, s *store.Store, ticket StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		return deletePrefixedKeysInBatch(b, dispatchInputTicketPrefix(ticket))
	})
}
