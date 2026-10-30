package layout

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/store"
)

// Phase 1 dispatch keys (CD §10 DispatchRecord, TaskProfileLease). Before the
// record entry everything is keyed by dispatch_ticket_hash.
//
// TODO(S5/S6): nothing here deletes dispatch records or their task index.
// S5 adds the task_id merge key at record time; S6 owns deleting records,
// task-index entries and revoke tombstones after the claim window and
// dispatch_evidence_retention_blocks.
const (
	dispatchTicketPrefix    = "dispatch-ticket/"
	dispatchTaskPrefix      = "dispatch-task/"
	dispatchOpenPrefix      = "dispatch-open/"
	dispatchInputPrefix     = "dispatch-input/"
	workerLeasePrefix       = "lease/worker/"
	workerTicketLeasePrefix = "lease/worker/ticket/"
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

// DispatchState is the local state of one received ticket.
type DispatchState string

const (
	DispatchOffered      DispatchState = "offered"       // W1 durable; no answer signed yet
	DispatchRejected     DispatchState = "rejected"      // DispatchRejectV1 signed
	DispatchAccepted     DispatchState = "accepted"      // DispatchAcceptV1 signed
	DispatchAcceptUnsent DispatchState = "accept-unsent" // signed, never transmitted before the deadline (C4)
	DispatchRevoked      DispatchState = "revoked"       // DispatchRevokeV1 (RBF) received
	DispatchSuperseded   DispatchState = "superseded"    // a newer round of the same task arrived
)

// dispatchTransitions lists the states each state may move to. S5 extends it
// with the record observations.
var dispatchTransitions = map[DispatchState][]DispatchState{
	DispatchOffered:      {DispatchRejected, DispatchAccepted, DispatchRevoked, DispatchSuperseded},
	DispatchAccepted:     {DispatchAcceptUnsent, DispatchRevoked, DispatchSuperseded},
	DispatchAcceptUnsent: {DispatchRevoked},
	DispatchSuperseded:   {DispatchRevoked},
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
	TicketHash             StoredHash `json:"-"`
	Builder                string     `json:"builder_operator"`
	AcceptDeadlineUnixMs   int64      `json:"accept_deadline_unix_ms,omitempty"`
	AcceptSeq              uint64     `json:"accept_seq,omitempty"`
	AcceptEnqueuing        bool       `json:"accept_enqueuing,omitempty"`
	InputRequestSeq        uint64     `json:"input_request_seq,omitempty"`
	InputRequestedAtUnixMs int64      `json:"input_requested_at_unix_ms,omitempty"`
	ClaimFromHeight        uint64     `json:"claim_from_height,omitempty"`
}

func putDispatch(b *store.Batch, rec DispatchRecord) error {
	if err := putBatchJSON(b, DispatchTicketKey(rec.TicketHash), rec); err != nil {
		return err
	}
	if rec.State == DispatchAccepted && !rec.InputCommitted {
		return putBatchJSON(b, DispatchOpenKey(rec.TicketHash), DispatchOpenEntry{
			Builder: rec.Builder, AcceptDeadlineUnixMs: rec.AcceptDeadlineUnixMs, AcceptSeq: rec.AcceptSeq,
			AcceptEnqueuing: rec.AcceptEnqueuing, InputRequestSeq: rec.InputRequestSeq,
			InputRequestedAtUnixMs: rec.InputRequestedAtUnixMs, ClaimFromHeight: rec.ClaimFromHeight,
		})
	}
	return b.Delete(DispatchOpenKey(rec.TicketHash))
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
	} {
		if len(f.cur) > 0 && !bytes.Equal(f.cur, f.next) {
			return fmt.Errorf("%w: dispatch %s is write-once", ErrConflict, f.name)
		}
	}
	if !cur.AcceptDigest.IsZero() && next.AcceptDigest != cur.AcceptDigest {
		return fmt.Errorf("%w: dispatch accept digest is write-once", ErrConflict)
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
// same batch.
//
// TODO(S6): tombstones and revoked records are never deleted here; S6 owns
// their GC once dispatch_evidence_retention_blocks has passed.
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

// OpenDispatchEntries returns the open index: accepted tickets whose input is
// not committed, without loading their records.
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

// OpenDispatches returns accepted tickets whose input is not committed.
func OpenDispatches(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
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

// HasWorkerLease reports whether ticket holds a pre-record lease.
func HasWorkerLease(ctx context.Context, s *store.Store, ticket StoredHash) (bool, error) {
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

// ErrInputBound refuses a chunk that would stage more than input_size_bytes,
// or one far larger than an even share of it.
var ErrInputBound = errors.New("dispatch input chunk out of bounds")

// inputChunkSlack is the constant part of DispatchInputChunkLimit, for small
// inputs split unevenly.
const inputChunkSlack = 4096

// DispatchInputChunkLimit bounds one chunk of a size-byte input sent as count
// chunks. Wire fixes no chunking rule, so it has to admit both an even split
// (every chunk at most ceil(size/count)) and fixed-size chunking with a short
// last chunk, where a chunk can reach almost twice the even share (size C+1
// as two chunks: C and 1). Twice the even share plus a small constant admits
// both; the cumulative bound (input_size_bytes) is the hard one.
func DispatchInputChunkLimit(size uint64, count uint32) uint64 {
	if count == 0 {
		return 0
	}
	share := size / uint64(count)
	if size%uint64(count) != 0 {
		share++
	}
	return 2*share + inputChunkSlack
}

// StageDispatchInputChunk stores chunk index of an accepted ticket's input and
// counts it, in one batch. A redelivered identical chunk is a no-op
// (stored=false); different bytes or a different chunk_count are ErrConflict;
// a chunk that would take the staged total past input_size_bytes, or exceeds
// DispatchInputChunkLimit, is ErrInputBound and changes nothing. A ticket
// that is not accepted, or whose input is committed, is returned unchanged.
func StageDispatchInputChunk(ctx context.Context, s *store.Store, ticket StoredHash, index, count uint32, data []byte) (DispatchRecord, bool, error) {
	var out DispatchRecord
	stored := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var rec DispatchRecord
		if err := getBatchJSON(b, DispatchTicketKey(ticket), &rec); err != nil {
			return err
		}
		out = rec
		if rec.State != DispatchAccepted || rec.InputCommitted {
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
		size := uint64(len(data))
		if size > rec.InputSizeBytes-rec.InputStagedBytes {
			return fmt.Errorf("%w: %d staged + %d exceeds input_size_bytes %d", ErrInputBound, rec.InputStagedBytes, size, rec.InputSizeBytes)
		}
		if limit := DispatchInputChunkLimit(rec.InputSizeBytes, count); size > limit {
			return fmt.Errorf("%w: chunk of %d bytes exceeds %d for %d chunks of %d bytes", ErrInputBound, size, limit, count, rec.InputSizeBytes)
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

// PutDispatchInputChunk stores chunk index of ticket's input once: identical
// bytes are a no-op (stored=false), different bytes ErrConflict.
func PutDispatchInputChunk(ctx context.Context, s *store.Store, ticket StoredHash, index uint32, data []byte) (bool, error) {
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

// DispatchInputChunks returns ticket's stored chunks by index.
func DispatchInputChunks(ctx context.Context, s *store.Store, ticket StoredHash) (map[uint32][]byte, error) {
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

// DeleteDispatchInputChunks drops every chunk of ticket.
func DeleteDispatchInputChunks(ctx context.Context, s *store.Store, ticket StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		return deletePrefixedKeysInBatch(b, dispatchInputTicketPrefix(ticket))
	})
}
