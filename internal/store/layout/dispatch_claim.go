package layout

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/store"
)

var errCollectStop = errors.New("collect scan stop")

// DispatchClaimKey marks a ticket whose claim is unsettled.
func DispatchClaimKey(ticket StoredHash) []byte { return join([]byte(dispatchClaimPrefix), ticket[:]) }

// DispatchCollectKey marks a ticket the GC may delete after its retention.
func DispatchCollectKey(ticket StoredHash) []byte {
	return join([]byte(dispatchCollectPrefix), ticket[:])
}

// ClaimDispatches lists claimable and claim-pending tickets.
func ClaimDispatches(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
	tickets, err := scanHashes(ctx, s, []byte(dispatchClaimPrefix))
	if err != nil {
		return nil, err
	}
	return getDispatchRecords(ctx, s, tickets)
}

// CollectableDispatchTickets returns up to limit collectable tickets ordered
// by hash, strictly after after (zero: from the start).
func CollectableDispatchTickets(ctx context.Context, s *store.Store, after StoredHash, limit int) ([]StoredHash, error) {
	prefix := []byte(dispatchCollectPrefix)
	var out []StoredHash
	err := s.ScanPrefix(ctx, prefix, func(key, _ []byte) error {
		var h StoredHash
		if len(key) != len(prefix)+len(h) {
			return fmt.Errorf("malformed key under %q", prefix)
		}
		copy(h[:], key[len(prefix):])
		if !after.IsZero() && bytes.Compare(h[:], after[:]) <= 0 {
			return nil
		}
		if len(out) == limit {
			return errCollectStop
		}
		out = append(out, h)
		return nil
	})
	if errors.Is(err, errCollectStop) {
		err = nil
	}
	return out, err
}

// DeleteDispatchRecord removes a settled ticket and everything keyed by it.
// It refuses (ErrConflict) a state that is not Collectable, a ticket still
// holding a ticket- or task-keyed lease, or one still owning its task's
// InferRecord. An absent record is a no-op.
func DeleteDispatchRecord(ctx context.Context, s *store.Store, ticket StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		var rec DispatchRecord
		err := getBatchJSON(b, DispatchTicketKey(ticket), &rec)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !rec.State.Collectable() {
			return fmt.Errorf("%w: ticket %s is %s, not settled", ErrConflict, ticket, rec.State)
		}
		if _, err := b.Get(WorkerTicketLeaseKey(ticket)); err == nil {
			return fmt.Errorf("%w: ticket %s still holds its lease", ErrConflict, ticket)
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var lease WorkerLease
		switch err := getBatchJSON(b, WorkerTaskLeaseKey(rec.TaskID), &lease); {
		case err == nil && lease.TicketHash == ticket:
			return fmt.Errorf("%w: ticket %s still holds the task lease", ErrConflict, ticket)
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return err
		}
		if !rec.TaskHash.IsZero() {
			var infer InferRecord
			switch err := getBatchJSON(b, InferKey(rec.TaskHash), &infer); {
			case err == nil && infer.DispatchTicketHash == ticket:
				return fmt.Errorf("%w: ticket %s still owns its InferRecord", ErrConflict, ticket)
			case err != nil && !errors.Is(err, store.ErrNotFound):
				return err
			}
		}
		if err := deletePrefixedKeysInBatch(b, dispatchInputTicketPrefix(ticket)); err != nil {
			return err
		}
		for _, k := range [][]byte{DispatchTicketKey(ticket), DispatchTaskKey(rec.TaskID, ticket), DispatchOpenKey(ticket),
			DispatchAwaitKey(ticket), DispatchReceiptKey(ticket), DispatchClaimKey(ticket), DispatchCollectKey(ticket)} {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}
