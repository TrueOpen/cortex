package layout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/store"
)

var errStopScan = errors.New("stop scan")

// scanDispatchRecords visits every stored DispatchRecord.
func scanDispatchRecords(ctx context.Context, s *store.Store, fn func(DispatchRecord) error) error {
	err := s.ScanPrefix(ctx, []byte(dispatchTicketPrefix), func(key, value []byte) error {
		var rec DispatchRecord
		if err := json.Unmarshal(value, &rec); err != nil {
			return fmt.Errorf("dispatch record %x: %w", key[len(dispatchTicketPrefix):], err)
		}
		return fn(rec)
	})
	if errors.Is(err, errStopScan) {
		return nil
	}
	return err
}

// BuilderHoldsDuty reports whether a ticket from builder still holds a duty
// (accepted, pending-claim, recorded): a Builder being removed keeps its
// stream until this is false (CD §15.3).
func BuilderHoldsDuty(ctx context.Context, s *store.Store, builder string) (bool, error) {
	busy := false
	err := scanDispatchRecords(ctx, s, func(r DispatchRecord) error {
		if r.Builder == builder && r.State.HoldsDuty() {
			busy = true
			return errStopScan
		}
		return nil
	})
	return busy, err
}

// DispatchScopeOwner finds the ticket whose DispatchEvidenceScope is scope,
// so evidence cleanup can follow the task it belongs to (S6 Q9).
func DispatchScopeOwner(ctx context.Context, s *store.Store, scope StoredHash) (DispatchRecord, bool, error) {
	var out DispatchRecord
	found := false
	err := scanDispatchRecords(ctx, s, func(r DispatchRecord) error {
		if DispatchEvidenceScope(r.TaskHash, r.TicketHash) == scope {
			out, found = r, true
			return errStopScan
		}
		return nil
	})
	return out, found, err
}

// DispatchAnchorSlotHolders returns the records whose ticket holds an audit
// slot of the anchor admission gate while the node runs: an accepted or
// pending-claim ticket; a recorded ticket whose task still holds a Worker
// lease (under the ticket key, or under (task_id, WORKER) for a task still
// running); and a recorded ticket with a signed receipt, whose commitment may
// be on its way. A recorded ticket without a receipt whose lease is gone is a
// task that ended with no commitment: it holds nothing, though its record
// stays until the GC.
func DispatchAnchorSlotHolders(ctx context.Context, s *store.Store) ([]DispatchRecord, error) {
	var recorded, out []DispatchRecord
	err := scanDispatchRecords(ctx, s, func(r DispatchRecord) error {
		switch {
		case r.State == DispatchRecorded && len(r.Receipt) == 0:
			recorded = append(recorded, r)
		case r.State.HoldsDuty():
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, r := range recorded {
		held, err := hasWorkerLease(ctx, s, r.TicketHash)
		if err == nil && !held {
			held, err = hasWorkerTaskLease(ctx, s, r.TaskID)
		}
		if err != nil {
			return nil, fmt.Errorf("lease of ticket %s: %w", r.TicketHash, err)
		}
		if held {
			out = append(out, r)
		}
	}
	return out, nil
}

// DispatchAnswer is one row of the reject-rate metric (S4 Q16).
type DispatchAnswer struct {
	Builder     string
	Answer      string // "accept" or "reject"
	BuilderSide bool   // CD §5.1 2a: a Builder-side reject, not this node's
}

// DispatchAnswerCounts counts the retained tickets this node answered.
func DispatchAnswerCounts(ctx context.Context, s *store.Store) (map[DispatchAnswer]uint64, error) {
	out := map[DispatchAnswer]uint64{}
	err := scanDispatchRecords(ctx, s, func(r DispatchRecord) error {
		switch {
		case len(r.Accept) > 0:
			out[DispatchAnswer{Builder: r.Builder, Answer: "accept"}]++
		case len(r.Reject) > 0:
			out[DispatchAnswer{Builder: r.Builder, Answer: "reject", BuilderSide: r.RejectBuilderSide}]++
		}
		return nil
	})
	return out, err
}
