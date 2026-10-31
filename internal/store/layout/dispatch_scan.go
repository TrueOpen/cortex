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
