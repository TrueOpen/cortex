package observability

import (
	"context"
	"sync"
)

// InMemoryObservationSource owns one authoritative observation snapshot. A
// single upstream Keeper-event owner replaces the complete snapshot after it
// has reconciled a finalized view; readers never receive aliased mutable data.
// This intentionally provides no crash durability.
type InMemoryObservationSource struct {
	mu   sync.RWMutex
	rows []ModelObservation
}

func NewInMemoryObservationSource(rows []ModelObservation) *InMemoryObservationSource {
	source := &InMemoryObservationSource{}
	source.ReplaceModelObservations(rows)
	return source
}

// ReplaceModelObservations atomically transfers a complete authoritative
// snapshot into the source. It is not an append-only event log.
func (s *InMemoryObservationSource) ReplaceModelObservations(rows []ModelObservation) {
	if s == nil {
		return
	}
	cloned := cloneModelObservations(rows)
	s.mu.Lock()
	s.rows = cloned
	s.mu.Unlock()
}

func (s *InMemoryObservationSource) ModelObservations(ctx context.Context) ([]ModelObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrObservationSourceRequired
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneModelObservations(s.rows), nil
}

func cloneModelObservations(rows []ModelObservation) []ModelObservation {
	if rows == nil {
		return nil
	}
	out := make([]ModelObservation, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].Payload = append([]byte(nil), out[i].Payload...)
	}
	return out
}
