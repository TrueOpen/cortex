package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// DispatchEventFact is one committed Phase 1 dispatch event other than
// dispatch_recorded. Events are hints: consumers re-read the authoritative
// Query before acting.
type DispatchEventFact struct {
	Type   chainclient.KeeperEventType
	Height uint64
	TaskID layout.StoredHash
	// Compensation events.
	TicketHash      layout.StoredHash
	Builder, Worker string
}

// DispatchEventObserver consumes DispatchEventFacts (S9 wires
// TaskRunnerConfig.DispatchEvents).
type DispatchEventObserver interface {
	ObserveDispatchEvent(context.Context, DispatchEventFact) error
}

var dispatchEventTypes = map[chainclient.KeeperEventType]bool{
	chainclient.KeeperEventDispatchCompensationClaimed:  true,
	chainclient.KeeperEventDispatchCompensationPaid:     true,
	chainclient.KeeperEventDispatchCompensationRebutted: true,
}

func eventHash32(e chainclient.KeeperEvent, name, value string) (layout.StoredHash, error) {
	raw, err := hex.DecodeString(chainclient.CanonicalEventHash32(value))
	if err != nil || len(raw) != 32 {
		return layout.StoredHash{}, fmt.Errorf("%s requires %s as Hash32", e.Type, name)
	}
	return layout.StoredHash(raw), nil
}

func dispatchEventFact(e chainclient.KeeperEvent) (DispatchEventFact, error) {
	f := DispatchEventFact{Type: e.Type, Height: e.Height}
	var err error
	if f.TaskID, err = eventHash32(e, "task_id", e.TaskID); err != nil {
		return f, err
	}
	switch e.Type {
	case chainclient.KeeperEventDispatchCompensationClaimed, chainclient.KeeperEventDispatchCompensationPaid, chainclient.KeeperEventDispatchCompensationRebutted:
		if f.TicketHash, err = eventHash32(e, "dispatch_ticket_hash", e.Attributes["dispatch_ticket_hash"]); err != nil {
			return f, err
		}
		f.Builder, f.Worker = strings.TrimSpace(e.Attributes["builder"]), strings.TrimSpace(e.Attributes["worker"])
		if f.Builder == "" || f.Worker == "" {
			return f, fmt.Errorf("%s requires builder and worker", e.Type)
		}
	}
	return f, nil
}
