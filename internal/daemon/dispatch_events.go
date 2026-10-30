package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
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
	// Challenge events (S8).
	ChallengeID layout.StoredHash
	Kind        sharedv1.DispatchChallengeKindV1
	Challenger  string
}

// DispatchEventObserver consumes DispatchEventFacts (S9 wires
// TaskRunnerConfig.DispatchEvents, a DispatchEventObservers fan-out of the
// Dispatcher and the OmissionWatcher).
type DispatchEventObserver interface {
	ObserveDispatchEvent(context.Context, DispatchEventFact) error
}

var dispatchEventTypes = map[chainclient.KeeperEventType]bool{
	chainclient.KeeperEventDispatchCompensationClaimed:  true,
	chainclient.KeeperEventDispatchCompensationPaid:     true,
	chainclient.KeeperEventDispatchCompensationRebutted: true,
	chainclient.KeeperEventDispatchChallengeOpened:      true,
	chainclient.KeeperEventDispatchChallengeResolved:    true,
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
	case chainclient.KeeperEventDispatchChallengeOpened, chainclient.KeeperEventDispatchChallengeResolved:
		if f.ChallengeID, err = eventHash32(e, "challenge_id", e.Attributes["challenge_id"]); err != nil {
			return f, err
		}
		kind, ok := sharedv1.DispatchChallengeKindV1_value[strings.TrimSpace(e.Attributes["kind"])]
		if !ok || kind == 0 {
			return f, fmt.Errorf("%s requires a known kind", e.Type)
		}
		f.Kind, f.Challenger = sharedv1.DispatchChallengeKindV1(kind), strings.TrimSpace(e.Attributes["challenger"])
	}
	return f, nil
}

// DispatchEventObservers fans an event out to every observer (S9: the
// Dispatcher and the OmissionWatcher, as TaskRunnerConfig.DispatchEvents).
// All see it; any retryable error makes the joined error retryable
// (observers are idempotent).
type DispatchEventObservers []DispatchEventObserver

func (o DispatchEventObservers) ObserveDispatchEvent(ctx context.Context, f DispatchEventFact) error {
	errs := make([]error, 0, len(o))
	for _, x := range o {
		errs = append(errs, x.ObserveDispatchEvent(ctx, f))
	}
	return joinObserverErrs(errs)
}

// DispatchRecordObservers fans dispatch_recorded out the same way (S9:
// TaskRunnerConfig.DispatchRecords).
type DispatchRecordObservers []DispatchRecordObserver

func (o DispatchRecordObservers) ObserveDispatchRecorded(ctx context.Context, f DispatchRecordedFact) error {
	errs := make([]error, 0, len(o))
	for _, x := range o {
		errs = append(errs, x.ObserveDispatchRecorded(ctx, f))
	}
	return joinObserverErrs(errs)
}

func joinObserverErrs(errs []error) error {
	err := errors.Join(errs...)
	if err != nil && slices.ContainsFunc(errs, func(e error) bool { return builderclient.IsRetryable(e) || chainclient.IsRetryable(e) }) {
		return builderclient.Retryable(err)
	}
	return err
}
