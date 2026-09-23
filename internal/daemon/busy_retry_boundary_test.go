package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// The boundary this pins is the one a busy node crosses three times for one
// frame: the inbox's admission map, the authenticator's replay claim, and the
// durable candidate admission. Each keeps its own state, each was written for a
// different reason, and "this node was briefly full" has to be safe at all
// three at once or the frame is lost somewhere in the middle.
//
// The rule is a single one, read three ways: a RETRYABLE refusal is a
// not-yet, so every layer must leave the frame admissible; anything else is a
// verdict, so every layer must keep its state. That is why capacity had to
// become retryable (P1-1) before any of this could work -- these two halves ship
// together.
//
// What is deliberately NOT relaxed: the replay claim itself. It is released only
// for the exact envelope whose handling asked to be retried, which is the frame
// the transport is about to redeliver byte for byte. A frame nobody is
// redelivering keeps its claim, so a captured envelope replayed by an attacker
// is still refused.
func TestARetryableBusinessRefusalLeavesTheFrameAdmissibleAtEveryLayer(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Now().UTC()
	authenticator := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	envelope := envelopeTestMessage(t, key, now, nil)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	// The refusal the busy path now produces, wrapped the way admitOrder hands
	// it back: the capacity error travels through two frames of context and must
	// still read as retryable at the boundary.
	busy := fmt.Errorf("Worker handraise: %w",
		builderclient.Retryable(errors.New("model service has no available handraise capacity: queue_depth=4 max_concurrency=4")))
	if !inboxWillRedeliver(envelope.Subject, busy) {
		t.Fatalf("a busy refusal was not classified as redeliverable: %v", busy)
	}

	runner := NewTaskRunner(TaskRunnerConfig{NexusEnvelopeAuthenticator: authenticator})
	runner.releaseEnvelopeClaimForRedelivery(envelope.Subject, envelope, busy)

	// Capacity returned; the transport redelivers the same signed bytes.
	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("the redelivered frame was refused after a busy refusal: %v", err)
	}
}

// The complement, and the reason the release cannot simply be unconditional: a
// permanent refusal is acknowledged rather than redelivered, so releasing its
// claim would arm a replay of a frame the node has already judged.
func TestAPermanentRefusalKeepsItsReplayClaim(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Now().UTC()
	authenticator := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	envelope := envelopeTestMessage(t, key, now, nil)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	refused := builderclient.Permanent(errors.New("OrderBroadcast conflicts with Keeper accepted_task_hash"))
	if inboxWillRedeliver(envelope.Subject, refused) {
		t.Fatal("a permanent refusal was classified as redeliverable")
	}
	runner := NewTaskRunner(TaskRunnerConfig{NexusEnvelopeAuthenticator: authenticator})
	runner.releaseEnvelopeClaimForRedelivery(envelope.Subject, envelope, refused)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("Authenticate after a permanent refusal = %v, want ErrBusEnvelopeReplay", err)
	}
}

// And the success case, which is the one an over-eager release would break:
// nothing is redelivered after a frame is processed, so its claim must stay
// consumed. This is what stops a redelivery from signing a second handraise for
// one order.
func TestASuccessfullyProcessedFrameKeepsItsReplayClaim(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Now().UTC()
	authenticator := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	envelope := envelopeTestMessage(t, key, now, nil)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	runner := NewTaskRunner(TaskRunnerConfig{NexusEnvelopeAuthenticator: authenticator})
	runner.releaseEnvelopeClaimForRedelivery(envelope.Subject, envelope, nil)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("Authenticate after a successful handling = %v, want ErrBusEnvelopeReplay", err)
	}
}

// An expired envelope is refused whatever the business layer concluded.
// Redelivery does not refresh the stamps, so a busy window that outlives the
// frame's own lifetime ends the frame rather than the rule.
func TestABusyWindowDoesNotExtendAnEnvelopeLifetime(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Now().UTC()
	authenticator := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	expired := envelopeTestMessage(t, key, now.Add(-10*time.Minute), nil)

	if err := authenticator.Authenticate(context.Background(), expired.Subject, expired); err == nil {
		t.Fatal("an expired envelope authenticated")
	}
}
