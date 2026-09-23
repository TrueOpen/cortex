package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// busyThenFreeEligibility is a Worker eligibility resolver that refuses
// retryably until it is released, which is the shape of a node whose only GPU is
// occupied by another task.
type busyThenFreeEligibility struct {
	mu    sync.Mutex
	busy  bool
	calls int
}

func (e *busyThenFreeEligibility) Worker(context.Context, WorkerHandraiseCandidate) (policy.WorkerPrecheckInput, uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.busy {
		return policy.WorkerPrecheckInput{}, 0, builderclient.Retryable(errors.New("model service has no available handraise capacity: queue_depth=1 max_concurrency=1"))
	}
	return acceptingEligibility(), 100, nil
}

func (e *busyThenFreeEligibility) Verifier(context.Context, VerifierHandraiseCandidate) (policy.VerifierPrecheckInput, error) {
	return policy.VerifierPrecheckInput{}, nil
}

func (e *busyThenFreeEligibility) free() {
	e.mu.Lock()
	e.busy = false
	e.mu.Unlock()
}

// redriveTestRunner builds a Worker runner over a real store with the fake bus
// seam, so the test drives the production admitOrder rather than a stand-in.
func redriveTestRunner(t *testing.T, eligibility HandraiseEligibility, chain ChainStatusReader) (*TaskRunner, *store.Store, *admissionBuilder) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	builder := &admissionBuilder{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, Builder: builder, LocalWorkerAddress: "worker", ChainID: "chain",
		FakeOutput: true, FakeBus: true,
		ChainStatus:          chain,
		ProfileCapabilities:  map[string]string{"model\x001": modelservice.CapabilityLLMTextV1},
		HandraiseEligibility: eligibility,
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		SignerAddress:        "service", SignerKeyRef: "key",
		Signer: signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
			return bytes.Repeat([]byte{1}, 64), nil
		}),
	})
	return runner, db, builder
}

// The gap P1-1 alone does not close. `trueopen.task.open.*` is Core tier, so the
// retryable verdict a busy node now returns is honoured by the inbox and the
// authenticator -- and then nothing redelivers the frame. Without a local
// pending entry, "busy for the duration of one task" and "refused this order for
// good" produce the same outcome: no handraise, ever, for an order this node was
// eligible for a block later.
func TestAnOrderRefusedWhileBusyIsHandraisedWhenCapacityReturns(t *testing.T) {
	ctx := context.Background()
	eligibility := &busyThenFreeEligibility{busy: true}
	chain := &movingChainStatus{height: 50, chainID: "chain"}
	runner, db, builder := redriveTestRunner(t, eligibility, chain)

	message, taskHash := orderMessageFor(t, 1, 200)
	if err := runner.HandleNexusMessage(ctx, message); err == nil {
		t.Fatal("the busy node admitted the order")
	} else if !builderclient.IsRetryable(err) {
		t.Fatalf("the busy refusal was not retryable: %v", err)
	}
	if _, err := layout.GetCandidateAdmission(ctx, db, layout.StoredHash(taskHash)); err == nil {
		t.Fatal("a busy refusal wrote a candidate admission")
	}

	// The task that was occupying the node finishes, and the chain moves on.
	eligibility.free()
	chain.advance()
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	admission, err := layout.GetCandidateAdmission(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("the order was never handraised for after capacity returned: %v", err)
	}
	if len(admission.HandraisePayload) == 0 {
		t.Fatal("the re-driven admission stored no signed handraise")
	}
	if len(builder.payloads) != 1 {
		t.Fatalf("the re-drive published %d handraises, want exactly 1", len(builder.payloads))
	}

	// And it stops: a successful admission clears the pending entry, so a later
	// tick must not publish a second handraise for the same order.
	chain.advance()
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if len(builder.payloads) != 1 {
		t.Fatalf("the re-drive kept publishing after success: %d handraises", len(builder.payloads))
	}
}

// The backlog is bounded by the order's own chain deadline, which is the only
// bound that is authoritative: past order_expire_height nobody may handraise for
// this order, so holding it costs memory and buys nothing.
func TestAPendingOrderIsAbandonedAtItsOwnExpiryHeight(t *testing.T) {
	ctx := context.Background()
	eligibility := &busyThenFreeEligibility{busy: true}
	// The order fixture's earliest_submit_height is 100, so its expiry has to sit
	// above that; the tip starts just under it and is walked past it below.
	chain := &movingChainStatus{height: 105, chainID: "chain"}
	runner, _, builder := redriveTestRunner(t, eligibility, chain)

	message, _ := orderMessageFor(t, 1, 110)
	if err := runner.HandleNexusMessage(ctx, message); err == nil {
		t.Fatal("the busy node admitted the order")
	}

	// Past the order's own expiry, with capacity available again: the order is
	// still dropped, because the chain window is closed regardless.
	eligibility.free()
	for range 20 {
		chain.advance()
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if len(builder.payloads) != 0 {
		t.Fatalf("an expired order was handraised for: %d handraises", len(builder.payloads))
	}
	runner.orderRedriveMu.Lock()
	pending := len(runner.orderRedrives)
	runner.orderRedriveMu.Unlock()
	if pending != 0 {
		t.Fatalf("the expired order is still pending: %d entries", pending)
	}
}

// Only a retryable refusal is owed another attempt. Anything else is a decision
// -- the frame contradicts Keeper authority, or this node is not configured for
// the model -- and re-asking it on a schedule would be re-deciding it.
func TestANonRetryableRefusalIsNotRedriven(t *testing.T) {
	ctx := context.Background()
	chain := &movingChainStatus{height: 50, chainID: "chain"}
	runner, _, builder := redriveTestRunner(t,
		staticEligibility{err: errors.New("Keeper model capability does not enable WORKER inference")}, chain)

	message, _ := orderMessageFor(t, 1, 200)
	if err := runner.HandleNexusMessage(ctx, message); err == nil {
		t.Fatal("an ineligible node admitted the order")
	}
	runner.orderRedriveMu.Lock()
	pending := len(runner.orderRedrives)
	runner.orderRedriveMu.Unlock()
	if pending != 0 {
		t.Fatalf("a non-retryable refusal armed the re-drive: %d entries", pending)
	}

	chain.advance()
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if len(builder.payloads) != 0 {
		t.Fatalf("a non-retryable refusal was re-driven: %d handraises", len(builder.payloads))
	}
}

// The pending set has a ceiling, because a chain whose height cannot be read
// gives the height bound nothing to expire against.
func TestThePendingOrderSetIsBounded(t *testing.T) {
	runner := NewTaskRunner(TaskRunnerConfig{})
	tip := chainTip{height: 1, readable: true, configured: true}
	for i := range maxTrackedOrderRedrives + 50 {
		runner.updateWorkerOrderRedrive("trueopen.task.open.model", builderclient.BusEnvelope{}, nil,
			string(rune('a'+i%26))+"-"+itoa(i), 10_000, tip,
			builderclient.Retryable(errors.New("busy")))
	}
	runner.orderRedriveMu.Lock()
	pending := len(runner.orderRedrives)
	runner.orderRedriveMu.Unlock()
	if pending > maxTrackedOrderRedrives {
		t.Fatalf("pending set grew to %d, past the bound %d", pending, maxTrackedOrderRedrives)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}
