package daemon

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// order_sequence = 0 is the first order of every session, not an unset field.
//
// Keeper builds StreamState without assigning NextExpectedSequence, so the Go
// zero value is what the first order must carry, and consumeOrderSequence
// requires each order to equal it exactly (node x/task/keeper). Nexus
// stopped rejecting it at ingress in nexus#60; Cortex kept rejecting it on the
// bus, which is what "OpenTask task identity does not match order_sequence"
// meant on a live devnet order.
//
// There is also nothing to detect here: order_sequence is a proto3 scalar and a
// JSON number, neither of which distinguishes "the user wrote 0" from "the field
// was absent". What actually binds the value is the identity equation below -
// task_id = H_FIELDS_V1(TRUEOPEN_TASK_ID_V1, session_id, order_sequence) - which
// holds a zero sequence to exactly the same standard as any other.
func TestHandleNexusMessageAdmitsSessionFirstOrderSequenceZero(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	builder := &admissionBuilder{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, Builder: builder, LocalWorkerAddress: "worker", ChainID: "chain",
		FakeOutput: true, FakeBus: true,
		ProfileCapabilities:  map[string]string{testModelID + "\x001": modelservice.CapabilityLLMTextV1},
		HandraiseEligibility: staticEligibility{input: acceptingEligibility(), expiry: 100},
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		SignerAddress:        "service", SignerKeyRef: "key",
		Signer: signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
			return bytes.Repeat([]byte{1}, 64), nil
		}),
	})

	message, taskHash := orderMessageWithSequence(t, 0)
	if err := runner.HandleNexusMessage(ctx, message); err != nil {
		t.Fatalf("HandleNexusMessage() error = %v, want the session's first order admitted", err)
	}
	admission, err := layout.GetCandidateAdmission(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetCandidateAdmission() error = %v, want a durable handraise", err)
	}
	if len(admission.HandraisePayload) == 0 {
		t.Fatal("admitted order stored no signed handraise")
	}
}

// TestKeeperHandraiseEligibilityAcceptsSessionFirstOrderSequenceZero covers the
// second gate on the same path. Admission and eligibility both derive the same
// canonical task id, so a zero-sequence rejection in either one stops the
// handraise; fixing only the first would move the refusal one frame later.
func TestKeeperHandraiseEligibilityAcceptsSessionFirstOrderSequenceZero(t *testing.T) {
	const session = "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: activeHandraiseKeeper(), Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})

	input, expires, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString(session, 0), SessionID: session, OrderSequence: 0, ModelID: modelservice.FakeModelID,
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	})
	if err != nil {
		t.Fatalf("Worker eligibility error = %v, want the session's first order accepted", err)
	}
	if !policy.EvaluateWorkerPrecheck(input).Accepted || expires != 140 {
		t.Fatalf("Worker eligibility = %#v expires=%d", input, expires)
	}

	// The identity equation still has to bite at sequence 0: a task_id derived
	// from a different sequence must be refused, or dropping the zero check
	// would have replaced one bug with a hole.
	if _, _, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString(session, 1), SessionID: session, OrderSequence: 0, ModelID: modelservice.FakeModelID,
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	}); err == nil {
		t.Fatal("Worker eligibility accepted a task_id that does not derive from order_sequence 0")
	}
}
