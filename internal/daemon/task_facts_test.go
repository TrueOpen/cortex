package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
)

const factsTestTaskID = "1111111111111111111111111111111111111111111111111111111111111111"

type stubTaskReceiptFacts struct {
	asked []string
	// answerFor is the task this stub CLAIMS to have answered for. Empty means
	// it answers honestly, for whatever it was asked; a value is a reader that
	// serves one task's values under another task's name.
	answerFor string
	snapshot  chainclient.TaskReceiptFactsSnapshot
	err       error
}

// ChainHeight is what makes the stub a KeeperClient, which is the type
// NewTaskFacts narrows from. Without it the stub could only be handed to the
// capability interface directly, and the test would never exercise the
// narrowing.
func (*stubTaskReceiptFacts) ChainHeight(context.Context) (uint64, error) { return 20, nil }

func (s *stubTaskReceiptFacts) TaskReceiptFacts(
	_ context.Context,
	taskID string,
) (chainclient.TaskReceiptFactsAnswer, error) {
	s.asked = append(s.asked, taskID)
	if s.err != nil {
		return chainclient.TaskReceiptFactsAnswer{}, s.err
	}
	answered := s.answerFor
	if answered == "" {
		answered = taskID
	}
	return chainclient.TaskReceiptFactsAnswer{TaskID: answered, TaskReceiptFactsSnapshot: s.snapshot}, nil
}

func factsTestSnapshot() chainclient.TaskReceiptFactsSnapshot {
	return chainclient.TaskReceiptFactsSnapshot{
		AcceptedTaskHash:       chainclient.ProtoBytes32(bytes.Repeat([]byte{0x22}, 32)),
		GenerationParamsDigest: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x33}, 32)),
	}
}

// TestKeeperTaskFactsCarriesTheIdentityTheReaderAnswered pins the chain of
// custody the consumers' identity check depends on: the label on the Facts is
// the one the READER stated, and chainclient.TaskReceiptFacts only states an id
// it has checked against the served TaskCoreState.task_id and
// TaskAssignmentViewV1.task_id.
func TestKeeperTaskFactsCarriesTheIdentityTheReaderAnswered(t *testing.T) {
	keeper := &stubTaskReceiptFacts{snapshot: factsTestSnapshot()}

	facts, err := NewTaskFacts(keeper).TaskFacts(context.Background(), factsTestTaskID)
	if err != nil {
		t.Fatalf("TaskFacts: %v", err)
	}
	if facts.TaskID != factsTestTaskID {
		t.Fatalf("answered task = %q, want the queried %q", facts.TaskID, factsTestTaskID)
	}
	if len(keeper.asked) != 1 || keeper.asked[0] != factsTestTaskID {
		t.Fatalf("Keeper asked = %#v, want exactly the requested task", keeper.asked)
	}
	if !bytes.Equal(facts.AcceptedTaskHash, factsTestSnapshot().AcceptedTaskHash) ||
		!bytes.Equal(facts.GenerationParamsDigest, factsTestSnapshot().GenerationParamsDigest) {
		t.Fatalf("facts = %#v, want the served snapshot passed through unchanged", facts)
	}
	if err := facts.Validate(factsTestTaskID); err != nil {
		t.Fatalf("the adapter's own answer does not satisfy the consumer check: %v", err)
	}
}

// TestKeeperTaskFactsKeepsRetryabilityDistinctFromAbsence is the requirement that
// a transport failure and a missing value never collapse. The first must reach
// the task runner as retryable so the read is attempted again; the second is a
// permanent refusal the consumer raises from the served value.
func TestKeeperTaskFactsKeepsRetryabilityDistinctFromAbsence(t *testing.T) {
	transport := errors.New("keeper ABCI query failed")
	retryable := NewTaskFacts(&stubTaskReceiptFacts{err: chainclient.Retryable(transport)})
	if _, err := retryable.TaskFacts(context.Background(), factsTestTaskID); err == nil ||
		!builderclient.IsRetryable(err) || !errors.Is(err, transport) {
		t.Fatalf("TaskFacts error = %v, want a builderclient-retryable wrap of the Keeper failure", err)
	}

	permanent := NewTaskFacts(&stubTaskReceiptFacts{err: transport})
	if _, err := permanent.TaskFacts(context.Background(), factsTestTaskID); err == nil ||
		builderclient.IsRetryable(err) {
		t.Fatalf("TaskFacts error = %v, want a permanent Keeper failure", err)
	}

	// A well-formed response that lacks a fact is not an error at this layer at
	// all: it comes back unset and the consumer refuses it, which is what keeps
	// "the chain does not carry this" from looking like "the query failed".
	absent := NewTaskFacts(&stubTaskReceiptFacts{snapshot: chainclient.TaskReceiptFactsSnapshot{
		AcceptedTaskHash: factsTestSnapshot().AcceptedTaskHash,
	}})
	facts, err := absent.TaskFacts(context.Background(), factsTestTaskID)
	if err != nil {
		t.Fatalf("TaskFacts reported an absent fact as a read failure: %v", err)
	}
	if err := facts.Validate(factsTestTaskID); err == nil ||
		!strings.Contains(err.Error(), "carries no generation_params_digest") {
		t.Fatalf("Validate error = %v, want the absent fact refused at the consumer", err)
	}
}

// TestKeeperTaskFactsRefusesANonCanonicalTaskID keeps the adapter from
// normalizing a caller's id and then labelling the answer with the normalized
// form, which would make the consumer's identity check pass for an id the caller
// never actually holds.
func TestKeeperTaskFactsRefusesANonCanonicalTaskID(t *testing.T) {
	keeper := &stubTaskReceiptFacts{snapshot: factsTestSnapshot()}
	reader := NewTaskFacts(keeper)
	for name, taskID := range map[string]string{
		"empty":            "",
		"padded":           " " + factsTestTaskID,
		"trailing newline": factsTestTaskID + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := reader.TaskFacts(context.Background(), taskID); err == nil ||
				!strings.Contains(err.Error(), "canonical task id") {
				t.Fatalf("TaskFacts error = %v, want a canonical-id refusal", err)
			}
		})
	}
	if len(keeper.asked) != 0 {
		t.Fatalf("Keeper was queried for %#v despite a non-canonical id", keeper.asked)
	}
}

// TestKeeperTaskFactsRefusesAReaderThatAnsweredForAnotherTask is the seam's own
// fail-closed property, and it is about an INJECTED reader rather than the
// shipped one. *chainclient.KeeperABCIClient checks both served identities
// itself, but the whole point of routing every consumer through one capability
// is that a Keeper can be supplied, so the seam must not rest on the
// implementation being trustworthy.
//
// The misbehaviour modelled here is the realistic one: a reader with a snapshot
// cached under the wrong key answers task A's request with task B's values and
// says so. Nothing about those bytes is malformed, so this refusal is the only
// thing between them and a receipt signed over another Task's consensus state.
func TestKeeperTaskFactsRefusesAReaderThatAnsweredForAnotherTask(t *testing.T) {
	other := strings.Repeat("ab", 32)
	keeper := &stubTaskReceiptFacts{answerFor: other, snapshot: factsTestSnapshot()}

	facts, err := NewTaskFacts(keeper).TaskFacts(context.Background(), factsTestTaskID)
	if err == nil {
		t.Fatalf("TaskFacts = %#v, nil error: an answer for another task must not be accepted", facts)
	}
	for _, want := range []string{"stubTaskReceiptFacts", other, factsTestTaskID, "another Task"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to name %q", err, want)
		}
	}
	// No facts escape, under either identity. A relabelled answer would satisfy
	// the consumer's own Validate, so the refusal has to be total.
	if facts.TaskID != "" || facts.AcceptedTaskHash.IsSet() || facts.GenerationParamsDigest.IsSet() {
		t.Fatalf("a refused read still produced facts: %#v", facts)
	}
	if facts.Validate(factsTestTaskID) == nil || facts.Validate(other) == nil {
		t.Fatalf("the refused answer is still usable by a consumer: %#v", facts)
	}
	// Permanent: the reader will keep answering for the wrong task.
	if builderclient.IsRetryable(err) {
		t.Fatalf("a wrong-task answer was reported as retryable: %v", err)
	}
}

// TestNewTaskFactsWithoutAKeeperYieldsNoProvider covers config.ModeFake, which
// is the one shipped configuration that leaves Dependencies.Keeper nil
// (BuildDependencies returns before it assigns one). No Keeper means no
// provider, and the Worker and Verifier refuse before any inference or
// signature.
func TestNewTaskFactsWithoutAKeeperYieldsNoProvider(t *testing.T) {
	if reader := NewTaskFacts(nil); reader != nil {
		t.Fatalf("reader = %#v, want no provider without a Keeper reader", reader)
	}
}

// heightOnlyKeeper is a KeeperClient that satisfies the runtime's injection
// point and nothing else. Only RuntimeOptions.Keeper can introduce one, which
// cmd/cortexd never sets, but an embedder can - so the branch has to behave.
type heightOnlyKeeper struct{}

func (heightOnlyKeeper) ChainHeight(context.Context) (uint64, error) { return 20, nil }

// TestNewTaskFactsFailsClosedByNameForAKeeperWithoutTheCapability exercises the
// narrowing FAILING. The requirement is not merely "no panic": the reader must
// be non-nil, every call must fail, and the message must name the missing
// capability so the failure cannot be read as a missing config line or as a
// chain that does not carry the value.
func TestNewTaskFactsFailsClosedByNameForAKeeperWithoutTheCapability(t *testing.T) {
	reader := NewTaskFacts(heightOnlyKeeper{})
	if reader == nil {
		t.Fatal("reader = nil for a Keeper without the capability: a nil is indistinguishable from no Keeper at all")
	}
	facts, err := reader.TaskFacts(context.Background(), factsTestTaskID)
	if err == nil {
		t.Fatalf("TaskFacts = %#v, nil error: a Keeper that cannot read must not answer", facts)
	}
	for _, want := range []string{
		"heightOnlyKeeper",
		"cannot serve the frozen task.v1 Query/Task",
		"chainclient.KeeperABCIClient.TaskReceiptFacts",
		"Cortex wiring fault, not a chain state that lacks the value",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to name %q", err, want)
		}
	}
	// Nothing usable may escape, and retrying cannot help.
	if facts.TaskID != "" || facts.AcceptedTaskHash.IsSet() || facts.GenerationParamsDigest.IsSet() {
		t.Fatalf("a refused read still produced facts: %#v", facts)
	}
	if builderclient.IsRetryable(err) {
		t.Fatalf("a Keeper that cannot serve the read was reported as retryable: %v", err)
	}
}

// TestTaskFactsFailureModesAreDistinguishable is the operator-facing property:
// "the Keeper cannot do this read", "the read failed" and "the chain answered
// without the value" are three different faults with three different responses,
// and no two of them may produce the same message.
func TestTaskFactsFailureModesAreDistinguishable(t *testing.T) {
	unsupported := NewTaskFacts(heightOnlyKeeper{})
	_, capabilityErr := unsupported.TaskFacts(context.Background(), factsTestTaskID)

	transport := NewTaskFacts(&stubTaskReceiptFacts{err: chainclient.Retryable(errors.New("dial tcp: connection refused"))})
	_, transportErr := transport.TaskFacts(context.Background(), factsTestTaskID)

	served := NewTaskFacts(&stubTaskReceiptFacts{snapshot: chainclient.TaskReceiptFactsSnapshot{
		AcceptedTaskHash: factsTestSnapshot().AcceptedTaskHash,
	}})
	facts, err := served.TaskFacts(context.Background(), factsTestTaskID)
	if err != nil {
		t.Fatalf("a well-formed answer was reported as a read failure: %v", err)
	}
	absentErr := facts.Validate(factsTestTaskID)

	messages := map[string]error{
		"capability": capabilityErr,
		"transport":  transportErr,
		"absent":     absentErr,
	}
	for name, err := range messages {
		if err == nil {
			t.Fatalf("%s failure produced no error", name)
		}
	}
	for a, errA := range messages {
		for b, errB := range messages {
			if a < b && errA.Error() == errB.Error() {
				t.Fatalf("the %s and %s failures are one indistinguishable message: %v", a, b, errA)
			}
		}
	}
	// Only the transport failure is worth retrying; the other two are permanent
	// and retrying them would spin on a fault a retry cannot fix.
	if !builderclient.IsRetryable(transportErr) {
		t.Fatalf("transport failure = %v, want it retryable", transportErr)
	}
	if builderclient.IsRetryable(capabilityErr) || builderclient.IsRetryable(absentErr) {
		t.Fatalf("a permanent fault was marked retryable: capability=%v absent=%v", capabilityErr, absentErr)
	}
}

// TestKeeperABCIClientSatisfiesTheTaskFactsCapability is the runtime companion
// to the compile-time assertion in task_facts.go. runtime.go builds exactly this
// type when no Keeper is injected, and cmd/cortexd never injects one, so this
// pins that the shipped path takes the capable arm of NewTaskFacts rather than
// the fail-closed one.
func TestKeeperABCIClientSatisfiesTheTaskFactsCapability(t *testing.T) {
	reader := NewTaskFacts(chainclient.NewKeeperABCIClient("http://127.0.0.1:26657"))
	if _, unsupported := reader.(unsupportedTaskFacts); unsupported || reader == nil {
		t.Fatalf("reader = %#v, want the capable adapter for the client runtime.go constructs", reader)
	}
}
