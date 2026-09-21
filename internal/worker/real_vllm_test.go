package worker

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
)

const (
	envWorkerVLLMURL       = "CORTEX_TEST_VLLM_URL"
	envWorkerVLLMKeeperRPC = "CORTEX_TEST_VLLM_KEEPER_RPC"
	envWorkerVLLMModel     = "CORTEX_TEST_VLLM_MODEL"
	envWorkerVLLMPrompt    = "CORTEX_TEST_VLLM_PROMPT"
)

// keeperWorkerProfileResolver mirrors internal/daemon's unexported
// keeperLocalProfileResolver: read the chain's current profile and hand back the
// snapshot the local service applies. Using the chain rather than a fixture
// matters here because the profile carries the generation params the receipt
// commits to, so a fixture would have the worker sign material no verifier could
// reproduce.
type keeperWorkerProfileResolver struct {
	keeper *chainclient.KeeperABCIClient
}

func (r keeperWorkerProfileResolver) ResolveLocalProfile(ctx context.Context, modelID string, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	snapshot, err := r.keeper.CurrentModelProfile(ctx, modelID, profileVersion)
	if err != nil {
		return chainclient.CurrentProfileSnapshot{}, err
	}
	return snapshot.Profile, nil
}

// The Worker layer against a real model service. internal/modelservice already
// covers infer and verify against live vLLM; what is unverified above it is
// everything the Worker does with a REAL inference result: package the output,
// derive the receipt, sign it, and persist evidence. Every existing worker test
// runs with FakeOutput true and a fake service, so the output is a fixture of
// known size and shape. Real vLLM output is 128 generated tokens and a ~75KB
// logprob trace, which is where size bounds, canonical encoding and digest
// computation over real data actually get exercised.
//
// Requires CORTEX_TEST_VLLM_KEEPER_RPC as well as the vLLM URL: without the
// chain profile the model id on the event cannot be the one the chain committed,
// and the receipt would bind generation params nothing else can reproduce.
func TestWorkerHandlesRealVLLMInference(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envWorkerVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM worker test", envWorkerVLLMURL)
	}
	keeperRPC := strings.TrimSpace(os.Getenv(envWorkerVLLMKeeperRPC))
	if keeperRPC == "" {
		t.Skipf("set %s to resolve the chain profile the receipt must bind", envWorkerVLLMKeeperRPC)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const serviceID = "real-vllm-worker"
	service := modelservice.NewLocalService(endpoint, serviceID, 1, 5*time.Minute, 5*time.Minute)
	service.SetProfileResolver(keeperWorkerProfileResolver{keeper: chainclient.NewKeeperABCIClient(keeperRPC)})

	caps, err := service.ListCapabilities(ctx, modelservice.ListCapabilitiesRequest{RequestID: "real-vllm-worker-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatal("ListCapabilities() returned no models")
	}
	modelID := strings.TrimSpace(os.Getenv(envWorkerVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}

	// The locked Profile fields the receipt commits to. Zeros here would produce
	// a well-formed worker-value commitment that commits nothing, and the frozen
	// handler refuses rather than letting that through — so they come from the
	// chain, like everything else the receipt binds.
	profile, err := chainclient.NewKeeperABCIClient(keeperRPC).CurrentModelProfile(ctx, modelID, "1")
	if err != nil {
		t.Fatalf("CurrentModelProfile(%q) error = %v", modelID, err)
	}
	// Mirrors internal/daemon/task_executors.go:58-66, which is the path a
	// deployed Worker takes. Both fields have to come from the same locked
	// profile: the hash is what the commitment binds, and the requirements are
	// what bound its encoded size.
	verification := profile.Profile.VerificationProfile
	evidenceSchemaHash := verification.EvidenceSchemaHash.Hex()
	if strings.Trim(evidenceSchemaHash, "0") == "" {
		t.Fatalf("chain profile %s@1 publishes no verification_profile.evidence_schema_hash", modelID)
	}
	requirements := make([]builderclient.InferEvidenceRequirement, len(verification.EvidenceSchema.RequiredInferEvidence))
	for index, requirement := range verification.EvidenceSchema.RequiredInferEvidence {
		requirements[index] = builderclient.InferEvidenceRequirement{
			EvidenceKind:            nodewire.EvidenceKind(requirement.EvidenceKind),
			CommitmentSchemaVersion: requirement.CommitmentSchemaVersion,
			MaxEncodedSizeBytes:     requirement.MaxEncodedSizeBytes.Uint64(),
		}
	}
	if len(requirements) == 0 {
		t.Fatalf("chain profile %s@1 publishes no evidence_schema.required_infer_evidence", modelID)
	}
	t.Logf("locked profile: evidence_schema_hash=%s requirements=%+v", evidenceSchemaHash, requirements)

	h := newHarnessWithConfig(t, func(cfg *Config) {
		cfg.Model = service
		// Artifact refs are namespaced by service id, so the worker must be told
		// the same one or it refuses its own output.
		cfg.ModelServiceID = serviceID
		cfg.FakeOutput = false
		cfg.EvidenceSchemaHash = evidenceSchemaHash
		cfg.ProfileEvidenceRequirements = requirements
	})

	// Outside the fixture path the worker signs the OUTPUT_AVAILABLE envelope, so
	// it needs a canonical bus signer. Envelope authentication is covered
	// elsewhere; here it just has to be real enough not to be the thing under
	// test. Set after construction, which is how the existing tests in this file
	// adjust it.
	h.worker.cfg.NexusEnvelopeSigner = builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		digest, err := builderclient.BusEnvelopeSignDigest(envelope)
		if err != nil {
			return nil, err
		}
		return randomizedCompactSignature(h.signer.private, digest)
	})

	event := finalizedTask()
	event.ModelID = modelID
	event.ProfileVersion = 1
	prompt := strings.TrimSpace(os.Getenv(envWorkerVLLMPrompt))
	if prompt == "" {
		prompt = "Name one property of a deterministic verifier."
	}
	event.Input = []byte(prompt)
	h.snapshotReader.seedFrom(event)
	generation := nodewire.GenerationContext{
		ModelID: modelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 1024, MaxOutputDuration: 300000,
			DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}},
	}
	generationDigest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.worker.cfg.GenerationReader = generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
		return generation.Clone(), nil
	})
	h.taskFacts.override = func(taskID string) (taskfacts.Facts, error) {
		facts := workerTestServedTaskFacts(taskID)
		facts.GenerationParamsDigest = chainclient.ProtoBytes32(generationDigest[:])
		return facts, nil
	}

	result, err := h.worker.HandleAssignmentFinalized(ctx, event)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized() error = %v", err)
	}

	t.Logf("worker result: started=%v deadline=%d output_ref=%q package_hash=%x",
		result.Started, result.InferDeadlineHeight, result.OutputRef, result.PackageHash)
	t.Logf("receipt: task=%s output_hash=%x result_hash=%x summary=%q",
		result.Receipt.TaskID, result.Receipt.OutputHash,
		result.Receipt.ReceiptResultHash, result.Receipt.ActualOutputSummary)
	t.Logf("signed receipt: domain=%s window=[%d,%d] signature=%dB",
		result.SignedReceipt.Domain, result.SignedReceipt.ValidFromHeight,
		result.SignedReceipt.ValidUntilHeight, len(result.SignedReceipt.Signature))

	if !result.Started {
		t.Fatal("result.Started = false, want the worker to have run the inference")
	}
	// A real run must not look like the fixture path: the fake service returns a
	// fixed small output, so a zero digest or an empty package would mean the
	// worker never touched vLLM.
	if result.Receipt.OutputHash == (codec.Hash{}) {
		t.Fatal("receipt output hash is zero, want a digest over the real output")
	}
	if result.PackageHash == (codec.Hash{}) {
		t.Fatal("package hash is zero, want the packaged real output")
	}
	if result.Receipt.ReceiptResultHash == (codec.Hash{}) {
		t.Fatal("receipt result hash is zero, want the derived receipt digest")
	}
	if len(result.SignedReceipt.Signature) == 0 {
		t.Fatal("signed receipt carries no signature")
	}
	if result.Receipt.TaskID != event.TaskID {
		t.Fatalf("receipt task id = %q, want the canonical %q", result.Receipt.TaskID, event.TaskID)
	}
	if result.SignedReceipt.ValidUntilHeight != event.InferDeadlineHeight {
		t.Fatalf("receipt valid-until = %d, want the Keeper deadline %d",
			result.SignedReceipt.ValidUntilHeight, event.InferDeadlineHeight)
	}

	t.Logf("persisted: %s", describeRealVLLMPersistence(h.persistence))

	// Evidence is what a challenge would be answered from, so an empty or stub
	// persistence layer after a real inference is silent data loss. The trace is
	// the one that distinguishes a real run: the fake service emits a fixture of
	// a few hundred bytes, while 128 real generated tokens with top-k logprobs
	// run to tens of kilobytes.
	stored := map[string]int{}
	for _, record := range h.persistence.evidence {
		stored[record.Kind] = len(record.Data)
	}
	for _, kind := range []string{"worker-output", "worker-trace", "worker-checkpoint", "worker-infer-receipt"} {
		if stored[kind] == 0 {
			t.Fatalf("persisted evidence %q is missing or empty; have %v", kind, stored)
		}
	}
	const minRealTraceBytes = 8 << 10
	if stored["worker-trace"] < minRealTraceBytes {
		t.Fatalf("worker-trace is %dB, want at least %dB of real logprob trace rather than a fixture",
			stored["worker-trace"], minRealTraceBytes)
	}
	if len(h.persistence.outbox) == 0 {
		t.Fatal("no outbox record, want the OUTPUT_AVAILABLE publish queued")
	}
	if len(h.persistence.receipts) == 0 {
		t.Fatal("no receipt checkpoint, want the signed receipt persisted")
	}
}

// describeRealVLLMPersistence summarises what a real inference actually wrote,
// by kind and size. A count alone would not distinguish a run that persisted the
// real 75KB trace from one that persisted a fixture stub.
func describeRealVLLMPersistence(p *recordingPersistence) string {
	var parts []string
	for _, record := range p.evidence {
		parts = append(parts, record.Kind+"="+itoaBytes(len(record.Data)))
	}
	parts = append(parts, "outbox="+itoaBytes(len(p.outbox)))
	parts = append(parts, "jobs="+itoaBytes(len(p.jobs)))
	parts = append(parts, "receipts="+itoaBytes(len(p.receipts)))
	return strings.Join(parts, " ")
}

func itoaBytes(n int) string {
	return strconv.Itoa(n)
}
