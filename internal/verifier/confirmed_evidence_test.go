package verifier

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// confirmedTask is a non-fake verify input whose Worker evidence, receipt,
// generation params and output are all mutually consistent, the way the
// daemon's Nexus confirmer hands them over.
func confirmedTask(t *testing.T, h harness) TaskState {
	t.Helper()
	ctx := context.Background()
	h.verifier.cfg.FakeOutput = false
	profile := fixtureLockedProfile()
	requiredTopK := profile.Profile.RequiredTopK
	state := h.validTask()
	state.OpenVerifyAccepted = true

	generation := &nodewire.GenerationContext{
		ModelID: modelservice.FakeModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}},
	}
	rawParams, err := generation.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	paramsDigest := nodewire.GenerationParamsDigest(rawParams)
	accepted := fixtureTaskAcceptedTaskHash(state.TaskID)
	h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
		return taskfacts.Facts{TaskID: taskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash: accepted, GenerationParamsDigest: chainclient.ProtoBytes32(paramsDigest[:]),
			ProfileExecutionSnapshotHash: chainclient.ProtoBytes32(strings.Repeat("\x93", 32)),
		}}, nil
	})

	result, err := h.model.FakeService.Infer(ctx, modelservice.InferRequest{ModelID: generation.ModelID, ProfileVersion: "1",
		Capability: modelservice.CapabilityLLMTextV1, Input: []byte("confirmed prompt"), Generation: generation, GenerationParamsDigest: paramsDigest[:]})
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(ref string) []byte {
		artifact, err := h.model.FakeService.FetchArtifact(ctx, modelservice.FetchArtifactRequest{Ref: ref, AllowEmpty: true})
		if err != nil {
			t.Fatal(err)
		}
		return artifact.Data
	}
	output := fetch(result.OutputRef)
	ids, err := modelservice.DecodeTokenIDsArtifact(fetch(result.TokenIDsRef))
	if err != nil {
		t.Fatal(err)
	}
	values, err := modelservice.DecodePositionValuesArtifact(fetch(result.PositionValuesRef))
	if err != nil {
		t.Fatal(err)
	}
	inputIDs, generatedIDs, err := modelservice.ProtocolTokenIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := hex.DecodeString(state.TaskID)
	binding := nodewire.WorkerValueBindingV1{ChainID: h.verifier.cfg.ChainID, TaskID: taskID, AcceptedTaskHash: accepted[:],
		WorkerOperatorAddress: state.WorkerAddress, RequiredTopK: requiredTopK}
	leaves, err := metric.ValueLeaves(values, requiredTopK)
	if err != nil {
		t.Fatal(err)
	}
	workerValues, err := nodewire.EncodeWorkerValues(binding, leaves)
	if err != nil {
		t.Fatal(err)
	}
	valueRoot, err := nodewire.WorkerValueRoot(binding, leaves)
	if err != nil {
		t.Fatal(err)
	}
	outputHash, err := codec.OutputMMRRoot([][]byte{output})
	if err != nil {
		t.Fatal(err)
	}
	inputHash, _ := nodewire.InputTokenIDsHash(ids.Input)
	generatedHash, _ := nodewire.GeneratedTokenIDsHash(ids.Generated)
	schemaHash := codec.Hash(profile.Profile.VerificationProfile.EvidenceSchemaHash)
	commitments, err := builderclient.WorkerEvidenceCommitments(builderclient.WorkerEvidenceFacts{
		ChainID: h.verifier.cfg.ChainID, TaskID: state.TaskID, AcceptedTaskHash: hex.EncodeToString(accepted[:]),
		WorkerOperatorAddress: state.WorkerAddress, GenerationParamsDigest: paramsDigest.String(), EvidenceSchemaHash: schemaHash.String(),
		OutputHash: outputHash, OutputSizeBytes: uint64(len(output)), OutputLeafCount: 1, FinishReason: result.FinishReason,
		GeneratedTokenCount: uint64(len(ids.Generated)), InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash,
		InputTokenIDsSizeBytes: uint64(len(inputIDs)), GeneratedTokenIDsSizeBytes: uint64(len(generatedIDs)),
		WorkerValueRoot: valueRoot, WorkerValuesEncodedSizeBytes: uint64(len(workerValues)),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt := builderclient.SignedInferReceipt{
		SchemaVersion: nodewire.InferReceiptSchemaVersionV3, ChainID: h.verifier.cfg.ChainID, TaskID: state.TaskID,
		TaskHash: hex.EncodeToString(accepted[:]), WorkerOperatorAddress: state.WorkerAddress, ServiceAuthorizationNonce: 1,
		GenerationParamsDigest: paramsDigest.String(), OutputHash: outputHash.String(), OutputSizeBytes: uint64(len(output)),
		OutputLeafCount: 1, GeneratedTokenCount: uint64(len(ids.Generated)), RequiredEvidenceCommitments: commitments, ExpiryHeight: 1000,
	}
	receiptHash, err := builderclient.InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	state.InferReceiptHash = receiptHash
	state.OutputPackage.OutputHash = outputHash
	state.OutputPackage.PackageHash = codec.HashWithDomain("TRUEOPEN_OUTPUT_PACKAGE_V1", []byte(state.OutputPackage.TaskID),
		[]byte(state.OutputPackage.OutputRef), []byte(state.OutputPackage.TokenIDsRef), []byte(state.OutputPackage.PositionValuesRef), outputHash[:])
	state.ConfirmedOutput = output
	state.ConfirmedOutputChunkLengths = []uint64{uint64(len(output))}
	state.ConfirmedInputTokenIDs, state.ConfirmedGeneratedTokenIDs = inputIDs, generatedIDs
	state.ConfirmedWorkerValues, state.ConfirmedGenerationParams = workerValues, rawParams
	state.ConfirmedInferReceipt, state.ConfirmedFinishReason = &receipt, result.FinishReason
	return state
}

// The consistent confirmed input verifies; it is the baseline every negative
// below departs from by one change.
func TestConfirmedEvidenceBaselineVerifies(t *testing.T) {
	h := newHarness(t)
	state := confirmedTask(t, h)
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
		t.Fatalf("consistent confirmed evidence was refused: %v", err)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("model verify calls = %d, want 1", h.model.VerifyCalls)
	}
}

// Each change to the confirmed Worker evidence is refused before the model is
// asked for a prefill.
func TestConfirmedEvidenceRefusalsStopBeforeThePrefill(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*TaskState, *harness)
		want   string
	}{
		// A well-formed worker_values artifact with one logprob moved: it
		// decodes, so only the value commitment can catch it.
		"tampered worker_values": {func(s *TaskState, h *harness) {
			taskID, _ := hex.DecodeString(s.TaskID)
			accepted := fixtureTaskAcceptedTaskHash(s.TaskID)
			binding := nodewire.WorkerValueBindingV1{ChainID: h.verifier.cfg.ChainID, TaskID: taskID, AcceptedTaskHash: accepted[:],
				WorkerOperatorAddress: s.WorkerAddress, RequiredTopK: fixtureLockedProfile().Profile.RequiredTopK}
			leaves, err := nodewire.DecodeWorkerValues(binding, s.ConfirmedWorkerValues)
			if err != nil {
				t.Fatal(err)
			}
			for i := range leaves {
				if leaves[i].Finite {
					leaves[i].LogprobFP1e6--
					break
				}
			}
			if s.ConfirmedWorkerValues, err = nodewire.EncodeWorkerValues(binding, leaves); err != nil {
				t.Fatal(err)
			}
		}, "commitment"},
		"tampered generated token id": {func(s *TaskState, _ *harness) {
			s.ConfirmedGeneratedTokenIDs = append([]byte(nil), s.ConfirmedGeneratedTokenIDs...)
			s.ConfirmedGeneratedTokenIDs[len(s.ConfirmedGeneratedTokenIDs)-1] ^= 1
		}, "token commitment"},
		"receipt hash mismatch": {func(s *TaskState, _ *harness) {
			s.InferReceiptHash = codec.HashBytes([]byte("another receipt"))
		}, "differs from accepted task facts"},
		"value evidence above the profile bound": {func(_ *TaskState, h *harness) {
			profile := fixtureLockedProfile()
			profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence[0].MaxEncodedSizeBytes = chainclient.Uint64String(4)
			h.verifier.cfg.ProfileReader = &fixtureProfileReader{profile: profileWithHash(t, profile)}
		}, "bound"},
		"token evidence above the profile bound": {func(_ *TaskState, h *harness) {
			profile := fixtureLockedProfile()
			profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence[1].MaxEncodedSizeBytes = chainclient.Uint64String(4)
			h.verifier.cfg.ProfileReader = &fixtureProfileReader{profile: profileWithHash(t, profile)}
		}, "bound"},
		"missing token bundle":  {func(s *TaskState, _ *harness) { s.ConfirmedGeneratedTokenIDs = nil }, "incomplete"},
		"missing value bundle":  {func(s *TaskState, _ *harness) { s.ConfirmedWorkerValues = nil }, "incomplete"},
		"missing params":        {func(s *TaskState, _ *harness) { s.ConfirmedGenerationParams = nil }, "incomplete"},
		"finish reason differs": {func(s *TaskState, _ *harness) { s.ConfirmedFinishReason = nodewire.FinishReasonV1StopToken }, "finish reason"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			state := confirmedTask(t, h)
			tc.mutate(&state, &h)
			_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal containing %q", err, tc.want)
			}
			if h.model.VerifyCalls != 0 {
				t.Fatalf("model verify calls = %d, want the refusal before any prefill", h.model.VerifyCalls)
			}
		})
	}
	// An unspecified confirmed finish reason is "not asserted", not a
	// mismatch: the commitment alone decides it.
	h := newHarness(t)
	state := confirmedTask(t, h)
	state.ConfirmedFinishReason = nodewire.FinishReasonV1Unspecified
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
		t.Fatalf("an unasserted finish reason was refused: %v", err)
	}
}

// profileWithHash re-derives a mutated profile's evidence_schema_hash so the
// profile stays self-consistent and only the mutation is under test.
func profileWithHash(t *testing.T, profile chainclient.CurrentModelProfileSnapshot) chainclient.CurrentModelProfileSnapshot {
	t.Helper()
	hash, err := keepercontract.ComputeEvidenceSchemaHashFromCurrentModelProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(hash[:])
	return profile
}

// After a restart the persisted material restores the same verifier_value_root
// and metric_leaf_count, and they with the persisted salt recompute the
// commit_hash that was signed.
func TestVerifierRestartRestoresTheCommittedRootAndCount(t *testing.T) {
	h := newHarness(t)
	state := confirmedTask(t, h)
	first, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(h.verifier.cfg)
	source, err := restarted.persistedReveal(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if source.MetricMaterial.VerifierValueRoot != first.MetricMaterial.VerifierValueRoot ||
		source.MetricMaterial.LeafCount != first.MetricMaterial.LeafCount || source.MetricMaterial.Root != first.MetricMaterial.Root {
		t.Fatalf("restored material = %+v, want the pre-restart root and count", source.MetricMaterial)
	}
	taskID, _ := hex.DecodeString(state.TaskID)
	accepted := fixtureTaskAcceptedTaskHash(state.TaskID)
	commitHash, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV3{
		ChainID: h.verifier.cfg.ChainID, TaskID: taskID, TaskHash: accepted[:], VerifyRound: uint32(state.VerifyRound),
		VerifierOperatorAddress: h.verifier.cfg.VerifierAddress, VerifierValueRoot: source.MetricMaterial.VerifierValueRoot[:], Salt: source.Salt[:],
	})
	if err != nil || commitHash != first.CommitHash || source.CommitHash != first.CommitHash {
		t.Fatalf("recomputed commit_hash = %s, signed %s (%v)", commitHash, first.CommitHash, err)
	}
}
