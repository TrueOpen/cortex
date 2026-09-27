package integration_test

// D1: one task end to end against a fake chain, Nexus and model service. The
// Worker and the Verifier each published roots and commitments; this file
// recomputes every one of them from the model service's raw outputs and the
// task's public facts alone, with the wire encoders and none of the node code,
// and requires the published values to match byte for byte.
//
// The generation parameters are read from the Worker's A-level
// generation_params artifact: its raw-bytes digest must be the chain's, the
// receipt's, the result's and the one the Verifier's prefill ran under, and
// the prefill's parameters must encode to exactly those bytes.

import (
	"bytes"
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// d1Scenario is what the Worker and the Verifier published for one task, plus
// the public facts the recomputation binds to.
type d1Scenario struct {
	chainID, taskID, workerAddress, verifierAddress string
	facts                                           taskfacts.Facts
	profile                                         chainclient.CurrentModelProfileSnapshot
	finishReason                                    nodewire.FinishReasonV1

	// Worker side: the signed receipt and the persisted bundles.
	inferReceipt builderclient.SignedInferReceipt
	workerBundle func(context.Context, string, nodewire.EvidenceKind) ([]byte, map[string][]byte, error)

	// Verifier side: the signed commit and its salt, the metric material of
	// the verify run, and the finalized result receipt.
	commit   nodewire.VerifyCommitV1
	salt     codec.Hash
	material metric.Material
	result   nodewire.ResultReceiptV3
}

func assertD1RootsAndCommitments(t *testing.T, model *integrationGRPCServer, sc d1Scenario) {
	t.Helper()
	model.mu.Lock()
	rawTokenIDs, rawWorkerValues, rawVerifierValues := model.workerTokenIDs, model.workerPositionValues, model.verifierValues
	verifyGeneration, verifyGenerationDigest := model.verifyGeneration, model.verifyGenerationDigest
	model.mu.Unlock()
	if rawTokenIDs == nil || rawWorkerValues == nil || rawVerifierValues == nil {
		t.Fatal("D1: the model service recorded no Infer or Verify output")
	}
	taskID, err := builderclient.CanonicalWireHash(sc.taskID, "task_id")
	if err != nil {
		t.Fatal(err)
	}
	taskHash := codec.Hash(sc.facts.AcceptedTaskHash)
	requiredTopK := sc.profile.Profile.RequiredTopK
	evidenceSchemaHash := codec.Hash(sc.profile.Profile.VerificationProfile.EvidenceSchemaHash)

	// Generation parameters, from the A-level artifact only.
	_, tokenBundle, err := sc.workerBundle(context.Background(), sc.taskID, nodewire.EvidenceKindWorkerTokenOpening)
	if err != nil {
		t.Fatal(err)
	}
	generationParams := tokenBundle[builderclient.EvidenceArtifactGenerationParams]
	generationParamsDigest := nodewire.GenerationParamsDigest(generationParams)
	for name, digest := range map[string][]byte{
		"chain":          sc.facts.GenerationParamsDigest[:],
		"result receipt": sc.result.GenerationParamsDigest,
		"verify prefill": verifyGenerationDigest,
	} {
		if !bytes.Equal(digest, generationParamsDigest[:]) {
			t.Fatalf("D1: %s generation_params_digest = %x, the A-level artifact hashes to %s", name, digest, generationParamsDigest)
		}
	}
	if sc.inferReceipt.GenerationParamsDigest != generationParamsDigest.String() {
		t.Fatalf("D1: infer receipt generation_params_digest = %s, the A-level artifact hashes to %s", sc.inferReceipt.GenerationParamsDigest, generationParamsDigest)
	}
	if verifyGeneration == nil {
		t.Fatal("D1: the Verifier's prefill ran without generation parameters")
	}
	prefillParams, err := verifyGeneration.CanonicalJSON()
	if err != nil || !bytes.Equal(prefillParams, generationParams) {
		t.Fatalf("D1: the prefill's parameters encode to %s, not the A-level artifact %s (%v)", prefillParams, generationParams, err)
	}

	// Worker value tree, from the Worker's raw position values.
	positionValues, err := modelservice.DecodePositionValuesArtifact(rawWorkerValues)
	if err != nil {
		t.Fatal(err)
	}
	workerLeaves, err := metric.ValueLeaves(positionValues, requiredTopK)
	if err != nil {
		t.Fatal(err)
	}
	workerBinding := nodewire.WorkerValueBindingV1{
		ChainID: sc.chainID, TaskID: taskID[:], AcceptedTaskHash: taskHash[:],
		WorkerOperatorAddress: sc.workerAddress, RequiredTopK: requiredTopK,
	}
	workerValueRoot, err := nodewire.WorkerValueRoot(workerBinding, workerLeaves)
	if err != nil {
		t.Fatal(err)
	}
	workerValues, err := nodewire.EncodeWorkerValues(workerBinding, workerLeaves)
	if err != nil {
		t.Fatal(err)
	}
	valueDigest, valueSize, err := nodewire.WorkerValueCommitmentV3Digest(nodewire.WorkerValueCommitmentV3{
		SchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV3, ChainID: sc.chainID, TaskID: taskID[:],
		AcceptedTaskHash: taskHash[:], WorkerOperatorAddress: sc.workerAddress, EvidenceSchemaHash: evidenceSchemaHash[:],
		WorkerValueRoot: workerValueRoot[:], WorkerValuesEncodedSizeBytes: uint64(len(workerValues)),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Worker token commitment, from the Worker's raw token ids and the
	// receipt's output facts.
	ids, err := modelservice.DecodeTokenIDsArtifact(rawTokenIDs)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := nodewire.EncodeTokenIDs(ids.Input)
	if err != nil {
		t.Fatal(err)
	}
	generatedArtifact, err := nodewire.EncodeTokenIDs(ids.Generated)
	if err != nil {
		t.Fatal(err)
	}
	inputHash, err := nodewire.InputTokenIDsHash(ids.Input)
	if err != nil {
		t.Fatal(err)
	}
	generatedHash, err := nodewire.GeneratedTokenIDsHash(ids.Generated)
	if err != nil {
		t.Fatal(err)
	}
	outputHash, err := builderclient.CanonicalWireHash(sc.inferReceipt.OutputHash, "output_hash")
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest, tokenSize, err := nodewire.WorkerTokenCommitment(nodewire.WorkerTokenCommitmentV1{
		SchemaVersion: nodewire.WorkerTokenCommitmentSchemaVersionV1, ChainID: sc.chainID, TaskID: taskID[:],
		AcceptedTaskHash: taskHash[:], WorkerOperatorAddress: sc.workerAddress, GenerationParamsDigest: generationParamsDigest[:],
		EvidenceSchemaHash: evidenceSchemaHash[:], OutputHash: outputHash[:], OutputSizeBytes: sc.inferReceipt.OutputSizeBytes,
		OutputLeafCount: sc.inferReceipt.OutputLeafCount, FinishReason: sc.finishReason, GeneratedTokenCount: uint64(len(ids.Generated)),
		InputTokenIDsHash: inputHash[:], GeneratedTokenIDsHash: generatedHash[:],
		InputTokenIDsSizeBytes: uint64(len(inputArtifact)), GeneratedTokenIDsSizeBytes: uint64(len(generatedArtifact)),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The Worker's signed receipt carries exactly [value, token].
	want := []builderclient.EvidenceCommitment{
		{EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: valueDigest, EncodedSizeBytes: valueSize},
		{EvidenceKind: nodewire.EvidenceKindWorkerTokenOpening, EvidenceHashOrRoot: tokenDigest, EncodedSizeBytes: tokenSize},
	}
	got := sc.inferReceipt.RequiredEvidenceCommitments
	if len(got) != len(want) {
		t.Fatalf("D1: receipt commitments = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("D1: receipt commitment %d = %+v, recomputed %+v", i, got[i], want[i])
		}
	}
	if sc.inferReceipt.GeneratedTokenCount != uint64(len(ids.Generated)) {
		t.Fatalf("D1: receipt generated_token_count = %d, model generated %d", sc.inferReceipt.GeneratedTokenCount, len(ids.Generated))
	}

	// The bundles the Verifier fetched hold exactly the recomputed artifacts.
	for kind, artifacts := range map[nodewire.EvidenceKind]map[string][]byte{
		nodewire.EvidenceKindWorkerValueOpening: {builderclient.EvidenceArtifactWorkerValues: workerValues},
		nodewire.EvidenceKindWorkerTokenOpening: {
			builderclient.EvidenceArtifactInputTokenIDs: inputArtifact, builderclient.EvidenceArtifactGeneratedTokenIDs: generatedArtifact,
			builderclient.EvidenceArtifactGenerationParams: generationParams,
		},
	} {
		_, stored, err := sc.workerBundle(context.Background(), sc.taskID, kind)
		if err != nil {
			t.Fatalf("D1: read Worker bundle %d: %v", kind, err)
		}
		for id, data := range artifacts {
			if !bytes.Equal(stored[id], data) {
				t.Fatalf("D1: Worker bundle %d artifact %s differs from the recomputed bytes", kind, id)
			}
		}
	}

	// Verifier value tree, from the Verifier's raw prefill values.
	verifierPositionValues, err := modelservice.DecodePositionValuesArtifact(rawVerifierValues)
	if err != nil {
		t.Fatal(err)
	}
	verifierLeaves, err := metric.ValueLeaves(verifierPositionValues, requiredTopK)
	if err != nil {
		t.Fatal(err)
	}
	verifierValueRoot, err := nodewire.VerifierValueRoot(nodewire.VerifierValueBindingV1{
		ChainID: sc.chainID, TaskID: taskID[:], TaskHash: taskHash[:], VerifyRound: 1,
		VerifierOperatorAddress: sc.verifierAddress, RequiredTopK: requiredTopK,
	}, verifierLeaves)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sc.result.VerifierValueRoot, verifierValueRoot[:]) || sc.material.VerifierValueRoot != verifierValueRoot {
		t.Fatalf("D1: verifier_value_root receipt=%x material=%s, recomputed %s",
			sc.result.VerifierValueRoot, sc.material.VerifierValueRoot, verifierValueRoot)
	}
	// The rig's Verifier drifts on purpose, so the two trees are distinct.
	if verifierValueRoot == workerValueRoot {
		t.Fatal("D1: Verifier and Worker value roots coincide; the rig lost its drift")
	}

	// ResultCommitmentV3 binds that root and the salt.
	commitHash, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV3{
		ChainID: sc.chainID, TaskID: taskID[:], TaskHash: taskHash[:], VerifyRound: 1,
		VerifierOperatorAddress: sc.verifierAddress, VerifierValueRoot: verifierValueRoot[:], Salt: sc.salt[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sc.commit.CommitHash, commitHash[:]) || !bytes.Equal(sc.result.Salt, sc.salt[:]) {
		t.Fatalf("D1: commit_hash = %x, recomputed %s", sc.commit.CommitHash, commitHash)
	}

	// The metric tree compares the two value trees and binds the Verifier root
	// and the artifact's generation_params_digest into every leaf.
	binding, err := metric.BindTask(sc.chainID, taskID, taskHash, 1, sc.profile.Profile, generationParamsDigest)
	if err != nil {
		t.Fatal(err)
	}
	samples, err := metric.CompareLeavesV3(binding.Spec, requiredTopK, workerLeaves, verifierLeaves)
	if err != nil {
		t.Fatal(err)
	}
	material, err := metric.BuildV3(binding, verifierValueRoot, samples)
	if err != nil {
		t.Fatal(err)
	}
	if material.Root != sc.material.Root || !bytes.Equal(sc.result.MetricRoot, material.Root[:]) {
		t.Fatalf("D1: metric_root receipt=%x material=%s, recomputed %s", sc.result.MetricRoot, sc.material.Root, material.Root)
	}
	if uint64(sc.result.MetricLeafCount) != uint64(material.LeafCount) || material.LeafCount != sc.material.LeafCount {
		t.Fatalf("D1: metric_leaf_count = %d, recomputed %d", sc.result.MetricLeafCount, material.LeafCount)
	}
	if !bytes.Equal(sc.result.AggregateProofHash, material.AggregateProof.Hash[:]) || sc.result.MetricSummary != material.Summary {
		t.Fatalf("D1: aggregate proof or summary differs from the recomputation")
	}
}
