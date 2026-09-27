package worker

// Two-level Worker evidence (wire v0.3.0). One inference yields two bundles:
//
//	A-level WORKER_TOKEN_OPENING: input_token_ids, generated_token_ids
//	B-level WORKER_VALUE_OPENING: worker_values
//
// Both are derived from the model service's material (TokenIDsV1 and
// PositionValuesV1), published write-once through the bundle store, committed
// in the receipt as one commitment each, and uploaded and finalized one bundle
// at a time.

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// workerEvidenceKinds are the Worker's two bundles in ascending kind order,
// which is also the receipt's commitment order.
var workerEvidenceKinds = [...]nodewire.EvidenceKind{nodewire.EvidenceKindWorkerValueOpening, nodewire.EvidenceKindWorkerTokenOpening}

// workerBundle is one published Worker bundle read back from the store.
type workerBundle struct {
	kind      nodewire.EvidenceKind
	manifest  []byte
	decoded   evidencebundle.Manifest
	artifacts map[string][]byte // by artifact id
}

// workerEvidence is what the two bundles contribute to the commitments.
type workerEvidence struct {
	inputTokenIDs, generatedTokenIDs, workerValues []byte
	// generationParams is the task's exact canonical_generation_params_json,
	// carried in the A-level bundle so a Verifier prefills under it.
	generationParams                    []byte
	inputHash, generatedHash, valueRoot codec.Hash
	generatedCount                      uint64
}

// decodeMaterial reads the model service's two Infer artifacts.
func decodeMaterial(tokenIDs, positionValues []byte) (modelservice.TokenIDs, []metric.PositionValue, error) {
	ids, err := modelservice.DecodeTokenIDsArtifact(tokenIDs)
	if err != nil {
		return modelservice.TokenIDs{}, nil, err
	}
	values, err := modelservice.DecodePositionValuesArtifact(positionValues)
	if err != nil {
		return modelservice.TokenIDs{}, nil, err
	}
	return ids, values, nil
}

func (w *Worker) valueBinding(taskID string, acceptedTaskHash []byte) (nodewire.WorkerValueBindingV1, error) {
	if w.cfg.RequiredTopK == 0 {
		return nodewire.WorkerValueBindingV1{}, fmt.Errorf("%w: worker_values require the locked Profile's required_top_k",
			builderclient.ErrInferReceiptInputUnavailable)
	}
	rawTaskID, err := builderclient.CanonicalWireHash(taskID, "task_id")
	if err != nil {
		return nodewire.WorkerValueBindingV1{}, err
	}
	return nodewire.WorkerValueBindingV1{
		ChainID: w.cfg.ChainID, TaskID: rawTaskID[:], AcceptedTaskHash: acceptedTaskHash,
		WorkerOperatorAddress: w.cfg.WorkerAddress, RequiredTopK: w.cfg.RequiredTopK,
	}, nil
}

// deriveWorkerEvidence encodes the protocol artifacts of both bundles from the
// model material. It is deterministic, so a restart re-derives the same bytes.
func (w *Worker) deriveWorkerEvidence(taskID string, acceptedTaskHash, generationParams []byte, tokenIDs, positionValues []byte) (workerEvidence, error) {
	ids, values, err := decodeMaterial(tokenIDs, positionValues)
	if err != nil {
		return workerEvidence{}, err
	}
	out := workerEvidence{generationParams: generationParams}
	if out.inputTokenIDs, out.generatedTokenIDs, err = modelservice.ProtocolTokenIDs(ids); err != nil {
		return workerEvidence{}, err
	}
	if out.inputHash, err = nodewire.InputTokenIDsHash(ids.Input); err != nil {
		return workerEvidence{}, err
	}
	if out.generatedHash, err = nodewire.GeneratedTokenIDsHash(ids.Generated); err != nil {
		return workerEvidence{}, err
	}
	binding, err := w.valueBinding(taskID, acceptedTaskHash)
	if err != nil {
		return workerEvidence{}, err
	}
	leaves, err := metric.ValueLeaves(values, binding.RequiredTopK)
	if err != nil {
		return workerEvidence{}, fmt.Errorf("frame worker values: %w", err)
	}
	if out.workerValues, err = nodewire.EncodeWorkerValues(binding, leaves); err != nil {
		return workerEvidence{}, err
	}
	if out.valueRoot, err = nodewire.WorkerValueRoot(binding, leaves); err != nil {
		return workerEvidence{}, err
	}
	out.generatedCount = uint64(len(ids.Generated))
	return out, nil
}

// workerManifest is the canonical manifest of one Worker bundle.
func (w *Worker) workerManifest(event chainclient.AssignmentFinalized, taskHash string, kind nodewire.EvidenceKind, ev workerEvidence) (evidencebundle.Manifest, [][]byte) {
	manifest := evidencebundle.Manifest{
		ChainID: w.cfg.ChainID, EvidenceSchemaHash: w.cfg.EvidenceSchemaHash, Version: 1,
		EvidenceKind: evidencebundle.KindToken(kind), ProducerKind: "WORKER", ProducerOperator: w.cfg.WorkerAddress,
		TaskHash: taskHash, TaskID: event.TaskID, VerifyRound: 1,
	}
	if kind == nodewire.EvidenceKindWorkerTokenOpening {
		manifest.Artifacts = []evidencebundle.Artifact{
			evidencebundle.NewArtifact(builderclient.EvidenceArtifactGeneratedTokenIDs, ev.generatedTokenIDs),
			evidencebundle.NewArtifact(builderclient.EvidenceArtifactGenerationParams, ev.generationParams),
			evidencebundle.NewArtifact(builderclient.EvidenceArtifactInputTokenIDs, ev.inputTokenIDs),
		}
		return manifest, [][]byte{ev.generatedTokenIDs, ev.generationParams, ev.inputTokenIDs}
	}
	manifest.Artifacts = []evidencebundle.Artifact{evidencebundle.NewArtifact(builderclient.EvidenceArtifactWorkerValues, ev.workerValues)}
	return manifest, [][]byte{ev.workerValues}
}

// publishWorkerBundles publishes both bundles write-once. Republishing the same
// bytes after a crash is an idempotent success.
func (w *Worker) publishWorkerBundles(ctx context.Context, event chainclient.AssignmentFinalized, taskHash string, ev workerEvidence) error {
	for _, kind := range workerEvidenceKinds {
		manifest, artifacts := w.workerManifest(event, taskHash, kind, ev)
		encoded, err := manifest.Encode()
		if err != nil {
			return fmt.Errorf("encode Worker %s manifest: %w", manifest.EvidenceKind, err)
		}
		if err := w.cfg.Persistence.PublishWorkerBundle(ctx, event.TaskID, kind, encoded, artifacts); err != nil {
			return err
		}
	}
	return nil
}

// workerEvidenceFacts are the commitment inputs of one prepared output.
func (w *Worker) workerEvidenceFacts(in preparedReceiptInputs) builderclient.WorkerEvidenceFacts {
	return builderclient.WorkerEvidenceFacts{
		ChainID:                      w.cfg.ChainID,
		TaskID:                       in.event.TaskID,
		AcceptedTaskHash:             in.facts.AcceptedTaskHash.Hex(),
		WorkerOperatorAddress:        w.cfg.WorkerAddress,
		GenerationParamsDigest:       in.facts.GenerationParamsDigest.Hex(),
		EvidenceSchemaHash:           in.local.EvidenceSchemaHash,
		OutputHash:                   in.outputHash,
		OutputSizeBytes:              in.outputSizeBytes,
		OutputLeafCount:              in.outputLeafCount,
		FinishReason:                 in.local.FinishReason,
		GeneratedTokenCount:          in.evidence.generatedCount,
		InputTokenIDsHash:            in.evidence.inputHash,
		GeneratedTokenIDsHash:        in.evidence.generatedHash,
		InputTokenIDsSizeBytes:       uint64(len(in.evidence.inputTokenIDs)),
		GeneratedTokenIDsSizeBytes:   uint64(len(in.evidence.generatedTokenIDs)),
		WorkerValueRoot:              in.evidence.valueRoot,
		WorkerValuesEncodedSizeBytes: uint64(len(in.evidence.workerValues)),
	}
}

// readWorkerBundles reads both published bundles back and checks each manifest
// against the task, the locked Profile and the signed receipt, then re-derives
// both commitments from the stored artifacts. A restart trusts nothing it did
// not just re-derive.
func (w *Worker) readWorkerBundles(ctx context.Context, event chainclient.AssignmentFinalized, receipt builderclient.SignedInferReceipt, descriptor outputDescriptor) ([]workerBundle, error) {
	if err := builderclient.ValidateProfileEvidenceCommitments(w.cfg.ProfileEvidenceRequirements, receipt.RequiredEvidenceCommitments); err != nil {
		return nil, err
	}
	bundles := make([]workerBundle, 0, len(workerEvidenceKinds))
	byKind := map[nodewire.EvidenceKind]workerBundle{}
	for i, kind := range workerEvidenceKinds {
		manifestBytes, artifacts, err := w.cfg.Persistence.WorkerBundle(ctx, event.TaskID, kind)
		if err != nil {
			return nil, fmt.Errorf("read Worker %d bundle: %w", kind, err)
		}
		m, err := evidencebundle.Decode(manifestBytes)
		if err != nil {
			return nil, err
		}
		if m.ChainID != w.cfg.ChainID || m.TaskID != event.TaskID || m.TaskHash != receipt.TaskHash || m.ProducerKind != "WORKER" ||
			m.ProducerOperator != w.cfg.WorkerAddress || m.ProducerOperator != receipt.WorkerOperatorAddress || m.VerifyRound != 1 ||
			m.EvidenceSchemaHash != w.cfg.EvidenceSchemaHash || m.EvidenceKind != evidencebundle.KindToken(kind) {
			return nil, fmt.Errorf("Worker %s manifest scope differs from task or locked Profile", m.EvidenceKind)
		}
		if receipt.RequiredEvidenceCommitments[i].EvidenceKind != kind || receipt.RequiredEvidenceCommitments[i].EncodedSizeBytes != m.CommittedSize() {
			return nil, fmt.Errorf("Worker %s manifest does not match signed receipt", m.EvidenceKind)
		}
		for _, artifact := range m.Artifacts {
			data, ok := artifacts[artifact.ID]
			size, err := artifact.SizeBytes()
			if !ok || err != nil || size != uint64(len(data)) || artifact.ContentHash != codec.HashBytes(data).String() {
				return nil, fmt.Errorf("Worker artifact %s differs from manifest", artifact.ID)
			}
		}
		bundle := workerBundle{kind: kind, manifest: manifestBytes, decoded: m, artifacts: artifacts}
		bundles = append(bundles, bundle)
		byKind[kind] = bundle
	}
	token, value := byKind[nodewire.EvidenceKindWorkerTokenOpening], byKind[nodewire.EvidenceKindWorkerValueOpening]
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	input, err := nodewire.DecodeTokenIDs(token.artifacts[builderclient.EvidenceArtifactInputTokenIDs])
	if err != nil {
		return nil, err
	}
	generated, err := nodewire.DecodeTokenIDs(token.artifacts[builderclient.EvidenceArtifactGeneratedTokenIDs])
	if err != nil {
		return nil, err
	}
	binding, err := w.valueBinding(event.TaskID, facts.AcceptedTaskHash)
	if err != nil {
		return nil, err
	}
	leaves, err := nodewire.DecodeWorkerValues(binding, value.artifacts[builderclient.EvidenceArtifactWorkerValues])
	if err != nil {
		return nil, err
	}
	generationParams := token.artifacts[builderclient.EvidenceArtifactGenerationParams]
	if nodewire.GenerationParamsDigest(generationParams) != codec.Hash(facts.GenerationParamsDigest) {
		return nil, fmt.Errorf("Worker generation_params artifact differs from the task's generation_params_digest")
	}
	ev := workerEvidence{
		generationParams: generationParams,
		inputTokenIDs:    token.artifacts[builderclient.EvidenceArtifactInputTokenIDs], generatedTokenIDs: token.artifacts[builderclient.EvidenceArtifactGeneratedTokenIDs],
		workerValues: value.artifacts[builderclient.EvidenceArtifactWorkerValues], generatedCount: uint64(len(generated)),
	}
	if ev.inputHash, err = nodewire.InputTokenIDsHash(input); err != nil {
		return nil, err
	}
	if ev.generatedHash, err = nodewire.GeneratedTokenIDsHash(generated); err != nil {
		return nil, err
	}
	if ev.valueRoot, err = nodewire.WorkerValueRoot(binding, leaves); err != nil {
		return nil, err
	}
	derived, err := builderclient.WorkerEvidenceCommitments(w.workerEvidenceFacts(preparedReceiptInputs{
		event: event, facts: facts, local: workerValueEvidenceInputs{EvidenceSchemaHash: w.cfg.EvidenceSchemaHash, FinishReason: descriptor.FinishReason},
		outputHash: descriptor.OutputHash, outputSizeBytes: receipt.OutputSizeBytes, outputLeafCount: receipt.OutputLeafCount, evidence: ev,
	}))
	if err != nil {
		return nil, err
	}
	for i := range derived {
		if derived[i] != receipt.RequiredEvidenceCommitments[i] {
			return nil, fmt.Errorf("Worker evidence commitment of kind %d differs from persisted artifacts", derived[i].EvidenceKind)
		}
	}
	return bundles, nil
}

// bundleKey is the object ref of a Worker bundle's manifest: its content hash
// is the receipt's typed commitment for the bundle's kind.
func workerBundleKey(receipt builderclient.SignedInferReceipt, sessionID, taskID string, kind nodewire.EvidenceKind) (builderclient.TaskDataKey, error) {
	for _, commitment := range receipt.RequiredEvidenceCommitments {
		if commitment.EvidenceKind == kind {
			return builderclient.EvidenceObjectKey(receipt.TaskHash, sessionID, taskID, builderclient.DataKindEvidenceManifest,
				commitment.EvidenceHashOrRoot.String(), builderclient.EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress, kind), nil
		}
	}
	return builderclient.TaskDataKey{}, fmt.Errorf("receipt commits no evidence of kind %d", kind)
}
