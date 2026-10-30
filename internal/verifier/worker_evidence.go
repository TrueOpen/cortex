package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// ErrBLevelBeforeCommit refuses B-level WORKER_VALUE_OPENING material handed
// to the commit phase: ADR-0023 decision 4 (CD §6.2 V12) forbids requesting,
// reading or caching it until this node's commit is accepted and the round
// is REVEALING.
var ErrBLevelBeforeCommit = errors.New("B-level WORKER_VALUE_OPENING material reached the verifier before its commit")

// workerTokenArtifacts is the A-level WORKER_TOKEN_OPENING material, the
// only Worker evidence the commit phase may hold.
type workerTokenArtifacts struct {
	inputTokenIDs, generatedTokenIDs []byte
	// generationParams is the canonical generation_params artifact; the
	// fake ref path has none.
	generationParams []byte
}

// tokenIDs is the A-level material the prefill runs over.
func (e workerTokenArtifacts) tokenIDs() (modelservice.TokenIDs, error) {
	input, err := nodewire.DecodeTokenIDs(e.inputTokenIDs)
	if err != nil {
		return modelservice.TokenIDs{}, fmt.Errorf("Worker input token IDs: %w", err)
	}
	generated, err := nodewire.DecodeTokenIDs(e.generatedTokenIDs)
	if err != nil {
		return modelservice.TokenIDs{}, fmt.Errorf("Worker generated token IDs: %w", err)
	}
	return modelservice.TokenIDs{Input: input, Generated: generated}, nil
}

// workerTokenEvidence returns the A-level material.
//
// There are two ways to get it and they are not fallbacks for each other. The
// confirmed artifacts arrive already bound to the receipt's on-chain
// commitments, which is what a real chain gives. The ref path is the fake model
// transport's, where the Worker and the Verifier share one model service that
// can resolve the Worker's material refs; the protocol artifacts are then
// re-derived from that material exactly as the Worker derived them.
func (v *Verifier) workerTokenEvidence(ctx context.Context, state TaskState, limits map[nodewire.EvidenceKind]uint64) (workerTokenArtifacts, error) {
	if len(state.ConfirmedWorkerValues) > 0 {
		return workerTokenArtifacts{}, ErrBLevelBeforeCommit
	}
	var out workerTokenArtifacts
	if len(state.ConfirmedInputTokenIDs) > 0 || len(state.ConfirmedGeneratedTokenIDs) > 0 || len(state.ConfirmedGenerationParams) > 0 {
		if len(state.ConfirmedInputTokenIDs) == 0 || len(state.ConfirmedGeneratedTokenIDs) == 0 || len(state.ConfirmedGenerationParams) == 0 {
			return workerTokenArtifacts{}, fmt.Errorf(
				"confirmed Worker token evidence is incomplete for task %s: input_token_ids, generated_token_ids and generation_params are all required", state.TaskID)
		}
		out = workerTokenArtifacts{
			inputTokenIDs: state.ConfirmedInputTokenIDs, generatedTokenIDs: state.ConfirmedGeneratedTokenIDs,
			generationParams: state.ConfirmedGenerationParams,
		}
	} else {
		artifact, err := v.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
			RequestID: "verifier-fetch-token-ids-" + state.TaskID, ModelServiceID: v.cfg.ModelServiceID,
			Ref: state.OutputPackage.TokenIDsRef, SizeLimitBytes: limits[nodewire.EvidenceKindWorkerTokenOpening], Kind: "token-ids",
		})
		if err != nil {
			return workerTokenArtifacts{}, err
		}
		ids, err := modelservice.DecodeTokenIDsArtifact(artifact.Data)
		if err != nil {
			return workerTokenArtifacts{}, err
		}
		if out.inputTokenIDs, out.generatedTokenIDs, err = modelservice.ProtocolTokenIDs(ids); err != nil {
			return workerTokenArtifacts{}, err
		}
	}
	// The confirmer bounded the artifacts against the chain-committed
	// encoded_size_bytes, which the Keeper checked against the locked Profile.
	// This node's own bound is re-applied anyway: the guarantee must not depend
	// on which caller assembled the state.
	if size := uint64(len(out.inputTokenIDs) + len(out.generatedTokenIDs)); size > limits[nodewire.EvidenceKindWorkerTokenOpening] {
		return workerTokenArtifacts{}, fmt.Errorf("Worker token-id evidence is %d bytes, above the locked profile bound", size)
	}
	return out, nil
}

// workerValueArtifacts is the B-level WORKER_VALUE_OPENING material, decoded
// strictly under this task's binding.
type workerValueArtifacts struct {
	workerValues    []byte
	workerLeaves    []nodewire.PositionValueV1
	workerValueRoot codec.Hash
}

// workerValueEvidence returns the B-level material. Only the reveal calls it
// (reveal_material.go), after the round is REVEALING.
func (v *Verifier) workerValueEvidence(ctx context.Context, state TaskState, limits map[nodewire.EvidenceKind]uint64, requiredTopK uint32, acceptedTaskHash []byte, positionValuesRef string) (workerValueArtifacts, error) {
	binding, err := v.workerValueBinding(state, acceptedTaskHash, requiredTopK)
	if err != nil {
		return workerValueArtifacts{}, err
	}
	var out workerValueArtifacts
	switch {
	case len(state.ConfirmedWorkerValues) > 0:
		out.workerValues = state.ConfirmedWorkerValues
	case v.cfg.FakeOutput && positionValuesRef != "":
		artifact, err := v.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
			RequestID: "verifier-fetch-position-values-" + state.TaskID, ModelServiceID: v.cfg.ModelServiceID,
			Ref: positionValuesRef, SizeLimitBytes: limits[nodewire.EvidenceKindWorkerValueOpening], Kind: "position-values", AllowEmpty: true,
		})
		if err != nil {
			return workerValueArtifacts{}, err
		}
		values, err := modelservice.DecodePositionValuesArtifact(artifact.Data)
		if err != nil {
			return workerValueArtifacts{}, err
		}
		leaves, err := metric.ValueLeaves(values, requiredTopK)
		if err != nil {
			return workerValueArtifacts{}, err
		}
		if out.workerValues, err = nodewire.EncodeWorkerValues(binding, leaves); err != nil {
			return workerValueArtifacts{}, err
		}
	default:
		return workerValueArtifacts{}, fmt.Errorf(
			"confirmed Worker value evidence is incomplete for task %s: the reveal needs the WORKER_VALUE_OPENING worker_values", state.TaskID)
	}
	if size := uint64(len(out.workerValues)); size > limits[nodewire.EvidenceKindWorkerValueOpening] {
		return workerValueArtifacts{}, fmt.Errorf("Worker value evidence is %d bytes, above the locked profile bound", size)
	}
	if out.workerLeaves, err = nodewire.DecodeWorkerValues(binding, out.workerValues); err != nil {
		return workerValueArtifacts{}, fmt.Errorf("Worker values: %w", err)
	}
	if out.workerValueRoot, err = nodewire.WorkerValueRoot(binding, out.workerLeaves); err != nil {
		return workerValueArtifacts{}, err
	}
	return out, nil
}

func (v *Verifier) workerValueBinding(state TaskState, acceptedTaskHash []byte, requiredTopK uint32) (nodewire.WorkerValueBindingV1, error) {
	taskID, err := hash32FromHex("task_id", state.TaskID)
	if err != nil {
		return nodewire.WorkerValueBindingV1{}, err
	}
	return nodewire.WorkerValueBindingV1{
		ChainID: v.cfg.ChainID, TaskID: taskID[:], AcceptedTaskHash: acceptedTaskHash,
		WorkerOperatorAddress: state.WorkerAddress, RequiredTopK: requiredTopK,
	}, nil
}

// verifierValueLeaves frames this Verifier's own values and roots them. It
// runs on the model service's answer alone, before any comparison, so the root
// the commit binds is fixed by this Verifier's prefill and nothing else.
func (v *Verifier) verifierValueLeaves(state TaskState, acceptedTaskHash []byte, requiredTopK uint32, values []metric.PositionValue) ([]nodewire.PositionValueV1, codec.Hash, error) {
	leaves, err := metric.ValueLeaves(values, requiredTopK)
	if err != nil {
		return nil, codec.Hash{}, fmt.Errorf("frame verifier values: %w", err)
	}
	taskID, err := hash32FromHex("task_id", state.TaskID)
	if err != nil {
		return nil, codec.Hash{}, err
	}
	if state.VerifyRound == 0 || state.VerifyRound > 2 {
		return nil, codec.Hash{}, fmt.Errorf("verify round %d is not 1 or 2", state.VerifyRound)
	}
	root, err := nodewire.VerifierValueRoot(nodewire.VerifierValueBindingV1{
		ChainID: v.cfg.ChainID, TaskID: taskID[:], TaskHash: acceptedTaskHash, VerifyRound: uint32(state.VerifyRound),
		VerifierOperatorAddress: v.cfg.VerifierAddress, RequiredTopK: requiredTopK,
	}, leaves)
	if err != nil {
		return nil, codec.Hash{}, err
	}
	return leaves, root, nil
}
