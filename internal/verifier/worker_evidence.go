package verifier

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// workerEvidenceArtifacts are the Worker's two bundles as the Verifier holds
// them: the A-level token-id artifacts and the B-level worker_values artifact,
// with the value leaves decoded strictly under this task's binding.
type workerEvidenceArtifacts struct {
	inputTokenIDs, generatedTokenIDs, workerValues []byte
	workerLeaves                                   []nodewire.PositionValueV1
	workerValueRoot                                codec.Hash
}

// tokenIDs is the A-level material the prefill runs over.
func (e workerEvidenceArtifacts) tokenIDs() (modelservice.TokenIDs, error) {
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

// workerEvidence returns the Worker's evidence the verify opens.
//
// There are two ways to get it and they are not fallbacks for each other. The
// confirmed artifacts arrive already bound to the receipt's on-chain
// commitments, which is what a real chain gives. The ref path is the fake model
// transport's, where the Worker and the Verifier share one model service that
// can resolve the Worker's material refs; the protocol artifacts are then
// re-derived from that material exactly as the Worker derived them.
//
// requiredTopK is the locked Profile's; zero means no Profile is bound (the
// fake/dev configuration), in which case the value leaves are not decoded and
// no metric material can be built.
func (v *Verifier) workerEvidence(ctx context.Context, state TaskState, limits map[nodewire.EvidenceKind]uint64, requiredTopK uint32, acceptedTaskHash []byte) (workerEvidenceArtifacts, error) {
	var out workerEvidenceArtifacts
	confirmed := len(state.ConfirmedInputTokenIDs) > 0 || len(state.ConfirmedGeneratedTokenIDs) > 0 || len(state.ConfirmedWorkerValues) > 0
	if confirmed {
		if len(state.ConfirmedInputTokenIDs) == 0 || len(state.ConfirmedGeneratedTokenIDs) == 0 || len(state.ConfirmedWorkerValues) == 0 {
			return workerEvidenceArtifacts{}, fmt.Errorf(
				"confirmed Worker evidence is incomplete for task %s: both the token and the value bundle are required", state.TaskID)
		}
		out.inputTokenIDs, out.generatedTokenIDs, out.workerValues = state.ConfirmedInputTokenIDs, state.ConfirmedGeneratedTokenIDs, state.ConfirmedWorkerValues
	} else {
		fetch := func(name, ref string, kind nodewire.EvidenceKind) ([]byte, error) {
			artifact, err := v.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
				RequestID: "verifier-fetch-" + name + "-" + state.TaskID, ModelServiceID: v.cfg.ModelServiceID,
				Ref: ref, SizeLimitBytes: limits[kind], Kind: name, AllowEmpty: name == "position-values",
			})
			return artifact.Data, err
		}
		tokenMaterial, err := fetch("token-ids", state.OutputPackage.TokenIDsRef, nodewire.EvidenceKindWorkerTokenOpening)
		if err != nil {
			return workerEvidenceArtifacts{}, err
		}
		valueMaterial, err := fetch("position-values", state.OutputPackage.PositionValuesRef, nodewire.EvidenceKindWorkerValueOpening)
		if err != nil {
			return workerEvidenceArtifacts{}, err
		}
		ids, err := modelservice.DecodeTokenIDsArtifact(tokenMaterial)
		if err != nil {
			return workerEvidenceArtifacts{}, err
		}
		if out.inputTokenIDs, out.generatedTokenIDs, err = modelservice.ProtocolTokenIDs(ids); err != nil {
			return workerEvidenceArtifacts{}, err
		}
		if requiredTopK != 0 {
			values, err := modelservice.DecodePositionValuesArtifact(valueMaterial)
			if err != nil {
				return workerEvidenceArtifacts{}, err
			}
			leaves, err := metric.ValueLeaves(values, requiredTopK)
			if err != nil {
				return workerEvidenceArtifacts{}, err
			}
			binding, err := v.workerValueBinding(state, acceptedTaskHash, requiredTopK)
			if err != nil {
				return workerEvidenceArtifacts{}, err
			}
			if out.workerValues, err = nodewire.EncodeWorkerValues(binding, leaves); err != nil {
				return workerEvidenceArtifacts{}, err
			}
		}
	}
	// The confirmer bounded the artifacts against the chain-committed
	// encoded_size_bytes, which the Keeper checked against the locked Profile.
	// This node's own bound is re-applied anyway: the guarantee must not depend
	// on which caller assembled the state.
	if size := uint64(len(out.inputTokenIDs) + len(out.generatedTokenIDs)); size > limits[nodewire.EvidenceKindWorkerTokenOpening] {
		return workerEvidenceArtifacts{}, fmt.Errorf("Worker token-id evidence is %d bytes, above the locked profile bound", size)
	}
	if size := uint64(len(out.workerValues)); size > limits[nodewire.EvidenceKindWorkerValueOpening] {
		return workerEvidenceArtifacts{}, fmt.Errorf("Worker value evidence is %d bytes, above the locked profile bound", size)
	}
	if requiredTopK == 0 {
		return out, nil
	}
	binding, err := v.workerValueBinding(state, acceptedTaskHash, requiredTopK)
	if err != nil {
		return workerEvidenceArtifacts{}, err
	}
	if out.workerLeaves, err = nodewire.DecodeWorkerValues(binding, out.workerValues); err != nil {
		return workerEvidenceArtifacts{}, fmt.Errorf("Worker values: %w", err)
	}
	if out.workerValueRoot, err = nodewire.WorkerValueRoot(binding, out.workerLeaves); err != nil {
		return workerEvidenceArtifacts{}, err
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
