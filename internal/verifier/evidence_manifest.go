package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/revealcontract"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

func selectedVerifierIndex(state TaskState, verifier string) (uint32, error) {
	seen := make(map[string]bool, len(state.AssignedVerifiers))
	selected := -1
	for i, address := range state.AssignedVerifiers {
		if seen[address] {
			return 0, fmt.Errorf("selected verifier list contains duplicate %q", address)
		}
		seen[address] = true
		if address == verifier {
			selected = i
		}
	}
	if selected < 0 || uint64(selected) > math.MaxUint32 {
		return 0, fmt.Errorf("selected verifier index unavailable for %q", verifier)
	}
	return uint32(selected), nil
}

func canonicalResultPayload(cfg Config, state TaskState, facts taskfacts.Facts, material metric.Material, manifest []byte) ([]byte, error) {
	if err := facts.Validate(state.TaskID); err != nil {
		return nil, err
	}
	if len(facts.ProfileExecutionSnapshotHash) != 32 || isZeroHash32(facts.ProfileExecutionSnapshotHash) {
		return nil, fmt.Errorf("profile_execution_snapshot_hash must be a served nonzero Hash32")
	}
	if state.VerifyRound == 0 || state.VerifyRound > math.MaxUint32 || material.LeafCount <= 0 || uint64(material.LeafCount) > math.MaxUint32 {
		return nil, fmt.Errorf("result round and metric leaf count must fit positive uint32")
	}
	index, err := selectedVerifierIndex(state, cfg.VerifierAddress)
	if err != nil {
		return nil, err
	}
	taskID, err := hash32FromHex("task_id", state.TaskID)
	if err != nil {
		return nil, err
	}
	summaryHash, err := nodewire.MetricSummaryHash(material.Summary)
	if err != nil {
		return nil, err
	}
	return revealcontract.CanonicalVerifierResultPayload(revealcontract.VerifierResultPayloadV1{
		ChainID: cfg.ChainID, TaskID: taskID, TaskHash: codec.Hash(facts.AcceptedTaskHash),
		VerifyRound: uint32(state.VerifyRound), SelectedVerifierIndex: index,
		VerifierOperatorAddress: cfg.VerifierAddress, InferReceiptHash: state.InferReceiptHash,
		ProfileExecutionSnapshotHash: codec.Hash(facts.ProfileExecutionSnapshotHash),
		GenerationParamsDigest:       codec.Hash(facts.GenerationParamsDigest),
		MetricRoot:                   material.Root, MetricLeafCount: uint32(material.LeafCount), MetricSummaryHash: summaryHash,
		AggregateProofHash: material.AggregateProof.Hash, VerifierEvidenceBundleHash: evidencebundle.Hash(manifest),
		VerifierEvidenceManifestSizeBytes: uint64(len(manifest)),
	})
}

// Rebuild each commitment from persisted bytes and authoritative task inputs.
// This also refuses records from the retired salted payload format.
func (v *Verifier) validateRevealSource(ctx context.Context, state TaskState, facts taskfacts.Facts, source revealSource) error {
	fail := func(err error) error {
		return fmt.Errorf("%w: persisted verifier evidence: %w", ErrResultReceiptInputUnavailable, err)
	}
	manifest, err := evidencebundle.Decode(source.EvidenceManifest)
	if err != nil {
		return fail(err)
	}
	profile, served, err := v.lockedProfile(ctx, state)
	if err != nil {
		return err
	}
	binding, bound, err := v.metricBinding(ctx, state, profile, served)
	if err != nil {
		return err
	}
	if !bound {
		return fail(fmt.Errorf("locked metric profile is required"))
	}
	if manifest.ChainID != v.cfg.ChainID || manifest.TaskID != state.TaskID ||
		manifest.TaskHash != hex.EncodeToString(facts.AcceptedTaskHash) || manifest.VerifyRound != uint32(state.VerifyRound) ||
		manifest.ProducerKind != "VERIFIER" || manifest.ProducerOperator != v.cfg.VerifierAddress ||
		manifest.EvidenceSchemaHash != binding.EvidenceSchemaHash.String() {
		return fail(fmt.Errorf("manifest scope does not match the locked task"))
	}
	proof, err := metric.BuildAggregateProof(binding, source.MetricMaterial.Root, source.MetricMaterial.LeafCount, source.MetricMaterial.Summary)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(proof.Bytes, source.MetricMaterial.AggregateProof.Bytes) || proof.Hash != source.MetricMaterial.AggregateProof.Hash ||
		manifest.Artifacts[0] != evidencebundle.NewArtifact("aggregate_proof", proof.Bytes) {
		return fail(fmt.Errorf("aggregate_proof does not match the manifest and metric binding"))
	}
	payload, err := canonicalResultPayload(v.cfg, state, facts, source.MetricMaterial, source.EvidenceManifest)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(payload, source.ResultReveal) {
		return fail(fmt.Errorf("result payload does not match the locked task and evidence"))
	}
	if source.Salt.IsZero() || source.CommitHash.IsZero() {
		return fail(fmt.Errorf("salt and commit_hash must be nonzero"))
	}
	taskID, _ := hex.DecodeString(state.TaskID)
	payloadHash := nodewire.ResultPayloadHash(payload)
	commit, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV2{
		ChainID: v.cfg.ChainID, TaskID: taskID, TaskHash: facts.AcceptedTaskHash,
		VerifyRound: uint32(state.VerifyRound), VerifierOperatorAddress: v.cfg.VerifierAddress,
		ResultPayloadHash: payloadHash[:], Salt: source.Salt[:],
	})
	if err != nil {
		return fail(err)
	}
	if commit != source.CommitHash {
		return fail(fmt.Errorf("result payload and salt do not match commit_hash"))
	}
	return nil
}
