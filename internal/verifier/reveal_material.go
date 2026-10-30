package verifier

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// verifierRevealMaterialEvidenceKind is the second phase's write-once record:
// the result payload, the verifier bundle manifest and the metric material,
// all derived after the round entered REVEALING.
const verifierRevealMaterialEvidenceKind = "verifier-reveal-material"

type persistedRevealMaterial struct {
	TaskID           string                   `json:"task_id"`
	VerifyRound      uint64                   `json:"verify_round"`
	ResultReveal     string                   `json:"result_reveal"`
	EvidenceManifest string                   `json:"evidence_manifest"`
	MetricMaterial   *persistedMetricMaterial `json:"metric_material"`
}

// buildReveal is CD §6.2 V14a–V14c: read the Worker's B-level values, compare
// them position by position with the committed verifier leaves, and persist
// the metric material and verifier bundle before anything is signed. It
// never changes the committed verifier_value_root or salt.
func (v *Verifier) buildReveal(ctx context.Context, state TaskState, facts taskfacts.Facts, source revealSource) (revealSource, error) {
	fail := func(err error) (revealSource, error) {
		return revealSource{}, fmt.Errorf("%w: %w", ErrResultReceiptInputUnavailable, err)
	}
	profile, served, err := v.lockedProfile(ctx, state)
	if err != nil {
		return revealSource{}, err
	}
	limits, err := v.profileEvidenceLimits(state, profile, served)
	if err != nil {
		return revealSource{}, err
	}
	binding, bound, err := v.metricBinding(ctx, state, profile, served)
	if err != nil {
		return revealSource{}, err
	}
	if !bound || binding.RequiredTopK != source.requiredTopK {
		return fail(fmt.Errorf("the locked metric profile is unavailable or no longer frames required_top_k %d", source.requiredTopK))
	}
	taskID, err := hash32FromHex("task_id", state.TaskID)
	if err != nil {
		return fail(err)
	}
	root, err := nodewire.VerifierValueRoot(nodewire.VerifierValueBindingV1{
		ChainID: v.cfg.ChainID, TaskID: taskID[:], TaskHash: facts.AcceptedTaskHash, VerifyRound: uint32(state.VerifyRound),
		VerifierOperatorAddress: v.cfg.VerifierAddress, RequiredTopK: source.requiredTopK,
	}, source.verifierLeaves)
	if err != nil || root != source.MetricMaterial.VerifierValueRoot {
		return fail(fmt.Errorf("persisted verifier leaves do not re-derive the committed verifier_value_root %s", source.MetricMaterial.VerifierValueRoot))
	}
	ref := state.OutputPackage.PositionValuesRef
	if ref == "" {
		ref = source.positionValuesRef
	}
	values, err := v.workerValueEvidence(ctx, state, limits, source.requiredTopK, facts.AcceptedTaskHash, ref)
	if err != nil {
		return revealSource{}, err
	}
	if !v.cfg.FakeOutput {
		if err := v.validateWorkerValueEvidence(ctx, state, profile, limits, values); err != nil {
			return revealSource{}, err
		}
	}
	if err := checkWorkerLeavesNameTheCommittedTokens(values.workerLeaves, source.verifierLeaves); err != nil {
		return revealSource{}, err
	}
	material, err := buildMetricMaterial(binding, true, root, values.workerLeaves, source.verifierLeaves)
	if err != nil {
		return revealSource{}, err
	}
	manifest, err := (evidencebundle.Manifest{
		Version: 1, ChainID: v.cfg.ChainID, TaskID: state.TaskID,
		TaskHash: hex.EncodeToString(facts.AcceptedTaskHash), VerifyRound: uint32(state.VerifyRound),
		EvidenceKind: evidencebundle.KindVerifierValueOpening,
		ProducerKind: "VERIFIER", ProducerOperator: v.cfg.VerifierAddress,
		EvidenceSchemaHash: binding.EvidenceSchemaHash.String(),
		Artifacts:          []evidencebundle.Artifact{evidencebundle.NewArtifact(builderclient.EvidenceArtifactAggregateProof, material.AggregateProof.Bytes)},
	}).Encode()
	if err != nil {
		return revealSource{}, fmt.Errorf("build verifier evidence manifest: %w", err)
	}
	resultReveal, err := canonicalResultPayload(v.cfg, state, facts, material, manifest)
	if err != nil {
		return fail(err)
	}
	if err := v.persistRevealMaterial(ctx, state, resultReveal, manifest, material); err != nil {
		return revealSource{}, err
	}
	v.cfg.Trace.Event("verify_reveal_material_built",
		tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
		tasktrace.Hash("worker_value_root", values.workerValueRoot), tasktrace.Hash("verifier_value_root", root),
		tasktrace.Hash("metric_root", material.Root), tasktrace.Int("metric_leaf_count", material.LeafCount),
		tasktrace.Hash("aggregate_proof_hash", material.AggregateProof.Hash))
	source.ResultReveal, source.EvidenceManifest, source.MetricMaterial = resultReveal, manifest, material
	return source, nil
}

// checkWorkerLeavesNameTheCommittedTokens is the B-level legality check: the
// Worker's value at every position must name the generated token the commit
// scored (CD §6.2 V14b WORKER_EVIDENCE_INVALID). Values that reproduce their
// commitment but describe other tokens are illegal content, not absent data.
func checkWorkerLeavesNameTheCommittedTokens(worker, committed []nodewire.PositionValueV1) error {
	if len(worker) != len(committed) {
		return fmt.Errorf("%w: %d Worker value leaves against %d committed generated positions",
			ErrWorkerEvidenceInvalid, len(worker), len(committed))
	}
	for i := range worker {
		if worker[i].TokenID != committed[i].TokenID {
			return fmt.Errorf("%w: Worker value at position %d names token %d, the committed token is %d",
				ErrWorkerEvidenceInvalid, i, worker[i].TokenID, committed[i].TokenID)
		}
	}
	return nil
}

func (v *Verifier) persistRevealMaterial(ctx context.Context, state TaskState, resultReveal, manifest []byte, material metric.Material) error {
	if v.cfg.Persistence == nil {
		return nil
	}
	projected := projectMetricMaterial(material)
	data, err := json.Marshal(persistedRevealMaterial{
		TaskID: state.TaskID, VerifyRound: state.VerifyRound,
		ResultReveal: hex.EncodeToString(resultReveal), EvidenceManifest: hex.EncodeToString(manifest), MetricMaterial: &projected,
	})
	if err != nil {
		return err
	}
	return v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: state.TaskID, Kind: verifierRevealMaterialEvidenceKind, Data: data, Ref: evidenceRef(data)})
}
