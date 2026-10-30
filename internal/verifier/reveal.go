package verifier

// The reveal responsibility: what a Verifier owes once the chain opens the
// reveal phase, and why it is not part of the commit.
//
// Task-04-Verification-flow.md gives MsgSubmitVerifyResult one admission window:
// it may be submitted only after EventRevealPhaseStarted, and the Keeper handler
// refuses every reveal that reaches it before the task entered REVEALING. The
// commit path cannot satisfy that by construction -- it runs before any commit
// is on chain, so it necessarily runs before the phase that only opens once the
// commits are counted (keeper §10.6: StartRevealPhase fires on
// selected_verifier_count CommitStates, or at the commit deadline).
//
// The second half of the same fact is the deadline. keeper §10.7 writes
// reveal_deadline_height exactly once, inside StartRevealPhase
// (reveal_deadline_height = current_height + reveal_window_blocks), so before
// the phase opens the verifier assignment snapshot carries a zero there -- not
// as a gap, as the protocol's own answer. resultReceiptWire refuses that zero
// (verifier.go, "verify result expiry_height requires the Keeper verifier reveal
// deadline height") and must keep refusing it: expiry_height is a frozen
// preimage field the Keeper compares, and no commit deadline, guess or fallback
// may stand in for it. This file does not relax that gate; it makes the gate
// reachable, by giving EventRevealPhaseStarted somewhere to land.
//
// So the reveal is opened by the phase, not by the commit. It is durable for the
// same reason the commit responsibility is: the daemon records the verify
// responsibility as StageCommitted with the reveal deadline the event carried,
// and a process that restarts between the two rebuilds the reveal from Pebble
// rather than losing it. No scheduler is involved -- the trigger is an event
// that already arrives, which is what keeps this off issue #108's durable
// deadline scheduling.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

const verifierFullResultRevealEvidenceKind = "verifier-full-result-reveal-state"

// ErrRevealPhaseNotStarted marks a reveal refused because the chain has not
// opened the reveal phase for this task yet.
//
// It is deliberately distinct from ErrResultReceiptInputUnavailable. That one
// says a frozen preimage value has no producer in Cortex at all; this one says
// every producer exists and the chain has simply not spoken yet, which is the
// protocol working rather than a gap. A caller that cannot tell them apart
// either retries a permanent gap forever or gives up on a wait that was about to
// end.
var ErrRevealPhaseNotStarted = errors.New("Keeper reveal phase has not started for this task")

// RevealResult is what happened to the reveal responsibility. Signed says the
// result credential was signed over a finalized evidence bundle. The Phase 0
// bus VERIFY_RESULT that carried it to the Builder is retired with wire
// 916e393; the credential reaches the chain only as MsgSubmitVerifyResult, so
// this node never observes chain acceptance here.
type RevealResult struct {
	Signed bool
	// ExpiryHeight is the reveal deadline the signed body actually carried. It
	// is reported back so an operator can confirm the body was bound by the
	// Keeper's reveal window and not by some other deadline.
	ExpiryHeight        uint64
	ResultSigningDigest codec.Hash
	// ResultDigest is SHA256 of the result payload; ResultReveal,
	// EvidenceManifest and MetricMaterial are the second phase's output.
	ResultDigest     codec.Hash
	ResultReveal     []byte
	EvidenceManifest []byte
	MetricMaterial   metric.Material
}

// HandleRevealPhaseStarted assembles, signs and publishes the frozen
// task.v1.ResultReceiptV3 for a task whose reveal phase the chain has
// opened.
//
// It runs the same ordering rule the commit path runs: the body is completed
// first, its TRUEOPEN_RESULT_V3 digest is derived from that exact value, and
// the signature is written back into the same struct that is published -- so
// an incomplete body stops the path before the signer is ever asked for
// anything.
//
// It deliberately does NOT re-run the verifier precheck. That precheck decides
// whether to start verifying, and judges the commit window while doing so; by
// the time the reveal phase opens that window is closing or shut, and the work
// it gates is already on chain as this node's CommitState. The gate that belongs
// here is the reveal phase itself.
func (v *Verifier) HandleRevealPhaseStarted(ctx context.Context, state TaskState) (RevealResult, error) {
	if !state.OpenVerifyAccepted || !slices.Contains(state.AssignedVerifiers, v.cfg.VerifierAddress) {
		// Unlike the commit path this is an error rather than a quiet no-op: a
		// reveal responsibility exists only because this node's own commit
		// reached the chain, so a state that says this node is not a selected
		// Verifier is a wiring fault, and reporting it as "nothing to do" would
		// let the caller mark the responsibility finished.
		return RevealResult{}, fmt.Errorf(
			"verifier %s has no reveal responsibility for task %s: the state does not name it as an accepted selected verifier",
			v.cfg.VerifierAddress, state.TaskID)
	}
	if err := validateCanonicalTaskState(state); err != nil {
		return RevealResult{}, err
	}
	if state.RevealDeadlineHeight == 0 {
		return RevealResult{}, fmt.Errorf(
			"%w: task %s round %d has no reveal_deadline_height, and keeper §10.7 writes that height only in "+
				"StartRevealPhase, so the reveal cannot be submitted and its expiry_height cannot be sourced",
			ErrRevealPhaseNotStarted, state.TaskID, state.VerifyRound)
	}
	// generation_params_digest is frozen preimage field 7 and a consensus read,
	// so it is fetched rather than derived. v.taskFacts validates the answer it
	// returns, so an answer that belongs to another task, lacks the fact, or
	// serves 32 zero bytes never reaches the assembler below.
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return RevealResult{}, err
	}
	// One read serves both halves of the credential. The compact reveal and the
	// metric material were written by the same verify run under the same
	// task/round identity, and reading them separately would allow a body whose
	// metric_root describes one run and whose result payload describes
	// another.
	reveal, err := v.persistedReveal(ctx, state)
	if err != nil {
		return RevealResult{}, err
	}
	// The commit bound this Verifier's leaves under the index it held then; a
	// changed assignment is not this commit's round any more (S7 Q14). Checked
	// on every attempt, not only the one that builds the material.
	if index, err := selectedVerifierIndex(state, v.cfg.VerifierAddress); err != nil {
		return RevealResult{}, fmt.Errorf("%w: %w", ErrResultReceiptInputUnavailable, err)
	} else if index != reveal.selectedIndex {
		return RevealResult{}, fmt.Errorf("%w: selected verifier index is %d now and was %d at commit",
			ErrResultReceiptInputUnavailable, index, reveal.selectedIndex)
	}
	if len(reveal.ResultReveal) == 0 {
		// Second phase (CD §6.2 V14a–V14c): only now, REVEALING, is the
		// Worker's B-level material read.
		if reveal, err = v.buildReveal(ctx, state, facts, reveal); err != nil {
			v.cfg.Trace.ErrorEvent("verify_reveal_material_refused",
				tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound), tasktrace.Err("reason", err))
			return RevealResult{}, err
		}
	}
	if err := v.validateRevealSource(ctx, state, facts, reveal); err != nil {
		return RevealResult{}, err
	}
	resultWire, err := resultReceiptCredential(v.cfg, state, facts, reveal.ResultReveal, reveal.MetricMaterial, reveal.EvidenceManifest, reveal.Salt)
	if err != nil {
		// The refusal is traced here rather than only returned, because this is
		// the line that says which frozen value is still missing. With the
		// timing and the expiry height fixed, what remains is the metric
		// pipeline, and an operator has to be able to read that off one line
		// instead of inferring it from a retry loop.
		v.cfg.Trace.ErrorEvent("verify_reveal_refused",
			tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
			tasktrace.Uint("reveal_deadline_height", state.RevealDeadlineHeight),
			tasktrace.Err("reason", err))
		return RevealResult{}, err
	}
	if v.cfg.EvidencePublisher == nil {
		return RevealResult{}, fmt.Errorf("%w: verifier evidence publisher is required", ErrResultReceiptInputUnavailable)
	}
	if err := v.signResultReceipt(ctx, &resultWire); err != nil {
		return RevealResult{}, err
	}
	if err := v.cfg.EvidencePublisher.PublishVerifierEvidence(ctx, state, resultWire, reveal.EvidenceManifest, reveal.MetricMaterial.AggregateProof.Bytes); err != nil {
		return RevealResult{}, fmt.Errorf("finalize verifier evidence bundle: %w", err)
	}
	resultSigningDigest, digestErr := nodewire.ResultReceiptSigningDigest(resultWire)
	if digestErr != nil {
		// Re-deriving a digest that was signed a few lines above cannot fail for
		// any reason the trace should turn into a task failure, so the value is
		// reported as zero rather than raised.
		resultSigningDigest = codec.Hash{}
	}
	v.cfg.Trace.Event("verify_result_signed",
		tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
		tasktrace.Hash("result_signing_digest", resultSigningDigest),
		tasktrace.Hex("generation_params_digest", hex.EncodeToString(resultWire.GenerationParamsDigest)),
		tasktrace.Hex("metric_root", hex.EncodeToString(resultWire.MetricRoot)),
		tasktrace.Int("metric_leaf_count", reveal.MetricMaterial.LeafCount),
		// metric_summary_hash is not on the wire - the Keeper recomputes it from
		// the submitted summary - so this is the value an operator compares
		// against ResultReceiptState without decoding chain state.
		tasktrace.Hash("metric_summary_hash", metricSummaryHashOrZero(resultWire.MetricSummary)),
		tasktrace.Hex("aggregate_proof_hash", hex.EncodeToString(resultWire.AggregateProofHash)),
		tasktrace.Uint("service_authorization_nonce", resultWire.ServiceAuthorizationNonce),
		// expiry_height is printed because it is the value this whole
		// responsibility exists to carry: it must be the Keeper's reveal
		// deadline, never the commit deadline.
		tasktrace.Uint("expiry_height", resultWire.ExpiryHeight))
	return RevealResult{
		Signed: true, ExpiryHeight: resultWire.ExpiryHeight, ResultSigningDigest: resultSigningDigest,
		ResultDigest: codec.HashBytes(reveal.ResultReveal), ResultReveal: reveal.ResultReveal,
		EvidenceManifest: reveal.EvidenceManifest, MetricMaterial: reveal.MetricMaterial,
	}, nil
}

// metricSummaryHashOrZero derives the value the Keeper will store for this
// summary, for the trace only. A derivation failure prints zero rather than
// failing the reveal: the summary has already been signed by the time this
// line is written, and a log field must never be the thing that drops a
// credential the chain is waiting for.
func metricSummaryHashOrZero(summary nodewire.MetricSummaryV1) codec.Hash {
	digest, err := nodewire.MetricSummaryHash(summary)
	if err != nil {
		return codec.Hash{}
	}
	return digest
}

// revealSource is one round's reveal input: the commit state persisted before
// the commit left this node and, once the second phase has run, the reveal
// material derived in REVEALING.
type revealSource struct {
	ResultReveal      []byte
	MetricMaterial    metric.Material
	EvidenceManifest  []byte
	Salt              codec.Hash
	CommitHash        codec.Hash
	verifierLeaves    []nodewire.PositionValueV1
	requiredTopK      uint32
	selectedIndex     uint32
	positionValuesRef string
}

// persistedCommitState is the commit-state record's projection the reveal
// reads (verifier.go persistResult writes it).
type persistedCommitState struct {
	TaskID            string                     `json:"task_id"`
	VerifyRound       uint64                     `json:"verify_round"`
	Salt              string                     `json:"salt"`
	CommitHash        string                     `json:"commit_hash"`
	VerifierValueRoot string                     `json:"verifier_value_root"`
	RequiredTopK      uint32                     `json:"required_top_k"`
	SelectedIndex     uint32                     `json:"selected_verifier_index"`
	VerifierLeaves    []nodewire.PositionValueV1 `json:"verifier_leaves"`
	PositionValuesRef string                     `json:"position_values_ref"`
}

// persistedReveal restores the commit state and, once the second phase has
// run, the reveal material. ResultReveal empty means the B level has not
// been read yet. Pebble is the authority - the reveal phase can open after a
// restart - and the in-memory map only serves paths with no evidence reader.
func (v *Verifier) persistedReveal(ctx context.Context, state TaskState) (revealSource, error) {
	fail := func(format string, args ...any) (revealSource, error) {
		return revealSource{}, fmt.Errorf("%w: "+format, append([]any{ErrResultReceiptInputUnavailable}, args...)...)
	}
	reader, ok := v.cfg.Persistence.(verifierEvidenceReader)
	if !ok {
		prefix := fmt.Sprintf("%s/%d/%s/", state.TaskID, state.VerifyRound, v.cfg.VerifierAddress)
		for key, result := range v.results {
			if strings.HasPrefix(key, prefix) && result.verifierLeaves != nil {
				return revealSource{
					Salt: result.Salt, CommitHash: result.CommitHash,
					MetricMaterial: metric.Material{VerifierValueRoot: result.MetricMaterial.VerifierValueRoot},
					verifierLeaves: result.verifierLeaves, requiredTopK: result.requiredTopK,
					selectedIndex: result.selectedIndex, positionValuesRef: result.positionValuesRef,
				}, nil
			}
		}
		return fail("no commit state is persisted or held in memory for task %s round %d", state.TaskID, state.VerifyRound)
	}
	data, err := reader.ReadVerifierEvidence(ctx, verifierFullResultRevealEvidenceKind)
	if err != nil {
		return fail("read persisted commit state: %v", err)
	}
	var c persistedCommitState
	if err := json.Unmarshal(data, &c); err != nil {
		return fail("decode persisted commit state: %v", err)
	}
	if c.TaskID != state.TaskID || c.VerifyRound != state.VerifyRound {
		return fail("persisted commit state belongs to task %q round %d, want task %q round %d", c.TaskID, c.VerifyRound, state.TaskID, state.VerifyRound)
	}
	salt, err := hash32FromHex("salt", c.Salt)
	if err != nil {
		return fail("%v", err)
	}
	commitHash, err := hash32FromHex("commit_hash", c.CommitHash)
	if err != nil {
		return fail("%v", err)
	}
	root, err := hash32FromHex("verifier_value_root", c.VerifierValueRoot)
	if err != nil {
		return fail("%v", err)
	}
	if c.RequiredTopK == 0 || c.VerifierLeaves == nil {
		return fail("persisted commit state carries no verifier value leaves (written by an earlier build)")
	}
	source := revealSource{
		Salt: salt, CommitHash: commitHash, MetricMaterial: metric.Material{VerifierValueRoot: root},
		verifierLeaves: c.VerifierLeaves, requiredTopK: c.RequiredTopK, selectedIndex: c.SelectedIndex, positionValuesRef: c.PositionValuesRef,
	}
	data, err = reader.ReadVerifierEvidence(ctx, verifierRevealMaterialEvidenceKind)
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return source, nil
	}
	if err != nil {
		return fail("read persisted reveal material: %v", err)
	}
	var m persistedRevealMaterial
	if err := json.Unmarshal(data, &m); err != nil {
		return fail("decode persisted reveal material: %v", err)
	}
	if m.TaskID != state.TaskID || m.VerifyRound != state.VerifyRound || m.MetricMaterial == nil {
		return fail("persisted reveal material belongs to another round or carries no metric material")
	}
	// The record holds the framed reveal bytes as hex; anything else is refused
	// rather than turned into a credential over different bytes.
	revealBytes, err := hex.DecodeString(m.ResultReveal)
	if err != nil || len(revealBytes) == 0 {
		return fail("persisted result_reveal is not canonical hex-encoded reveal bytes")
	}
	manifest, err := hex.DecodeString(m.EvidenceManifest)
	if err != nil || len(manifest) == 0 {
		return fail("persisted evidence_manifest is not hex-encoded manifest bytes")
	}
	material, err := m.MetricMaterial.restore()
	if err != nil {
		return fail("persisted metric material: %v", err)
	}
	if material.VerifierValueRoot != root {
		return fail("persisted metric material names verifier_value_root %s, the commit bound %s", material.VerifierValueRoot, root)
	}
	source.ResultReveal, source.EvidenceManifest, source.MetricMaterial = revealBytes, manifest, material
	return source, nil
}
