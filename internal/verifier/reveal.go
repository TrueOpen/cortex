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

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/metric"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/tasktrace"
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

// RevealResult is what happened to the reveal responsibility. Published is
// Nexus delivery of the signed credential and nothing weaker: the Keeper writes
// ResultState from the Builder's relayed MsgSubmitVerifyResult, so this node
// never observes chain acceptance here.
type RevealResult struct {
	Published bool
	Subject   string
	// ExpiryHeight is the reveal deadline the signed body actually carried. It
	// is reported back so an operator can confirm the body was bound by the
	// Keeper's reveal window and not by some other deadline.
	ExpiryHeight        uint64
	ResultSigningDigest codec.Hash
}

// HandleRevealPhaseStarted assembles, signs and publishes the frozen
// task.v1.ResultReceiptV2 for a task whose reveal phase the chain has
// opened.
//
// It runs the same ordering rule the commit path runs: the body is completed
// first, its TRUEOPEN_RESULT_V2 digest is derived from that exact value, the
// signature is written back into the same struct, and resultPayload marshals
// only from there -- so an incomplete body stops the path before the signer is
// ever asked for anything.
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
	if v.cfg.Builder == nil {
		return RevealResult{}, fmt.Errorf("Builder client is required for normal verifier result delivery")
	}
	if err := v.cfg.EvidencePublisher.PublishVerifierEvidence(ctx, state, resultWire, reveal.EvidenceManifest, reveal.MetricMaterial.AggregateProof.Bytes); err != nil {
		return RevealResult{}, fmt.Errorf("finalize verifier evidence bundle: %w", err)
	}
	// The bus VERIFY_RESULT payload is the frozen signed credential itself: the
	// bytes a verifier signs are the bytes the Builder relays on chain. The
	// retired Nexus-local VerifyResult shape (sample values, salt, commit and
	// result items inline) is gone with the JSON bus; those materials stay local
	// evidence, and the chain path reads them through the frozen Msgs.
	message, err := builderclient.ResultReceiptProto(resultWire)
	if err != nil {
		return RevealResult{}, err
	}
	subject := builderclient.NATSVerifyResultSubject(state.TaskID)
	payload, err := v.encodeNexusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindVerifyResult, ChainID: v.cfg.ChainID, Subject: subject,
		SenderOperatorAddress: v.cfg.VerifierAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: v.cfg.ServiceAuthorizationNonce,
	}, message)
	if err != nil {
		return RevealResult{}, err
	}
	resultSigningDigest, digestErr := nodewire.ResultReceiptSigningDigest(resultWire)
	if digestErr != nil {
		// Re-deriving a digest that was signed a few lines above cannot fail for
		// any reason the trace should turn into a task failure, so the value is
		// reported as zero rather than raised.
		resultSigningDigest = codec.Hash{}
	}
	v.cfg.Trace.Event("verify_result_published",
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
		tasktrace.Uint("expiry_height", resultWire.ExpiryHeight),
		tasktrace.Str("subject", subject), tasktrace.Int("payload_bytes", len(payload)))
	verifyResultDedupID := "verify-result:" + state.SessionID + "|" + state.TaskID + "|" + v.cfg.VerifierAddress
	persisted, err := v.persistBuilderOutbox(ctx, state.TaskID, subject, payload, verifyResultDedupID)
	if err != nil {
		return RevealResult{}, err
	}
	if !persisted {
		if err := v.cfg.Builder.Publish(ctx, builderclient.PublishRequest{Subject: subject, TaskID: state.TaskID, Payload: payload, DedupID: verifyResultDedupID}); err != nil {
			return RevealResult{}, err
		}
	}
	return RevealResult{
		Published: true, Subject: subject,
		ExpiryHeight: resultWire.ExpiryHeight, ResultSigningDigest: resultSigningDigest,
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

// revealSource is one verify run's output as the reveal needs it: the compact
// reveal bytes and the metric material derived from the same run.
type revealSource struct {
	ResultReveal     []byte
	MetricMaterial   metric.Material
	EvidenceManifest []byte
	Salt             codec.Hash
	CommitHash       codec.Hash
}

// persistedReveal restores the verify run's reveal source. Pebble is the
// authority - the reveal phase can open after a restart, and the in-memory map
// only serves the tests and single-process paths that have no evidence reader.
//
// The metric material is deliberately allowed to be absent here rather than
// refused: the credential gate is the single place that decides what a missing
// preimage value means, and duplicating that judgement in the reader would give
// the same failure two different error messages.
func (v *Verifier) persistedReveal(ctx context.Context, state TaskState) (revealSource, error) {
	if reader, ok := v.cfg.Persistence.(verifierEvidenceReader); ok {
		data, err := reader.ReadVerifierEvidence(ctx, verifierFullResultRevealEvidenceKind)
		if err != nil {
			return revealSource{}, fmt.Errorf("%w: read persisted result_reveal: %v", ErrResultReceiptInputUnavailable, err)
		}
		var persisted struct {
			TaskID           string                   `json:"task_id"`
			VerifyRound      uint64                   `json:"verify_round"`
			ResultReveal     string                   `json:"result_reveal"`
			EvidenceManifest string                   `json:"evidence_manifest"`
			Salt             string                   `json:"salt"`
			CommitHash       string                   `json:"commit_hash"`
			MetricMaterial   *persistedMetricMaterial `json:"metric_material"`
		}
		if err := json.Unmarshal(data, &persisted); err != nil {
			return revealSource{}, fmt.Errorf("%w: decode persisted result_reveal: %v", ErrResultReceiptInputUnavailable, err)
		}
		if persisted.TaskID != state.TaskID || persisted.VerifyRound != state.VerifyRound {
			return revealSource{}, fmt.Errorf(
				"%w: persisted result_reveal belongs to task %q round %d, want task %q round %d",
				ErrResultReceiptInputUnavailable, persisted.TaskID, persisted.VerifyRound, state.TaskID, state.VerifyRound)
		}
		if persisted.ResultReveal == "" {
			return revealSource{}, fmt.Errorf("%w: persisted result_reveal is empty", ErrResultReceiptInputUnavailable)
		}
		// The record holds the framed reveal bytes as hex. A record written by
		// the retired compact `p00000000=...|salt=...` text encoding fails to
		// decode here, and that is the correct outcome rather than a migration
		// gap: its bytes are not the bytes the commit already on chain bound, so
		// a credential built from them could never satisfy keeper §10.11 rule 5.
		revealBytes, err := hex.DecodeString(persisted.ResultReveal)
		if err != nil || len(revealBytes) == 0 {
			return revealSource{}, fmt.Errorf(
				"%w: persisted result_reveal is not canonical hex-encoded reveal bytes", ErrResultReceiptInputUnavailable)
		}
		manifest, err := hex.DecodeString(persisted.EvidenceManifest)
		if err != nil || len(manifest) == 0 {
			return revealSource{}, fmt.Errorf("%w: persisted evidence_manifest is not hex-encoded manifest bytes", ErrResultReceiptInputUnavailable)
		}
		salt, err := hash32FromHex("salt", persisted.Salt)
		if err != nil {
			return revealSource{}, fmt.Errorf("%w: %w", ErrResultReceiptInputUnavailable, err)
		}
		commitHash, err := hash32FromHex("commit_hash", persisted.CommitHash)
		if err != nil {
			return revealSource{}, fmt.Errorf("%w: %w", ErrResultReceiptInputUnavailable, err)
		}
		source := revealSource{ResultReveal: revealBytes, EvidenceManifest: manifest, Salt: salt, CommitHash: commitHash}
		if persisted.MetricMaterial != nil {
			material, err := persisted.MetricMaterial.restore()
			if err != nil {
				return revealSource{}, fmt.Errorf("%w: persisted metric material: %v", ErrResultReceiptInputUnavailable, err)
			}
			source.MetricMaterial = material
		}
		return source, nil
	}

	prefix := fmt.Sprintf("%s/%d/%s/", state.TaskID, state.VerifyRound, v.cfg.VerifierAddress)
	for key, result := range v.results {
		if strings.HasPrefix(key, prefix) && len(result.ResultReveal) > 0 {
			return revealSource{ResultReveal: result.ResultReveal, MetricMaterial: result.MetricMaterial, EvidenceManifest: result.EvidenceManifest, Salt: result.Salt, CommitHash: result.CommitHash}, nil
		}
	}
	return revealSource{}, fmt.Errorf("%w: result_reveal has no persisted or in-memory source", ErrResultReceiptInputUnavailable)
}
