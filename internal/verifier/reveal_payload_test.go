package verifier

// The sixth wall: what the reveal binds, and why the sample-value artifact is
// no longer an input to it.
//
// On devnet three selected Verifiers reached output_confirmed and
// evidence_confirmed and then retried
//
//	result reveal value 0 must be a canonical uint64
//
// every ~30s until the commit deadline, signing no commit at all. The cause was
// not chain state: fetchVerificationValues returned the sample-value artifact
// verbatim as ONE record and the retired compact encoder parsed each record with
// strconv.ParseUint, while modelservice.LocalService publishes a JSON
// verificationEnvelope there. modelservice.NewFakeService happens to publish a
// bare decimal, which is why every fake test in this package walked past it.
//
// So the fix is judged by two properties, and both are asserted below:
//
//   - a model service that publishes anything at all at SampleValueSequenceRef
//     still produces a signed commit, because the reveal does not read it; and
//   - the reveal that IS produced is the VerifierResult payload listed in
//     04-task-execution-verification-and-settlement.md §9, re-derivable from the run's own metric material and
//     the two consensus reads.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/revealcontract"
)

// envelopeSampleValueRef is the ref countingModel publishes when it is asked to
// behave like modelservice.LocalService: the sample-value sequence resolves to a
// JSON envelope rather than to a bare decimal.
const envelopeSampleValueRef = "cortex-artifact://fake-model-service/verification-envelope"

// jsonSampleValueEnvelope is the publishing shape modelservice.LocalService
// actually uses. It is deliberately NOT a fixture of that envelope's schema -
// the point is that these bytes are opaque to the verify path, so any
// non-decimal payload must do.
func jsonSampleValueEnvelope(t *testing.T) []byte {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"verdict":     "PASS_SINGLE",
		"raw_verdict": "PASS_SINGLE_STRICT",
		"verifier_id": "local-vllm",
		"values": []map[string]any{
			{"position": 0, "token_id": 41, "present": true, "logprob": -0.0412, "rank": 1},
			{"position": 1, "token_id": 902, "present": true, "logprob": -1.734, "rank": 2},
		},
	})
	if err != nil {
		t.Fatalf("marshal envelope fixture: %v", err)
	}
	return envelope
}

// TestVerifyCommitsWhenTheSampleValueArtifactIsAJSONEnvelope is the regression
// test for the devnet stall. Before this change the same input produced no
// commit at all, permanently.
func TestVerifyCommitsWhenTheSampleValueArtifactIsAJSONEnvelope(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	envelope := jsonSampleValueEnvelope(t)
	h.model.SampleValueEnvelope = envelope
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result, err := h.verifier.HandleOpenVerifyAccepted(ctx, state)
	if err != nil {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want a signed commit over a JSON sample-value artifact", err)
	}
	if !result.Started || result.CommitHash.IsZero() || len(result.ResultReveal) == 0 {
		t.Fatalf("verify produced no commit material: started=%v commit_hash=%x reveal=%dB",
			result.Started, result.CommitHash, len(result.ResultReveal))
	}
	if len(result.CommitWire.ServiceSignature) == 0 {
		t.Fatal("commit wire carries no service signature; the commit was never signed")
	}
	// The artifact is still fetched and still stored as local evidence - the end of §9
	// puts per-token values in the Verifier's own evidence bundle - but it is not an
	// input to the reveal. If it ever becomes one again, this assertion is where a
	// non-decimal payload starts failing the round again.
	if !containsString(h.model.fetchedRefs, envelopeSampleValueRef) {
		t.Fatalf("sample-value ref was never fetched; fetched %v", h.model.fetchedRefs)
	}
	if bytes.Contains(result.ResultReveal, envelope) {
		t.Fatal("the reveal embeds the sample-value envelope; the end of §9 keeps per-token values out of the normal Msg payload")
	}
}

// TestResultRevealIsTheVerifierResultPayload re-derives the reveal from the
// §9 item fields and requires the bytes the commit bound to equal it.
//
// This is the test that would catch a field silently dropped from the payload.
// Nothing else can: the chain never sees these bytes, only
// H_V1("TRUEOPEN_FULL_RESULT_REVEAL_PAYLOAD_V1", ...) over them, so a reveal that
// omitted the salt or the metric root would hash, sign, submit and be accepted -
// and only fail at a challenge-round opening, if one ever happened.
func TestResultRevealIsTheVerifierResultPayload(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result, err := h.verifier.HandleOpenVerifyAccepted(ctx, state)
	if err != nil {
		t.Fatalf("HandleOpenVerifyAccepted error = %v", err)
	}
	metricSummaryHash, err := nodewire.MetricSummaryHash(result.MetricMaterial.Summary)
	if err != nil {
		t.Fatalf("MetricSummaryHash error = %v", err)
	}
	taskIDBytes, err := hex.DecodeString(state.TaskID)
	if err != nil {
		t.Fatalf("task id %q is not canonical hex: %v", state.TaskID, err)
	}
	var taskIDHash codec.Hash
	copy(taskIDHash[:], taskIDBytes)
	facts := servedTaskFacts(state.TaskID)
	want, err := revealcontract.CanonicalVerifierResultPayload(revealcontract.VerifierResultPayloadV2{
		ChainID:                           "chain-A",
		TaskID:                            taskIDHash,
		TaskHash:                          codec.Hash(facts.AcceptedTaskHash),
		VerifyRound:                       uint32(state.VerifyRound),
		VerifierOperatorAddress:           fixtureVerifierAddress,
		InferReceiptHash:                  state.InferReceiptHash,
		VerifierValueRoot:                 result.MetricMaterial.VerifierValueRoot,
		MetricRoot:                        result.MetricMaterial.Root,
		MetricLeafCount:                   uint32(result.MetricMaterial.LeafCount),
		MetricSummaryHash:                 metricSummaryHash,
		AggregateProofHash:                result.MetricMaterial.AggregateProof.Hash,
		ProfileExecutionSnapshotHash:      codec.Hash(facts.ProfileExecutionSnapshotHash),
		GenerationParamsDigest:            codec.Hash(facts.GenerationParamsDigest),
		VerifierEvidenceBundleHash:        evidencebundle.Hash(result.EvidenceManifest),
		VerifierEvidenceManifestSizeBytes: uint64(len(result.EvidenceManifest)),
	})
	if err != nil {
		t.Fatalf("CanonicalVerifierResultPayload error = %v", err)
	}
	if !bytes.Equal(result.ResultReveal, want) {
		t.Fatalf("result reveal = %x\nwant the VerifierResult payload %x", result.ResultReveal, want)
	}
	// The V3 commit binds verifier_value_root and the salt, not the payload.
	wantCommit, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV3{
		ChainID:                 "chain-A",
		TaskID:                  taskIDBytes,
		TaskHash:                facts.AcceptedTaskHash,
		VerifyRound:             uint32(state.VerifyRound),
		VerifierOperatorAddress: fixtureVerifierAddress,
		VerifierValueRoot:       result.MetricMaterial.VerifierValueRoot[:],
		Salt:                    result.Salt[:],
	})
	if err != nil {
		t.Fatalf("ResultCommitmentHash error = %v", err)
	}
	if result.CommitHash != wantCommit {
		t.Fatalf("commit_hash = %x, want the frozen commitment over this reveal %x", result.CommitHash, wantCommit)
	}
}

// TestRevealDiffersPerVerifierBecauseOfTheSalt is the property nexus's
// settlement grouping violates, recorded here as a Cortex invariant rather than
// as a remark. §9 requires the reveal preimage to carry salt, and Cortex's salt
// mixes the verifier address, so two honest verifiers of the same task have
// different result_reveal_hash values by construction. Anything that groups
// verifiers by that hash can never reach a quorum.
func TestPayloadBindsVerifierAndSelectedIndex(t *testing.T) {
	base := revealcontract.VerifierResultPayloadV2{
		ChainID:                           "chain-A",
		TaskID:                            codec.HashWithDomain("TEST_TASK", []byte("t")),
		TaskHash:                          codec.HashWithDomain("TEST_ACCEPTED", []byte("t")),
		VerifyRound:                       1,
		VerifierOperatorAddress:           fixtureVerifierAddress,
		InferReceiptHash:                  codec.HashWithDomain("TEST_RECEIPT", []byte("t")),
		VerifierValueRoot:                 codec.HashWithDomain("TEST_VALUE_ROOT", []byte("t")),
		MetricRoot:                        codec.HashWithDomain("TEST_ROOT", []byte("t")),
		MetricLeafCount:                   8,
		MetricSummaryHash:                 codec.HashWithDomain("TEST_SUMMARY", []byte("t")),
		AggregateProofHash:                codec.HashWithDomain("TEST_PROOF", []byte("t")),
		ProfileExecutionSnapshotHash:      codec.HashBytes([]byte("profile")),
		GenerationParamsDigest:            codec.HashBytes([]byte("generation")),
		VerifierEvidenceBundleHash:        codec.HashBytes([]byte("manifest")),
		VerifierEvidenceManifestSizeBytes: 123,
	}
	other := base
	other.VerifierOperatorAddress = fixtureOtherVerifierAddress
	other.SelectedVerifierIndex = 1

	first, err := revealcontract.CanonicalVerifierResultPayload(base)
	if err != nil {
		t.Fatalf("first reveal error = %v", err)
	}
	second, err := revealcontract.CanonicalVerifierResultPayload(other)
	if err != nil {
		t.Fatalf("second reveal error = %v", err)
	}
	firstHash := nodewire.ResultPayloadHash(first)
	secondHash := nodewire.ResultPayloadHash(second)
	if firstHash == secondHash {
		t.Fatal("two selected verifier identities produced the same result payload hash")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
