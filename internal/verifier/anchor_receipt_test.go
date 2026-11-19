package verifier

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// anchorLockedProfile is fixtureLockedProfile additionally requiring the
// ADR-0040 WORKER_ANCHOR_OPENING (kind 5), with its evidence_schema_hash
// re-derived.
func anchorLockedProfile(t *testing.T) chainclient.CurrentModelProfileSnapshot {
	t.Helper()
	profile := fixtureLockedProfile()
	schema := &profile.Profile.VerificationProfile.EvidenceSchema
	schema.RequiredInferEvidence = append(schema.RequiredInferEvidence, chainclient.CurrentInferEvidenceRequirementSnapshot{
		EvidenceKind:            int32(nodewire.EvidenceKindWorkerAnchorOpening),
		CommitmentSchemaVersion: nodewire.WorkerAnchorCommitmentSchemaVersionV1,
		MaxEncodedSizeBytes:     chainclient.Uint64String(1 << 20),
	})
	return profileWithHash(t, profile)
}

// A receipt carrying the third (anchor) commitment goes through both PREFILL
// phases exactly like a two-commitment one. The Verifier re-establishes only
// the value and token commitments and never sees the anchor bytes: anchors are
// judged by chain validators.
func TestVerifierScoresAThreeCommitmentReceiptWithoutTheAnchorBundle(t *testing.T) {
	h := newHarness(t)
	profile := anchorLockedProfile(t)
	h.verifier.cfg.ProfileReader = &fixtureProfileReader{profile: profile}
	state, values := confirmedTaskWithValuesUnder(t, h, profile, []byte(`{"request_id":"cmpl-anchor","roots":[]}`))
	if n := len(state.ConfirmedInferReceipt.RequiredEvidenceCommitments); n != 3 {
		t.Fatalf("receipt carries %d commitments, want 3", n)
	}
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
		t.Fatalf("commit half refused a three-commitment receipt: %v", err)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("model verify calls = %d, want 1", h.model.VerifyCalls)
	}
	reveal := state
	reveal.ConfirmedWorkerValues = values
	result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), reveal)
	if err != nil || !result.Signed {
		t.Fatalf("reveal of a three-commitment receipt = %+v, %v", result, err)
	}
}

// The anchor commitment is still bounded by the locked Profile like the other
// two: a receipt whose anchor element exceeds the bound is refused before the
// prefill.
func TestVerifierRefusesAnAnchorCommitmentAboveTheProfileBound(t *testing.T) {
	h := newHarness(t)
	profile := fixtureLockedProfile()
	schema := &profile.Profile.VerificationProfile.EvidenceSchema
	schema.RequiredInferEvidence = append(schema.RequiredInferEvidence, chainclient.CurrentInferEvidenceRequirementSnapshot{
		EvidenceKind:            int32(nodewire.EvidenceKindWorkerAnchorOpening),
		CommitmentSchemaVersion: nodewire.WorkerAnchorCommitmentSchemaVersionV1,
		MaxEncodedSizeBytes:     chainclient.Uint64String(4),
	})
	profile = profileWithHash(t, profile)
	h.verifier.cfg.ProfileReader = &fixtureProfileReader{profile: profile}
	state, _ := confirmedTaskWithValuesUnder(t, h, profile, []byte(`{"request_id":"cmpl-anchor","roots":[]}`))
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err == nil {
		t.Fatal("an anchor commitment above the Profile bound was accepted")
	}
	if h.model.VerifyCalls != 0 {
		t.Fatalf("model verify calls = %d, want the refusal before any prefill", h.model.VerifyCalls)
	}
}
