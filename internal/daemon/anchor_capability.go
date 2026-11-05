package daemon

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// ADR-0040 capability gate. A Profile whose locked evidence schema requires
// WORKER_ANCHOR_OPENING (kind 5) can only be served by an engine with the
// anchor sidecar: without it the Worker would generate, fail to commit the
// anchor, and be slashed at the infer deadline. So the standing handraise
// leaves such a Profile out, and the Dispatcher refuses its offers, unless the
// local engine answers GET /slp/info. Profiles without kind 5 are never
// affected and never probe.

// AnchorProberOf returns the model service's anchor capability probe, or nil
// when the model service cannot serve anchor commitments at all (the cortex.v1
// gRPC client, the fakes).
func AnchorProberOf(model modelservice.Client) modelservice.AnchorCommitProber {
	if p, ok := model.(modelservice.AnchorCommitProber); ok {
		return p
	}
	return nil
}

// profileRequiresAnchorOpening reports whether the locked Profile's evidence
// schema lists WORKER_ANCHOR_OPENING.
func profileRequiresAnchorOpening(profile chainclient.CurrentModelProfileSnapshot) bool {
	for _, requirement := range profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence {
		if nodewire.EvidenceKind(requirement.EvidenceKind) == nodewire.EvidenceKindWorkerAnchorOpening {
			return true
		}
	}
	return false
}

// anchorCapabilityProblem is nil when this node can serve the Profile's
// evidence: always for a Profile without kind 5, and for one with kind 5 only
// when probe reports a capable engine. probe caches its verdict, so this may be
// called on every handraise pass and every offer.
func anchorCapabilityProblem(ctx context.Context, probe modelservice.AnchorCommitProber, profile chainclient.CurrentModelProfileSnapshot) error {
	if !profileRequiresAnchorOpening(profile) {
		return nil
	}
	if probe == nil {
		return fmt.Errorf("profile requires WORKER_ANCHOR_OPENING but this node's model service cannot serve anchor commitments")
	}
	if err := probe.AnchorCommitCapable(ctx); err != nil {
		return fmt.Errorf("profile requires WORKER_ANCHOR_OPENING but the local engine does not serve anchor commitments: %w", err)
	}
	return nil
}
