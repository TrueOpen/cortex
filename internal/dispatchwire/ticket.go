package dispatchwire

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Named ticket rejections, so callers can map each to a reject code.
var (
	ErrTicketChain           = errors.New("dispatch ticket: wrong chain")
	ErrTicketSignature       = errors.New("dispatch ticket: Builder signature")
	ErrTicketEpoch           = errors.New("dispatch ticket: vrf epoch")
	ErrTicketReferenceHeight = errors.New("dispatch ticket: reference height")
	ErrTicketVRF             = errors.New("dispatch ticket: vrf")
	ErrTicketRoster          = errors.New("dispatch ticket: roster hash")
	ErrTicketRoot            = errors.New("dispatch ticket: handraise root")
	ErrTicketTarget          = errors.New("dispatch ticket: target")
)

// EpochBeacon is the committed beacon at the epoch start, as read from chain
// authority. Verified must come from that authority, never from the ticket.
type EpochBeacon struct {
	Height     uint64
	Randomness []byte // raw R_h, 32 bytes
	Verified   bool
}

// TicketContext is what the node must already know from chain authority and
// from its own records before it may trust a ticket (CD §5.1 check 1).
type TicketContext struct {
	ChainID              string
	SelfOperator         string
	BuilderServicePubKey []byte // QueryCurrentServiceKey(BUILDER, ticket.builder_address)
	BuilderVRFPubKey     []byte // Hub VrfKey for the Builder; 32 bytes
	EpochLengthBlocks    uint64
	EarliestSubmitHeight uint64 // from the SignedOrderV2 in the same offer
	// Beacon is the verified beacon at the epoch start that
	// EarliestSubmitHeight implies; wire's ResolveEpochSeed checks it.
	Beacon          EpochBeacon
	HeldRootDigests map[[32]byte]bool // roots this node holds from this Builder
}

// CheckTicket runs the ticket-legitimacy checks that need no live state:
// Builder signature, epoch/reference height, VRF, root reference and target.
// Rank is deliberately not checked -- the Worker cannot see the roster.
// Deadlines are not checked here either (accept_deadline_ms is the Builder's
// clock; see plan C4).
func CheckTicket(t *taskv1.DispatchTicketV1, c TicketContext) error {
	if t.GetChainId() != c.ChainID {
		return fmt.Errorf("%w: ticket chain_id %q, want %q", ErrTicketChain, t.GetChainId(), c.ChainID)
	}
	if err := VerifyBuilderSigned(t, c.BuilderServicePubKey); err != nil {
		return fmt.Errorf("%w: %w", ErrTicketSignature, err)
	}
	seed, err := dispatch.ResolveEpochSeed(c.EarliestSubmitHeight, c.EpochLengthBlocks,
		c.Beacon.Height, c.Beacon.Randomness, c.Beacon.Verified)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTicketEpoch, err)
	}
	if t.GetVrfEpoch() != seed.Epoch {
		return fmt.Errorf("%w: ticket vrf_epoch %d, order implies %d", ErrTicketEpoch, t.GetVrfEpoch(), seed.Epoch)
	}
	if t.GetReferenceHeight() != seed.ReferenceHeight {
		return fmt.Errorf("%w: ticket reference_height %d, epoch %d starts at %d",
			ErrTicketReferenceHeight, t.GetReferenceHeight(), seed.Epoch, seed.ReferenceHeight)
	}
	if t.GetRandomnessScheme() != taskv1.DispatchRandomnessSchemeV1_DISPATCH_RANDOMNESS_SCHEME_V1_BUILDER_VRF {
		return fmt.Errorf("%w: unsupported randomness scheme %v", ErrTicketVRF, t.GetRandomnessScheme())
	}
	alpha, err := Digest(&taskv1.DispatchVrfInputV1{
		ChainId: c.ChainID, Epoch: seed.Epoch, EpochSeed: seed.Randomness[:],
		SessionId: t.GetSessionId(), OrderSequence: t.GetOrderSequence(),
	})
	if err != nil {
		return fmt.Errorf("%w: alpha: %w", ErrTicketVRF, err)
	}
	if err := dispatch.VerifyDispatchVRF(c.BuilderVRFPubKey, alpha[:], t.GetVrfProof(), t.GetVrfOutput()); err != nil {
		return fmt.Errorf("%w: %w", ErrTicketVRF, err)
	}
	if len(t.GetRosterHash()) != 32 {
		return fmt.Errorf("%w: roster_hash is %d bytes", ErrTicketRoster, len(t.GetRosterHash()))
	}
	if len(t.GetHandraiseRootDigest()) != 32 {
		return fmt.Errorf("%w: handraise_root_digest is %d bytes", ErrTicketRoot, len(t.GetHandraiseRootDigest()))
	}
	var root [32]byte
	copy(root[:], t.GetHandraiseRootDigest())
	if !c.HeldRootDigests[root] {
		return fmt.Errorf("%w: ticket references a handraise root this node does not hold", ErrTicketRoot)
	}
	if t.GetTarget().GetOperatorAddress() != c.SelfOperator {
		return fmt.Errorf("%w: ticket targets %s, not this node", ErrTicketTarget, t.GetTarget().GetOperatorAddress())
	}
	return nil
}
