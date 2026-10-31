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
	ErrTicketBuilder         = errors.New("dispatch ticket: not the stream's Builder")
	ErrTicketSignature       = errors.New("dispatch ticket: Builder signature")
	ErrTicketEpoch           = errors.New("dispatch ticket: vrf epoch")
	ErrTicketReferenceHeight = errors.New("dispatch ticket: reference height")
	ErrTicketVRF             = errors.New("dispatch ticket: vrf")
	ErrTicketRoot            = errors.New("dispatch ticket: handraise root")
	ErrTicketTarget          = errors.New("dispatch ticket: target")
)

// EpochBeacon is the committed beacon at an epoch start. Its fields are
// unexported so a verified beacon can only be made by NewVerifiedBeacon; the
// zero value is unverified and fails closed.
type EpochBeacon struct {
	height     uint64
	randomness []byte // raw R_h, 32 bytes
	verified   bool
}

// NewVerifiedBeacon records a beacon read from chain authority as committed
// and verified. Only the chain-authority path may call it; never construct a
// beacon from a ticket, an offer or a peer's assertion.
func NewVerifiedBeacon(height uint64, randomness []byte) EpochBeacon {
	return EpochBeacon{height: height, randomness: append([]byte(nil), randomness...), verified: true}
}

// TicketContext is what the node must already know before it may trust a
// ticket. Every field comes from the stream's authenticated Builder, chain
// authority or this node's own records -- never from the ticket itself.
type TicketContext struct {
	ChainID string
	// BuilderOperator is the operator the stream peer authenticated as; the
	// ticket must name it.
	BuilderOperator      string
	SelfOperator         string
	BuilderServicePubKey []byte // current service key of BuilderOperator, from chain
	BuilderVRFPubKey     []byte // Hub VrfKey of BuilderOperator; 32 bytes
	EpochLengthBlocks    uint64
	EarliestSubmitHeight uint64 // from the SignedOrderV2 in the same offer
	// Beacon is the verified beacon at the epoch start that
	// EarliestSubmitHeight implies; wire's ResolveEpochSeed checks it.
	Beacon          EpochBeacon
	HeldRootDigests map[[32]byte]bool // roots this node holds from BuilderOperator
}

// CheckTicket runs the ticket-legitimacy checks that need no live state:
// chain and Builder identity, Builder signature, root reference, target,
// epoch/reference height and VRF.
// Rank is deliberately not checked -- the Worker cannot see the roster.
// Deadlines are not checked either: accept_deadline_ms is on the Builder's
// clock, so it is never a protocol judgment for this node.
func CheckTicket(t *taskv1.DispatchTicketV1, c TicketContext) error {
	if t.GetChainId() != c.ChainID {
		return fmt.Errorf("%w: ticket chain_id %q, want %q", ErrTicketChain, t.GetChainId(), c.ChainID)
	}
	if t.GetBuilderAddress() != c.BuilderOperator {
		return fmt.Errorf("%w: ticket names %s, stream Builder is %s", ErrTicketBuilder, t.GetBuilderAddress(), c.BuilderOperator)
	}
	if err := VerifyBuilderSigned(t, c.BuilderServicePubKey); err != nil {
		return fmt.Errorf("%w: %w", ErrTicketSignature, err)
	}
	// roster_hash and handraise_root_digest are exactly 32 bytes here: wire's
	// signing projection, checked by the signature above, requires raw32.
	var root [32]byte
	copy(root[:], t.GetHandraiseRootDigest())
	if !c.HeldRootDigests[root] {
		return fmt.Errorf("%w: ticket references a handraise root this node does not hold", ErrTicketRoot)
	}
	if t.GetTarget().GetOperatorAddress() != c.SelfOperator {
		return fmt.Errorf("%w: ticket targets %s, not this node", ErrTicketTarget, t.GetTarget().GetOperatorAddress())
	}
	seed, err := dispatch.ResolveEpochSeed(c.EarliestSubmitHeight, c.EpochLengthBlocks,
		c.Beacon.height, c.Beacon.randomness, c.Beacon.verified)
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
	return nil
}
