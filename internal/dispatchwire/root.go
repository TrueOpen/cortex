package dispatchwire

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Named inclusion rejections.
var (
	ErrInclusionChain     = errors.New("handraise inclusion: wrong chain")
	ErrInclusionBuilder   = errors.New("handraise inclusion: wrong Builder")
	ErrInclusionMalformed = errors.New("handraise inclusion: malformed proof")
	ErrInclusionProof     = errors.New("handraise inclusion: path does not reach the signed root")
)

// InclusionContext identifies the Builder a root notice arrived from. All of
// it comes from the stream's authenticated peer and chain authority, never
// from the notice itself.
type InclusionContext struct {
	ChainID         string
	BuilderOperator string // the stream's authenticated Builder operator
	BuilderPubKey   []byte // its current service key, resolved from chain
}

// Inclusion is what a verified HandraiseRootNoticeV1 tells this node.
type Inclusion struct {
	RootDigest     [32]byte // handraise_root_digest, what tickets reference
	StandingDigest [32]byte
	Admitted       bool
	Reason         taskv1.AdmitRejectReasonV1
	RTTMillis      uint64
}

// VerifyInclusion checks that the root and the carried standing handraise
// both belong to the stream's Builder and chain, checks the Builder signature
// on the root, recomputes this node's leaf and walks the path. The caller must
// also check that proof.leaf.handraise is a handraise this node signed for
// this Builder (digest equality with its send log).
func VerifyInclusion(root *taskv1.SignedHandraiseRootV1, proof *taskv1.HandraiseInclusionProofV1, c InclusionContext) (Inclusion, error) {
	if root.GetChainId() != c.ChainID {
		return Inclusion{}, fmt.Errorf("%w: root chain_id %q, want %q", ErrInclusionChain, root.GetChainId(), c.ChainID)
	}
	if root.GetBuilderAddress() != c.BuilderOperator {
		return Inclusion{}, fmt.Errorf("%w: root signed for %s, stream Builder is %s", ErrInclusionBuilder, root.GetBuilderAddress(), c.BuilderOperator)
	}
	if err := VerifyBuilderSigned(root, c.BuilderPubKey); err != nil {
		return Inclusion{}, err
	}
	leaf := proof.GetLeaf()
	handraise := leaf.GetHandraise()
	if handraise == nil {
		return Inclusion{}, fmt.Errorf("%w: no standing handraise", ErrInclusionMalformed)
	}
	if handraise.GetChainId() != c.ChainID {
		return Inclusion{}, fmt.Errorf("%w: handraise chain_id %q, want %q", ErrInclusionChain, handraise.GetChainId(), c.ChainID)
	}
	if handraise.GetBuilderAddress() != c.BuilderOperator {
		return Inclusion{}, fmt.Errorf("%w: handraise is for %s, stream Builder is %s", ErrInclusionBuilder, handraise.GetBuilderAddress(), c.BuilderOperator)
	}
	standing, err := Digest(handraise)
	if err != nil {
		return Inclusion{}, fmt.Errorf("%w: %w", ErrInclusionMalformed, err)
	}
	leafDigest, err := dispatch.HandraiseLeafDigest(standing, leaf.GetAdmitted(), uint32(leaf.GetAdmitRejectReason()), leaf.GetBuilderMeasuredRttMs())
	if err != nil {
		return Inclusion{}, fmt.Errorf("%w: %w", ErrInclusionMalformed, err)
	}
	siblings := make([][32]byte, len(proof.GetSiblings()))
	for i, s := range proof.GetSiblings() {
		if len(s) != 32 {
			return Inclusion{}, fmt.Errorf("%w: sibling %d is %d bytes", ErrInclusionMalformed, i, len(s))
		}
		copy(siblings[i][:], s)
	}
	// root is exactly 32 bytes: wire's signing projection (checked above)
	// requires raw32 for it.
	var r [32]byte
	copy(r[:], root.GetRoot())
	if !dispatch.VerifyHandraiseProof(r, leafDigest, proof.GetLeafIndex(), root.GetLeafCount(), siblings) {
		return Inclusion{}, ErrInclusionProof
	}
	rootDigest, err := Digest(root)
	if err != nil {
		return Inclusion{}, err
	}
	return Inclusion{RootDigest: rootDigest, StandingDigest: standing, Admitted: leaf.GetAdmitted(),
		Reason: leaf.GetAdmitRejectReason(), RTTMillis: leaf.GetBuilderMeasuredRttMs()}, nil
}
