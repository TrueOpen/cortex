package dispatchwire

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// VerifyLeafPath is wire's handraise Merkle path check.
func VerifyLeafPath(root, leaf [32]byte, index, count uint32, siblings [][32]byte) bool {
	return dispatch.VerifyHandraiseProof(root, leaf, index, count, siblings)
}

// Inclusion is what a verified HandraiseRootNoticeV1 tells this node.
type Inclusion struct {
	RootDigest     [32]byte // handraise_root_digest, what tickets reference
	StandingDigest [32]byte
	Admitted       bool
	Reason         taskv1.AdmitRejectReasonV1
	RTTMillis      uint64
}

// VerifyInclusion checks the Builder signature on the root, recomputes this
// node's leaf from the standing handraise it carries, and walks the path. The
// caller must also check that proof.leaf.handraise is a handraise this node
// signed for this Builder (digest equality with its send log).
func VerifyInclusion(root *taskv1.SignedHandraiseRootV1, proof *taskv1.HandraiseInclusionProofV1, builderPubKey []byte) (Inclusion, error) {
	if err := VerifyBuilderSigned(root, builderPubKey); err != nil {
		return Inclusion{}, err
	}
	leaf := proof.GetLeaf()
	if leaf.GetHandraise() == nil {
		return Inclusion{}, fmt.Errorf("handraise inclusion proof carries no standing handraise")
	}
	standing, err := Digest(leaf.GetHandraise())
	if err != nil {
		return Inclusion{}, err
	}
	leafDigest, err := dispatch.HandraiseLeafDigest(standing, leaf.GetAdmitted(), uint32(leaf.GetAdmitRejectReason()), leaf.GetBuilderMeasuredRttMs())
	if err != nil {
		return Inclusion{}, fmt.Errorf("handraise leaf: %w", err)
	}
	siblings := make([][32]byte, len(proof.GetSiblings()))
	for i, s := range proof.GetSiblings() {
		if len(s) != 32 {
			return Inclusion{}, fmt.Errorf("sibling %d is %d bytes", i, len(s))
		}
		copy(siblings[i][:], s)
	}
	if len(root.GetRoot()) != 32 {
		return Inclusion{}, fmt.Errorf("root is %d bytes", len(root.GetRoot()))
	}
	var r [32]byte
	copy(r[:], root.GetRoot())
	if !dispatch.VerifyHandraiseProof(r, leafDigest, proof.GetLeafIndex(), root.GetLeafCount(), siblings) {
		return Inclusion{}, fmt.Errorf("handraise inclusion proof does not reach the signed root")
	}
	rootDigest, err := Digest(root)
	if err != nil {
		return Inclusion{}, err
	}
	return Inclusion{RootDigest: rootDigest, StandingDigest: standing, Admitted: leaf.GetAdmitted(),
		Reason: leaf.GetAdmitRejectReason(), RTTMillis: leaf.GetBuilderMeasuredRttMs()}, nil
}
