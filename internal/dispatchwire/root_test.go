package dispatchwire

import (
	"context"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/wirevectors"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

type merkleCase struct {
	Name      string   `json:"name"`
	Standing  []string `json:"standing_digests_hex"`
	LeavesHex []string `json:"leaf_digests_hex"`
	RootHex   string   `json:"root_hex"`
	Proofs    []struct {
		LeafIndex   uint32   `json:"leaf_index"`
		SiblingsHex []string `json:"siblings_hex"`
	} `json:"proofs"`
}

type handraiseMerkle struct {
	Leaves [][32]byte
	Root   [32]byte
	Proofs [][][32]byte
}

func to32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("%s is %d bytes", s, len(b))
	}
	copy(out[:], b)
	return out
}

// loadHandraiseMerkle reads handraise_merkle.cases[name] from the fixture.
func loadHandraiseMerkle(t *testing.T, name string) handraiseMerkle {
	t.Helper()
	var section struct {
		Cases []merkleCase `json:"cases"`
	}
	if err := wirevectors.DispatchSection("handraise_merkle", &section); err != nil {
		t.Fatal(err)
	}
	for _, c := range section.Cases {
		if c.Name != name {
			continue
		}
		var m handraiseMerkle
		m.Root = to32(t, c.RootHex)
		for i, l := range c.LeavesHex {
			m.Leaves = append(m.Leaves, to32(t, l))
			if c.Proofs[i].LeafIndex != uint32(i) {
				t.Fatalf("%s proof %d is for leaf %d", name, i, c.Proofs[i].LeafIndex)
			}
			var sib [][32]byte
			for _, s := range c.Proofs[i].SiblingsHex {
				sib = append(sib, to32(t, s))
			}
			m.Proofs = append(m.Proofs, sib)
		}
		return m
	}
	t.Fatalf("handraise_merkle case %s missing", name)
	return handraiseMerkle{}
}

func TestVerifyInclusionAgainstWireMerkleVector(t *testing.T) {
	m := loadHandraiseMerkle(t, "odd_three")
	if len(m.Leaves) != 3 {
		t.Fatalf("odd_three has %d leaves", len(m.Leaves))
	}
	for i, leaf := range m.Leaves {
		if !VerifyLeafPath(m.Root, leaf, uint32(i), uint32(len(m.Leaves)), m.Proofs[i]) {
			t.Fatalf("leaf %d does not verify", i)
		}
		if VerifyLeafPath(m.Root, leaf, uint32((i+1)%len(m.Leaves)), uint32(len(m.Leaves)), m.Proofs[i]) {
			t.Fatalf("leaf %d verifies at the wrong index", i)
		}
	}
}

// The published signed root (single leaf) over the published standing
// handraise, admitted, verifies end to end under the published Builder key.
func TestVerifyInclusionPublishedSignedRoot(t *testing.T) {
	rootRow := vectorByName(t, "task_v1_signedhandraiserootv1")
	root := vectorMessage(t, rootRow).(*taskv1.SignedHandraiseRootV1)
	standing := vectorMessage(t, vectorByName(t, "task_v1_standinghandraisev1")).(*taskv1.StandingHandraiseV1)
	proof := &taskv1.HandraiseInclusionProofV1{
		Leaf: &taskv1.HandraiseRootLeafV1{Handraise: standing, Admitted: true,
			AdmitRejectReason: taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE},
		LeafIndex: 0,
	}
	inc, err := VerifyInclusion(root, proof, mustHex(t, rootRow.PublicKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	if !inc.Admitted || inc.RootDigest != to32(t, rootRow.DigestHex) {
		t.Fatalf("inclusion = %+v", inc)
	}
	if inc.StandingDigest != to32(t, vectorByName(t, "task_v1_standinghandraisev1").DigestHex) {
		t.Fatal("standing digest differs from the published vector")
	}
	// The ticket vector references exactly this root digest.
	ticket := vectorMessage(t, vectorByName(t, "task_v1_dispatchticketv1")).(*taskv1.DispatchTicketV1)
	if [32]byte(ticket.HandraiseRootDigest) != inc.RootDigest {
		t.Fatal("ticket handraise_root_digest is not Digest(signed root)")
	}
}

func TestVerifyInclusionSelfBuiltRoot(t *testing.T) {
	const builderKey = "2222222222222222222222222222222222222222222222222222222222222222"
	base := vectorMessage(t, vectorByName(t, "task_v1_standinghandraisev1")).(*taskv1.StandingHandraiseV1)
	leaves := make([]*taskv1.HandraiseRootLeafV1, 3)
	digests := make([][32]byte, 3)
	for i := range leaves {
		h := proto.Clone(base).(*taskv1.StandingHandraiseV1)
		h.HandraiseNonce = uint64(10 + i)
		leaves[i] = &taskv1.HandraiseRootLeafV1{Handraise: h, Admitted: true,
			AdmitRejectReason: taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE}
	}
	// Leaf 1 is refused for RTT, which must carry the measured RTT.
	leaves[1].Admitted = false
	leaves[1].AdmitRejectReason = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD
	leaves[1].BuilderMeasuredRttMs = 420
	for i, l := range leaves {
		sd, err := Digest(l.Handraise)
		if err != nil {
			t.Fatal(err)
		}
		digests[i], err = dispatch.HandraiseLeafDigest(sd, l.Admitted, uint32(l.AdmitRejectReason), l.BuilderMeasuredRttMs)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := dispatch.HandraiseRoot(digests)
	root := &taskv1.SignedHandraiseRootV1{ChainId: base.ChainId, BuilderAddress: base.BuilderAddress,
		RootHeight: 7, RootVersion: 1, LeafCount: 3, Root: r[:]}
	// The Builder signs with the same digest-to-raw64 path Cortex uses.
	d, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	if root.BuilderServiceSignature, err = localSigner(builderKey)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	pub := pubKey(t, builderKey)
	for i := range leaves {
		sib, err := dispatch.HandraiseProof(digests, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		proof := &taskv1.HandraiseInclusionProofV1{Leaf: leaves[i], LeafIndex: uint32(i)}
		for _, s := range sib {
			proof.Siblings = append(proof.Siblings, append([]byte(nil), s[:]...))
		}
		inc, err := VerifyInclusion(root, proof, pub)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		if inc.Admitted != leaves[i].Admitted || inc.RTTMillis != leaves[i].BuilderMeasuredRttMs || inc.Reason != leaves[i].AdmitRejectReason {
			t.Fatalf("leaf %d: inclusion %+v", i, inc)
		}
		if inc.RootDigest != d {
			t.Fatalf("leaf %d: root digest", i)
		}

		flipped := proto.Clone(proof).(*taskv1.HandraiseInclusionProofV1)
		flipped.Leaf.Admitted = !flipped.Leaf.Admitted
		if _, err := VerifyInclusion(root, flipped, pub); err == nil {
			t.Fatalf("leaf %d: flipped admission verified", i)
		}
		// Admitted->refused with a consistent reason is a well-formed leaf that
		// must still miss the signed root.
		relabelled := proto.Clone(proof).(*taskv1.HandraiseInclusionProofV1)
		if relabelled.Leaf.Admitted {
			relabelled.Leaf.Admitted = false
			relabelled.Leaf.AdmitRejectReason = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE
		} else {
			relabelled.Leaf.Admitted = true
			relabelled.Leaf.AdmitRejectReason = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE
			relabelled.Leaf.BuilderMeasuredRttMs = 0
		}
		if _, err := VerifyInclusion(root, relabelled, pub); err == nil {
			t.Fatalf("leaf %d: relabelled admission verified", i)
		}
		wrongIndex := proto.Clone(proof).(*taskv1.HandraiseInclusionProofV1)
		wrongIndex.LeafIndex = uint32((i + 1) % 3)
		if _, err := VerifyInclusion(root, wrongIndex, pub); err == nil {
			t.Fatalf("leaf %d: wrong index verified", i)
		}
		if _, err := VerifyInclusion(root, proof, pubKey(t, fixtureKeyHex)); err == nil {
			t.Fatalf("leaf %d: root verified under another Builder key", i)
		}
	}
}
