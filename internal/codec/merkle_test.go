package codec

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMerkleRootV1MatchesTheFrozenSpecVector pins the primitive against the one
// published conformance vector (canonical-encoding-and-domain-hashing §10.4). Everything else in
// this file is a property of the tree; this is the only value that proves the
// framing bytes themselves are right.
func TestMerkleRootV1MatchesTheFrozenSpecVector(t *testing.T) {
	const domain = "TRUEOPEN_TEST_TREE_V1"
	const want = "64e6dfc10cdc303a1d4e3d57530a7e257bf14205b0fd51922f65720573d42524"

	var leaf Hash
	for i := range leaf {
		leaf[i] = 0xaa
	}
	root, err := MerkleRootV1(domain, []Hash{leaf})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if got := hex.EncodeToString(root[:]); got != want {
		t.Fatalf("root = %s, want the frozen §10.4 vector %s", got, want)
	}
}

// A single-leaf tree is the leaf FRAME, not the leaf. Returning the raw leaf
// would make a one-position metric tree indistinguishable from its only leaf
// hash, which is exactly the second-preimage confusion the leaf prefix exists to
// prevent - and it is why the §10.4 vector above is not aa..aa.
func TestSingleLeafRootIsTheFramedLeafNotTheLeaf(t *testing.T) {
	var leaf Hash
	for i := range leaf {
		leaf[i] = 0xaa
	}
	root, err := MerkleRootV1("TRUEOPEN_TEST_TREE_V1", []Hash{leaf})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if root == leaf {
		t.Fatalf("single-leaf root equals the bare leaf hash")
	}
}

func TestEmptyRootIsTheEmptyFrameNotZero(t *testing.T) {
	root, err := MerkleRootV1("TRUEOPEN_TEST_TREE_V1", nil)
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if root.IsZero() {
		t.Fatalf("empty root is 32 zero bytes; §8 rule 5 requires MerkleEmptyV1(domain)")
	}
	same, err := MerkleRootV1("TRUEOPEN_TEST_TREE_V1", []Hash{})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if same != root {
		t.Fatalf("nil and empty leaf lists produced different roots")
	}
}

// §8 rule 3: an odd node is promoted, never duplicated. The two are only
// distinguishable at an odd level, so the check is written against a three-leaf
// tree and compares against the root a duplicating implementation would return.
func TestOddTailIsPromotedNotDuplicated(t *testing.T) {
	const domain = "TRUEOPEN_TEST_TREE_V1"
	leaves := []Hash{fill(1), fill(2), fill(3)}

	root, err := MerkleRootV1(domain, leaves)
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}

	// What "copy the last leaf to pad" would produce.
	duplicating, err := MerkleRootV1(domain, []Hash{fill(1), fill(2), fill(3), fill(3)})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if root == duplicating {
		t.Fatalf("three-leaf root equals the duplicated-tail four-leaf root")
	}
}

func TestLeafOrderIsNotNormalised(t *testing.T) {
	const domain = "TRUEOPEN_TEST_TREE_V1"
	ascending, err := MerkleRootV1(domain, []Hash{fill(1), fill(2)})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	descending, err := MerkleRootV1(domain, []Hash{fill(2), fill(1)})
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if ascending == descending {
		t.Fatalf("the primitive sorted its leaves; §8 rule 1 forbids it")
	}
}

func TestDomainSeparatesOtherwiseIdenticalTrees(t *testing.T) {
	leaves := []Hash{fill(7), fill(8)}
	metric, err := MerkleRootV1("TRUEOPEN_PREFILL_TOKEN_METRIC_ROOT_V1", leaves)
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	other, err := MerkleRootV1("TRUEOPEN_TEST_TREE_V1", leaves)
	if err != nil {
		t.Fatalf("MerkleRootV1 returned error: %v", err)
	}
	if metric == other {
		t.Fatalf("two domains produced the same root for the same leaves")
	}
}

func TestEmptyDomainIsRefused(t *testing.T) {
	if _, err := MerkleRootV1("  ", []Hash{fill(1)}); err == nil {
		t.Fatalf("blank domain was accepted")
	}
}

func TestFromBytesRefusesALeafThatIsNot32Bytes(t *testing.T) {
	_, err := MerkleRootV1FromBytes("TRUEOPEN_TEST_TREE_V1", [][]byte{bytes.Repeat([]byte{1}, 31)})
	if err == nil {
		t.Fatalf("a 31-byte leaf was accepted")
	}
}

func fill(b byte) Hash {
	var out Hash
	for i := range out {
		out[i] = b
	}
	return out
}
