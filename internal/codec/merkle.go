package codec

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// MERKLE_ROOT_V1 framing constants. They are the frozen ASCII prefixes from
// canonical-encoding-and-domain-hashing §8 and are NOT business domains: the business domain is
// the caller's, and it is length-framed after the prefix.
const (
	merkleLeafPrefixV1  = "TRUEOPEN_MERKLE_LEAF_V1"
	merkleNodePrefixV1  = "TRUEOPEN_MERKLE_NODE_V1"
	merkleEmptyPrefixV1 = "TRUEOPEN_MERKLE_EMPTY_V1"
)

// ErrMerkleDomainRequired is returned when a caller asks for a root under no
// domain. The domain is the only thing separating two trees built from the same
// leaves, so an empty one is refused rather than framed as zero bytes.
var ErrMerkleDomainRequired = errors.New("merkle root domain is required")

// MerkleRootV1 implements the frozen MERKLE_ROOT_V1 tree of
// canonical-encoding-and-domain-hashing §8 over an already-ordered set of 32-byte leaf hashes.
//
// The five rules that make this primitive interoperable, all of which a
// plausible-looking implementation gets wrong:
//
//  1. leaf, internal node and empty root each carry their own ASCII framing
//     prefix, and the business domain is length-framed (u32_be) inside each of
//     them. Dropping the prefix on internal nodes lets a leaf hash be presented
//     as an internal node.
//  2. leaves are neither sorted nor deduplicated here. Their order is the
//     business protocol's - for the metric tree it is output_position ascending,
//     defined once in 05-verification-algorithm §7 - and re-sorting would silently accept a
//     caller that shuffled them.
//  3. adjacent nodes pair left-to-right; an odd node at the end of a level is
//     promoted unchanged. It is NOT duplicated, and the level is NOT padded to a
//     power of two with zero hashes.
//  4. the empty root is MerkleEmptyV1(domain), not 32 zero bytes.
//  5. every leaf must be exactly 32 bytes.
//
// The signature takes Hash rather than [][]byte precisely so rule 5 cannot be
// violated by a caller.
func MerkleRootV1(domain string, leaves []Hash) (Hash, error) {
	if strings.TrimSpace(domain) == "" {
		return Hash{}, ErrMerkleDomainRequired
	}
	if len(leaves) == 0 {
		return merkleEmptyV1(domain), nil
	}
	level := make([]Hash, len(leaves))
	for i := range leaves {
		level[i] = merkleLeafV1(domain, leaves[i])
	}
	for len(level) > 1 {
		next := make([]Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd tail: promoted as-is. Duplicating it here is the classic
				// variant §8 rule 4 names and forbids, and it changes the root.
				next = append(next, level[i])
				continue
			}
			next = append(next, merkleNodeV1(domain, level[i], level[i+1]))
		}
		level = next
	}
	return level[0], nil
}

// MerkleRootV1FromBytes is MerkleRootV1 for callers holding raw leaf bytes. It
// enforces the 32-byte leaf rule rather than truncating or padding, because a
// leaf of any other width has no encoding in this tree at all.
func MerkleRootV1FromBytes(domain string, leaves [][]byte) (Hash, error) {
	converted := make([]Hash, len(leaves))
	for i, leaf := range leaves {
		if len(leaf) != len(Hash{}) {
			return Hash{}, fmt.Errorf("merkle leaf %d is %d bytes, want exactly 32", i, len(leaf))
		}
		copy(converted[i][:], leaf)
	}
	return MerkleRootV1(domain, converted)
}

func merkleLeafV1(domain string, leaf Hash) Hash {
	digest := sha256.New()
	digest.Write([]byte(merkleLeafPrefixV1))
	writeMerkleDomain(digest, domain)
	digest.Write(leaf[:])
	return sumHash(digest)
}

func merkleNodeV1(domain string, left, right Hash) Hash {
	digest := sha256.New()
	digest.Write([]byte(merkleNodePrefixV1))
	writeMerkleDomain(digest, domain)
	digest.Write(left[:])
	digest.Write(right[:])
	return sumHash(digest)
}

func merkleEmptyV1(domain string) Hash {
	digest := sha256.New()
	digest.Write([]byte(merkleEmptyPrefixV1))
	writeMerkleDomain(digest, domain)
	return sumHash(digest)
}

// writeMerkleDomain frames the business domain with a u32_be length. Note this
// is u32, unlike the u64 frames of H_FIELDS_V1 and the payload frame of H_V1 -
// the three schemes are not interchangeable.
func writeMerkleDomain(digest interface{ Write([]byte) (int, error) }, domain string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(domain)))
	digest.Write(length[:])
	digest.Write([]byte(domain))
}

func sumHash(digest interface{ Sum([]byte) []byte }) Hash {
	var out Hash
	copy(out[:], digest.Sum(nil))
	return out
}
