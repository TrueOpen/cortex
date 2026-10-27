package codec

import (
	"fmt"
	"reflect"
	"strings"
)

// Declarations only tests use, kept out of the production binary.

func ProtocolHash(domain string, input any) (Hash, error) {
	if strings.TrimSpace(domain) == "" {
		return Hash{}, fmt.Errorf("protocol hash domain is required")
	}
	if isMap(input) {
		return Hash{}, fmt.Errorf("protocol hash input must not be map/JSON material")
	}
	field, ok := input.([]byte)
	if !ok {
		return Hash{}, fmt.Errorf("protocol hash input must be canonical []byte, got %T", input)
	}
	return HashWithDomain(domain, field), nil
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

func CanonicalOutputPackageHash(canonicalPackageBytes []byte) Hash {
	return HashBytes(canonicalPackageBytes)
}
func isMap(input any) bool {
	if input == nil {
		return false
	}
	return reflect.TypeOf(input).Kind() == reflect.Map
}
