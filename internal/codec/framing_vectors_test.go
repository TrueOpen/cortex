package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// framingFixture is the H_V1 and MERKLE_ROOT_V1 part of wire's
// shared/framing_v1.json.
type framingFixture struct {
	MerkleFraming struct {
		LeafPrefix  string `json:"leaf_prefix"`
		NodePrefix  string `json:"node_prefix"`
		EmptyPrefix string `json:"empty_prefix"`
	} `json:"merkle_framing"`
	HV1 []struct {
		Name    string `json:"name"`
		Domain  string `json:"domain"`
		Payload struct {
			Type  string `json:"type"`
			Hex   string `json:"hex"`
			Count int    `json:"count"`
		} `json:"payload"`
		HashHex string `json:"hash_hex"`
	} `json:"h_v1"`
	MerkleRoots []struct {
		Name      string   `json:"name"`
		Domain    string   `json:"domain"`
		LeavesHex []string `json:"leaves_hex"`
		RootHex   string   `json:"root_hex"`
	} `json:"merkle_root_v1"`
	MerkleStructural []struct {
		Name           string `json:"name"`
		Kind           string `json:"kind"`
		Vector         string `json:"vector"`
		LeftVector     string `json:"left_vector"`
		RightLeafIndex int    `json:"right_leaf_index"`
	} `json:"merkle_structural_checks"`
	MerkleRejects []struct {
		Name      string   `json:"name"`
		Domain    string   `json:"domain"`
		LeavesHex []string `json:"leaves_hex"`
	} `json:"merkle_rejects"`
}

func loadFramingFixture(t *testing.T) framingFixture {
	t.Helper()
	raw, err := wirevectors.File("shared/framing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture framingFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.HV1) == 0 || len(fixture.MerkleRoots) == 0 || len(fixture.MerkleRejects) == 0 {
		t.Fatal("framing fixture is missing h_v1 or merkle vectors")
	}
	return fixture
}

func decodeHexT(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

// TestHashV1FramingVectors recomputes every published H_V1 hash, including
// the 64 KiB+1 and 1 MiB payloads, with HashV1.
func TestHashV1FramingVectors(t *testing.T) {
	for _, vector := range loadFramingFixture(t).HV1 {
		payload := decodeHexT(t, vector.Payload.Hex)
		switch vector.Payload.Type {
		case "bytes":
		case "repeat":
			payload = bytes.Repeat(payload, vector.Payload.Count)
		default:
			t.Fatalf("%s: unknown payload type %q", vector.Name, vector.Payload.Type)
		}
		if got := HashV1(vector.Domain, payload); got.String() != vector.HashHex {
			t.Errorf("%s: H_V1 = %s, want %s", vector.Name, got, vector.HashHex)
		}
	}
}

// TestMerkleRootFramingVectors recomputes every published MERKLE_ROOT_V1 root,
// checks the published structural relations and prefixes, and requires every
// published reject to be refused.
func TestMerkleRootFramingVectors(t *testing.T) {
	fixture := loadFramingFixture(t)
	if fixture.MerkleFraming.LeafPrefix != merkleLeafPrefixV1 || fixture.MerkleFraming.NodePrefix != merkleNodePrefixV1 ||
		fixture.MerkleFraming.EmptyPrefix != merkleEmptyPrefixV1 {
		t.Fatalf("merkle prefixes = %+v", fixture.MerkleFraming)
	}
	leavesOf := func(hexLeaves []string) [][]byte {
		leaves := make([][]byte, len(hexLeaves))
		for index, leaf := range hexLeaves {
			leaves[index] = decodeHexT(t, leaf)
		}
		return leaves
	}
	roots := map[string]Hash{}
	leaves := map[string][][]byte{}
	domains := map[string]string{}
	for _, vector := range fixture.MerkleRoots {
		root, err := MerkleRootV1FromBytes(vector.Domain, leavesOf(vector.LeavesHex))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if root.String() != vector.RootHex {
			t.Errorf("%s: root = %s, want %s", vector.Name, root, vector.RootHex)
		}
		roots[vector.Name], leaves[vector.Name], domains[vector.Name] = root, leavesOf(vector.LeavesHex), vector.Domain
	}
	for _, check := range fixture.MerkleStructural {
		root, domain := roots[check.Vector], domains[check.Vector]
		var want Hash
		switch check.Kind {
		case "empty_root_is_empty_prefix_hash":
			want = merkleEmptyV1(domain)
		case "root_equals_leaf_hash":
			var leaf Hash
			copy(leaf[:], leaves[check.Vector][0])
			want = merkleLeafV1(domain, leaf)
		case "node_of_root_and_leaf":
			var leaf Hash
			copy(leaf[:], leaves[check.Vector][check.RightLeafIndex])
			want = merkleNodeV1(domain, roots[check.LeftVector], merkleLeafV1(domain, leaf))
		default:
			t.Fatalf("%s: unknown structural check %q", check.Name, check.Kind)
		}
		if root != want {
			t.Errorf("%s: root %s does not satisfy %s", check.Name, root, check.Kind)
		}
	}
	for _, reject := range fixture.MerkleRejects {
		_, err := MerkleRootV1FromBytes(reject.Domain, leavesOf(reject.LeavesHex))
		if err == nil {
			t.Errorf("%s was accepted", reject.Name)
		}
		if reject.Domain == "" && !errors.Is(err, ErrMerkleDomainRequired) {
			t.Errorf("%s: %v, want ErrMerkleDomainRequired", reject.Name, err)
		}
	}
}
