package codec

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func TestMMRPublishedPrimitive(t *testing.T) {
	raw, err := wirevectors.File("shared/mmr_primitive_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Domain    string   `json:"domain"`
		Leaves    []string `json:"leaves_utf8"`
		Preimages []struct {
			Preimage string `json:"preimage_hex"`
			Digest   string `json:"digest_hex"`
		} `json:"framing_preimages"`
		Cases []struct {
			Count int    `json:"leaf_count"`
			Root  string `json:"root_hex"`
			Peaks []struct {
				Height uint8  `json:"height"`
				Hash   string `json:"hash_hex"`
			} `json:"peaks"`
		} `json:"cases"`
		Negative []struct {
			Name  string `json:"name"`
			Count int    `json:"leaf_count"`
			Root  string `json:"root_hex"`
		} `json:"negative"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		mmr, err := NewMMR(fixture.Domain)
		if err != nil {
			t.Fatal(err)
		}
		for _, leaf := range fixture.Leaves[:tc.Count] {
			if err := mmr.Append([]byte(leaf)); err != nil {
				t.Fatal(err)
			}
		}
		if mmr.Root().String() != tc.Root || mmr.LeafCount() != uint64(tc.Count) {
			t.Fatalf("%d leaves: root %s, want %s", tc.Count, mmr.Root(), tc.Root)
		}
		if len(mmr.peaks) != len(tc.Peaks) {
			t.Fatalf("%d leaves: incorrect peak count", tc.Count)
		}
		for i, peak := range tc.Peaks {
			if mmr.peaks[i].height != peak.Height || mmr.peaks[i].hash.String() != peak.Hash {
				t.Fatalf("%d leaves: peak %d differs from published shape/hash", tc.Count, i)
			}
		}
	}
	for _, tc := range fixture.Negative {
		leaves := make([][]byte, tc.Count)
		for i := range leaves {
			leaves[i] = []byte(fixture.Leaves[i])
		}
		root, err := MMRRoot(fixture.Domain, leaves)
		if err != nil || root.String() == tc.Root {
			t.Fatalf("accepted %s: %v", tc.Name, err)
		}
	}
	mmr, _ := NewMMR(fixture.Domain)
	derived := []Hash{mmr.leaf(0, []byte(fixture.Leaves[0])), mmr.leaf(1, []byte(fixture.Leaves[1]))}
	derived = append(derived, mmr.node(derived[0], derived[1]), mmr.Root())
	for i, tc := range fixture.Preimages {
		preimage, err := hex.DecodeString(tc.Preimage)
		if err != nil {
			t.Fatal(err)
		}
		if HashBytes(preimage) != derived[i] || derived[i].String() != tc.Digest {
			t.Fatalf("primitive preimage %d differs", i)
		}
	}
}

func TestOutputMMRRequiresAtLeastOneLeaf(t *testing.T) {
	if _, err := OutputMMRRoot(nil); err == nil {
		t.Fatal("empty output tree accepted")
	}
	root, err := OutputMMRRoot([][]byte{{}})
	if err != nil {
		t.Fatal(err)
	}
	if root.String() != "df63f8049ceef9870c9238e256a1af5bd0011692f442cc6141b3b3a69517a9a6" {
		t.Fatalf("empty output root = %s", root)
	}
	if root == OutputHash(nil) {
		t.Fatal("output MMR collapsed to a blob hash")
	}
	for _, domain := range []string{"", string([]byte{0xff})} {
		if _, err := NewMMR(domain); err == nil {
			t.Fatal("invalid domain accepted")
		}
	}
}

func TestOutputMMRRootFromLengthsPreservesBoundaries(t *testing.T) {
	root, err := OutputMMRRootFromLengths([]byte("Hello, world!"), []uint64{5, 2, 5, 1})
	if err != nil || root.String() != "17da96c6c109eb9889d40d667f726a0fdbb8a0c85173d2274aef93e93ebb0d45" {
		t.Fatalf("published root %s: %v", root, err)
	}
	empty, err := OutputMMRRootFromLengths(nil, []uint64{0})
	if err != nil || empty.String() != "df63f8049ceef9870c9238e256a1af5bd0011692f442cc6141b3b3a69517a9a6" {
		t.Fatalf("empty output %s: %v", empty, err)
	}
	for _, tc := range []struct {
		data    []byte
		lengths []uint64
	}{
		{nil, nil}, {nil, []uint64{0, 0}}, {nil, []uint64{1}},
		{[]byte("a"), []uint64{0}}, {[]byte("a"), []uint64{2}},
		{[]byte("a"), []uint64{1, math.MaxUint64}},
		{[]byte{0xc3, 0xa9}, []uint64{1, 1}},
		{[]byte{0xff}, []uint64{1}},
	} {
		if _, err := OutputMMRRootFromLengths(tc.data, tc.lengths); err == nil {
			t.Fatalf("invalid lengths %v for %x accepted", tc.lengths, tc.data)
		}
	}
	for _, chunks := range [][][]byte{{{}, {}}, {{0xff}}, {{0xc3}, {0xa9}}} {
		if _, err := OutputMMRRoot(chunks); err == nil {
			t.Fatalf("invalid TEXT chunks %x accepted", chunks)
		}
	}
	if _, err := MMRRoot("TRUEOPEN_TEST_MMR_V1", [][]byte{{0xff}}); err != nil {
		t.Fatalf("generic MMR must permit arbitrary leaf bytes: %v", err)
	}
}

func TestMMRCloneAppendDoesNotChangeOriginal(t *testing.T) {
	original, err := NewMMR(DomainOutputMMRV1)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []string{"a", "b", "c"} {
		if err := original.Append([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	root := original.Root()
	clone := original.Clone()
	if clone.Root() != root || clone.LeafCount() != 3 {
		t.Fatal("clone lost its prefix")
	}
	if err := clone.Append([]byte("d")); err != nil {
		t.Fatal(err)
	}
	if original.Root() != root || original.LeafCount() != 3 {
		t.Fatal("clone append changed original accumulator")
	}
	if clone.Root() == root || clone.LeafCount() != 4 {
		t.Fatal("clone did not advance independently")
	}
	if err := original.Append([]byte("e")); err != nil {
		t.Fatal(err)
	}
	if original.Root() == clone.Root() {
		t.Fatal("independent appends collapsed to the same root")
	}
}
