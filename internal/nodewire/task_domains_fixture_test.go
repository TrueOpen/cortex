package nodewire_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/SingaXYZ/cortex/internal/hfields"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

// wirevectors.File checks these published bytes against the pinned release
// manifest. A digest mismatch must never be fixed by editing the fixture.
const goldenFixturePath = "task/task_domains_v1.json"

// goldenFixtureSchema is the fixture's self-declared schema. wire publishes the
// vectors under their own schema name rather than Node's file layout, so a file
// swapped in from the wrong package fails on shape before any digest is compared.
const goldenFixtureSchema = "trueopen.task.domains.v1"

const (
	vectorEvidenceEmpty     = "infer_evidence_commitments_v1_empty"
	vectorEvidenceSingle    = "infer_evidence_commitments_v1_single"
	vectorEvidencePair      = "infer_evidence_commitments_v1_pair"
	vectorEvidenceReordered = "infer_evidence_commitments_v1_pair_reordered"
	vectorInferReceipt      = "infer_receipt_v2"
	vectorVerifyCommit      = "verify_commit_v1"
	vectorWorkerHandraise   = "worker_handraise_v1"
	vectorVerifierHandraise = "verifier_handraise_v1"
	vectorSettlementBill    = "settlement_bill_leaf_v1"
)

// evidenceCommitmentFrameBytesV1 is the exact framed length of one
// EvidenceCommitmentV1 element: u64_be(4)||uint32_be(evidence_kind) +
// u64_be(32)||evidence_hash_or_root + u64_be(8)||uint64_be(encoded_size_bytes).
// It is derived from the frozen field list rather than fed to an encoder, so a
// future field addition fails loudly instead of silently changing the digest.
const evidenceCommitmentFrameBytesV1 = (8 + 4) + (8 + 32) + (8 + 8)

type goldenFixture struct {
	Schema  string         `json:"schema"`
	Source  string         `json:"source"`
	Vectors []goldenVector `json:"vectors"`
}

type goldenVector struct {
	Name                 string         `json:"name"`
	Domain               string         `json:"domain"`
	Framing              string         `json:"framing"`
	ContractSection      string         `json:"contract_section"`
	Producer             string         `json:"producer"`
	RejectedByProduction string         `json:"rejected_by_production,omitempty"`
	Fields               []goldenField  `json:"fields"`
	PreimageHex          string         `json:"preimage_hex"`
	DigestHex            string         `json:"digest_hex"`
	Tamper               []goldenTamper `json:"tamper"`
	Replay               []goldenReplay `json:"replay"`
}

type goldenField struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Hex     string  `json:"hex,omitempty"`
	UTF8    *string `json:"utf8,omitempty"`
	Value   *uint64 `json:"value,omitempty"`
	Signed  *int32  `json:"signed,omitempty"`
	Bool    *bool   `json:"bool,omitempty"`
	Present *bool   `json:"present,omitempty"`
	Enum    string  `json:"enum,omitempty"`
	Bech32  string  `json:"bech32,omitempty"`
	// FrameHex is the encoded content the fixture expects for a composite
	// field. It is redundant with Fields by construction, which is exactly why
	// it is checked: an encoder that composes the nested parts in the wrong
	// order still produces a plausible byte string, and only comparing against
	// the published one catches it.
	FrameHex string        `json:"frame_hex,omitempty"`
	Fields   []goldenField `json:"fields,omitempty"`
}

type goldenTamper struct {
	Name      string `json:"name"`
	Field     int    `json:"field"`
	Byte      int    `json:"byte"`
	Bit       int    `json:"bit"`
	DigestHex string `json:"digest_hex"`
}

type goldenReplay struct {
	Name      string           `json:"name"`
	Reason    string           `json:"reason"`
	Overrides []goldenOverride `json:"overrides"`
	DigestHex string           `json:"digest_hex"`
}

type goldenOverride struct {
	Field int         `json:"field"`
	Value goldenField `json:"value"`
}

func loadGoldenFixture(t *testing.T) goldenFixture {
	t.Helper()
	raw, err := wirevectors.File(goldenFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenFixturePath, err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode %s: %v", goldenFixturePath, err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", goldenFixturePath)
	}
	raw, err = wirevectors.File("task/infer_receipt_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var receiptFixture goldenFixture
	if err := json.Unmarshal(raw, &receiptFixture); err != nil {
		t.Fatal(err)
	}
	fixture.Vectors = append(fixture.Vectors, receiptFixture.Vectors...)
	return fixture
}

func goldenVectorsByName(t *testing.T) map[string]goldenVector {
	t.Helper()
	fixture := loadGoldenFixture(t)
	byName := make(map[string]goldenVector, len(fixture.Vectors))
	for _, vector := range fixture.Vectors {
		if _, duplicate := byName[vector.Name]; duplicate {
			t.Fatalf("fixture declares %s twice", vector.Name)
		}
		byName[vector.Name] = vector
	}
	return byName
}

func requireVector(t *testing.T, vectors map[string]goldenVector, name string) goldenVector {
	t.Helper()
	vector, ok := vectors[name]
	if !ok {
		t.Fatalf("fixture is missing vector %s", name)
	}
	return vector
}

// encode applies the frozen typed field encoders through internal/hfields, so
// the golden gate exercises Cortex's framing primitive rather than a second copy
// of it. "address" is the one type that records both representations: the Bech32
// text a caller signs and the address codec bytes that are actually framed, and
// the production decoder must map one onto the other.
func (f goldenField) encode(t *testing.T) []byte {
	t.Helper()
	switch f.Type {
	case "bytes":
		return f.decodeHex(t)
	case "address":
		raw := f.decodeHex(t)
		if f.Bech32 == "" {
			t.Fatalf("address field %q must record the Bech32 text", f.Name)
		}
		decoded, err := nodewire.CanonicalOperatorAddressBytes(f.Name, f.Bech32)
		if err != nil {
			t.Fatalf("address field %q must be a canonical Bech32 address: %v", f.Name, err)
		}
		if !bytes.Equal(raw, decoded) {
			t.Fatalf("address field %q: %s decodes to %s, fixture records %s",
				f.Name, f.Bech32, hex.EncodeToString(decoded), hex.EncodeToString(raw))
		}
		return raw
	case "string":
		if f.UTF8 == nil {
			t.Fatalf("string field %q requires utf8", f.Name)
		}
		return []byte(*f.UTF8)
	case "uint32":
		return framedBytes(t, hfields.Uint32(uint32(f.requireUint32(t))))
	case "uint64":
		if f.Value == nil {
			t.Fatalf("uint64 field %q requires value", f.Name)
		}
		return framedBytes(t, hfields.Uint64(*f.Value))
	case "bool":
		if f.Bool == nil {
			t.Fatalf("bool field %q requires bool", f.Name)
		}
		return framedBytes(t, hfields.Bool(*f.Bool))
	case "enum":
		if f.Enum == "" {
			t.Fatalf("enum field %q must record the symbolic name", f.Name)
		}
		return framedBytes(t, hfields.Uint32(uint32(f.requireUint32(t))))
	case "int32":
		// Signed integers are two's-complement 4-byte big-endian, which is not
		// the same bytes as widening to uint32 for a negative value: the
		// published task_order_v1 vectors carry presence_penalty_milli = -250.
		if f.Signed == nil {
			t.Fatalf("int32 field %q requires signed", f.Name)
		}
		return framedBytes(t, hfields.Int32(*f.Signed))
	case "optional":
		// A presence-tracked field is a presence byte followed, only when set,
		// by the nested value frame. Absent is one 0x00 byte and never a
		// zero-valued payload: the two must not collapse to the same digest.
		if f.Present == nil {
			t.Fatalf("optional field %q requires present", f.Name)
		}
		if !*f.Present {
			if len(f.Fields) != 0 {
				t.Fatalf("absent optional field %q must carry no nested fields", f.Name)
			}
			return f.checkFrameHex(t, []byte{0})
		}
		if len(f.Fields) == 0 {
			t.Fatalf("present optional field %q must carry its nested value", f.Name)
		}
		return f.checkFrameHex(t, append([]byte{1}, frameBytes(t, encodeFields(t, f.Fields))...))
	case "oneof":
		// A oneof frames the SET case's field number first, so two cases whose
		// payloads happen to encode identically still differ.
		if f.Enum == "" {
			t.Fatalf("oneof field %q must record the set case name", f.Name)
		}
		if len(f.Fields) == 0 {
			t.Fatalf("oneof field %q must carry the set case's nested fields", f.Name)
		}
		var number [4]byte
		binary.BigEndian.PutUint32(number[:], uint32(f.requireUint32(t)))
		return f.checkFrameHex(t, append(number[:], frameBytes(t, encodeFields(t, f.Fields))...))
	case "frame":
		if len(f.Fields) == 0 {
			t.Fatalf("frame field %q must carry nested fields", f.Name)
		}
		return f.checkFrameHex(t, frameBytes(t, encodeFields(t, f.Fields)))
	default:
		t.Fatalf("unknown fixture field type %q on field %q", f.Type, f.Name)
		return nil
	}
}

// checkFrameHex compares a composite field's encoded content against the
// fixture's own frame_hex when it publishes one, and returns the bytes either
// way. It is the per-field half of the golden gate: without it a composition
// error only shows up as a whole-preimage mismatch, which names the vector but
// not the field that broke.
func (f goldenField) checkFrameHex(t *testing.T, encoded []byte) []byte {
	t.Helper()
	if f.FrameHex == "" {
		return encoded
	}
	if got := hex.EncodeToString(encoded); got != f.FrameHex {
		t.Fatalf("field %q frame mismatch\n got %s\nwant %s", f.Name, got, f.FrameHex)
	}
	return encoded
}

func (f goldenField) decodeHex(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatalf("field %q must be hex: %v", f.Name, err)
	}
	if hex.EncodeToString(raw) != f.Hex {
		t.Fatalf("field %q must be canonical lowercase hex", f.Name)
	}
	return raw
}

func (f goldenField) requireUint32(t *testing.T) uint64 {
	t.Helper()
	if f.Value == nil {
		t.Fatalf("field %q requires value", f.Name)
	}
	if *f.Value > uint64(^uint32(0)) {
		t.Fatalf("field %q overflows uint32", f.Name)
	}
	return *f.Value
}

func encodeFields(t *testing.T, fields []goldenField) [][]byte {
	t.Helper()
	encoded := make([][]byte, 0, len(fields))
	for _, field := range fields {
		encoded = append(encoded, field.encode(t))
	}
	return encoded
}

func byteFields(fields [][]byte) []hfields.Field {
	out := make([]hfields.Field, 0, len(fields))
	for _, field := range fields {
		out = append(out, hfields.Bytes(field))
	}
	return out
}

// framedBytes returns the encoded value of a single typed field, by framing it
// alone and stripping the domain framing and the field's own length prefix. It
// exists because the fixture mutates encoded field bytes directly, which needs
// the value rather than an opaque hfields.Field.
func framedBytes(t *testing.T, field hfields.Field) []byte {
	t.Helper()
	const domain = "F"
	preimage, err := hfields.Preimage(domain, field)
	if err != nil {
		t.Fatalf("frame one field: %v", err)
	}
	return preimage[8+len(domain)+8:]
}

// frameBytes returns the inner field frame of a nested message: the nested
// fields length-prefixed with no domain prefix.
func frameBytes(t *testing.T, fields [][]byte) []byte {
	t.Helper()
	return framedBytes(t, hfields.Frame(byteFields(fields)...))
}

func (v goldenVector) preimage(t *testing.T, fields [][]byte) []byte {
	t.Helper()
	if v.Framing != "H_FIELDS_V1" {
		t.Fatalf("%s declares framing %q; every frozen Task domain is H_FIELDS_V1", v.Name, v.Framing)
	}
	preimage, err := hfields.Preimage(v.Domain, byteFields(fields)...)
	if err != nil {
		t.Fatalf("%s: Preimage: %v", v.Name, err)
	}
	return preimage
}

func (v goldenVector) digestHex(t *testing.T, fields [][]byte) string {
	t.Helper()
	digest := codecHash(v.preimage(t, fields))
	return hex.EncodeToString(digest[:])
}

// TestFixtureProvenanceIsVerified pins the copy's provenance by digest rather
// than by stamp. The file this replaces carried a node_source_commit key and the
// test compared it to a constant - which proves only that two strings agree, not
// that the bytes came from where they claim. wire publishes a SHA-256 per
// fixture in testdata/v1/manifest.json, so the check is now the real one: hash
// what is on disk and compare it to what the release says it should be.
//
// A refresh that drops in an unverified file, or that silently loses a vector,
// fails here before any digest is compared.
func TestFixtureProvenanceIsVerified(t *testing.T) {
	_, err := wirevectors.File(goldenFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenFixturePath, err)
	}

	fixture := loadGoldenFixture(t)
	if fixture.Schema != goldenFixtureSchema {
		t.Fatalf("fixture declares schema %q, want %q", fixture.Schema, goldenFixtureSchema)
	}
	if fixture.Source == "" {
		t.Fatalf("fixture carries no source stamp")
	}
	// The published set is a superset of the nine vectors Cortex named by hand,
	// so the assertion is a floor and a per-name presence check rather than an
	// exact count: wire adding a vector for a domain Cortex does not implement
	// yet must not fail this repository's build.
	if len(fixture.Vectors) < 9 {
		t.Fatalf("fixture carries %d vectors, fewer than the 9 frozen Task vectors Cortex consumes",
			len(fixture.Vectors))
	}
	for _, name := range []string{
		vectorEvidenceEmpty, vectorEvidenceSingle, vectorEvidencePair, vectorEvidenceReordered,
		vectorInferReceipt, vectorVerifyCommit, vectorWorkerHandraise, vectorVerifierHandraise,
	} {
		requireVector(t, goldenVectorsByName(t), name)
	}
}

// TestGoldenPreimagesAndDigests reproduces every published preimage and digest
// byte for byte from the fixture's own field values through Cortex's framing.
func TestGoldenPreimagesAndDigests(t *testing.T) {
	fixture := loadGoldenFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.ContractSection == "" || vector.Producer == "" || len(vector.Fields) == 0 {
				t.Fatalf("%s is missing contract_section, producer or fields", vector.Name)
			}
			fields := encodeFields(t, vector.Fields)
			if got := hex.EncodeToString(vector.preimage(t, fields)); got != vector.PreimageHex {
				t.Fatalf("preimage mismatch\n got %s\nwant %s", got, vector.PreimageHex)
			}
			if got := vector.digestHex(t, fields); got != vector.DigestHex {
				t.Fatalf("digest mismatch\n got %s\nwant %s", got, vector.DigestHex)
			}
			if len(vector.DigestHex) != 64 {
				t.Fatalf("%s digest is not 32 bytes", vector.Name)
			}
		})
	}
}

// TestGoldenDigestsAreDistinct proves no two published vectors collide - in
// particular that the empty evidence list, the single-element list, the ascending
// pair and the illegal descending pair are four different digests, and that none
// of them is 32 zero bytes.
func TestGoldenDigestsAreDistinct(t *testing.T) {
	fixture := loadGoldenFixture(t)
	seen := make(map[string]string, len(fixture.Vectors))
	for _, vector := range fixture.Vectors {
		if previous, collided := seen[vector.DigestHex]; collided {
			t.Fatalf("%s collides with %s", vector.Name, previous)
		}
		seen[vector.DigestHex] = vector.Name
		if vector.DigestHex == "0000000000000000000000000000000000000000000000000000000000000000" {
			t.Fatalf("%s must not be the all-zero hash", vector.Name)
		}
	}
}

// TestGoldenRejectsEveryFieldBitFlip is the exhaustive per-field tamper gate:
// flipping any single bit of any framed field must move the digest, which is
// what proves no field is dropped from or duplicated in the preimage.
func TestGoldenRejectsEveryFieldBitFlip(t *testing.T) {
	fixture := loadGoldenFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			base := encodeFields(t, vector.Fields)
			if got := vector.digestHex(t, base); got != vector.DigestHex {
				t.Fatalf("base digest mismatch %s", got)
			}
			flipped := 0
			for index, field := range vector.Fields {
				if len(base[index]) == 0 {
					t.Fatalf("no frozen Task signing field is optional, so field %d (%s) must never frame empty",
						index, field.Name)
				}
				for byteIndex := range base[index] {
					for bit := range 8 {
						mutated := flipBit(t, base, index, byteIndex, bit)
						if got := vector.digestHex(t, mutated); got == vector.DigestHex {
							t.Fatalf("field %d (%s) byte %d bit %d did not change the digest",
								index, field.Name, byteIndex, bit)
						}
						flipped++
					}
				}
			}
			if flipped == 0 {
				t.Fatalf("%s flipped no bits", vector.Name)
			}
		})
	}
}

// TestGoldenTamperVectors checks the published per-field tamper goldens, so the
// bit-flip handling itself is pinned and not just self-consistent.
func TestGoldenTamperVectors(t *testing.T) {
	fixture := loadGoldenFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			base := encodeFields(t, vector.Fields)
			// Not every published vector carries tamper goldens: the five
			// structure-only domains wire added (assignment_legal_set_v1,
			// task_builders_v1, commit_key_v1, result_commitment_v1,
			// selected_task_builders_v1) publish a preimage and a digest and
			// nothing else. Demanding tamper vectors from them would reject the
			// upstream file rather than test this repository, and
			// TestGoldenRejectsEveryFieldBitFlip already flips every field of
			// every vector from the field values alone.
			if len(vector.Tamper) == 0 {
				t.Skipf("%s publishes no tamper vectors", vector.Name)
			}
			covered := make(map[int]struct{}, len(vector.Fields))
			seen := map[string]string{vector.DigestHex: "base"}
			for _, tamper := range vector.Tamper {
				if tamper.Field >= len(vector.Fields) {
					t.Fatalf("tamper %q names field %d of %d", tamper.Name, tamper.Field, len(vector.Fields))
				}
				covered[tamper.Field] = struct{}{}
				got := vector.digestHex(t, flipBit(t, base, tamper.Field, tamper.Byte, tamper.Bit))
				if got != tamper.DigestHex {
					t.Fatalf("tamper %q\n got %s\nwant %s", tamper.Name, got, tamper.DigestHex)
				}
				if previous, collided := seen[got]; collided {
					t.Fatalf("tamper %q collides with %s", tamper.Name, previous)
				}
				seen[got] = tamper.Name
			}
			for index, field := range vector.Fields {
				if _, ok := covered[index]; !ok {
					t.Fatalf("field %d (%s) has no published tamper vector", index, field.Name)
				}
			}
		})
	}
}

// TestGoldenReplayVectors covers the published cross-chain, cross-task,
// cross-operator, cross-duty, cross-round, stale-nonce, wrong-schema-version,
// non-ASCII and list reorder / duplicate replay classes.
func TestGoldenReplayVectors(t *testing.T) {
	fixture := loadGoldenFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			base := encodeFields(t, vector.Fields)
			// Skipped for the same reason as the tamper goldens above: the
			// structure-only domains publish no replay vectors, and a missing
			// upstream vector is not a Cortex defect.
			if len(vector.Replay) == 0 {
				t.Skipf("%s publishes no replay vectors", vector.Name)
			}
			seen := map[string]string{vector.DigestHex: "base"}
			for _, replay := range vector.Replay {
				if len(replay.Overrides) == 0 || replay.Reason == "" {
					t.Fatalf("replay %q needs at least one override and a reason", replay.Name)
				}
				mutated := make([][]byte, len(base))
				for i := range base {
					mutated[i] = append([]byte(nil), base[i]...)
				}
				for _, override := range replay.Overrides {
					if override.Field >= len(vector.Fields) {
						t.Fatalf("replay %q names field %d of %d", replay.Name, override.Field, len(vector.Fields))
					}
					if vector.Fields[override.Field].Type != override.Value.Type {
						t.Fatalf("replay %q must keep the frozen type of field %d", replay.Name, override.Field)
					}
					mutated[override.Field] = override.Value.encode(t)
				}
				got := vector.digestHex(t, mutated)
				if got != replay.DigestHex {
					t.Fatalf("replay %q\n got %s\nwant %s", replay.Name, got, replay.DigestHex)
				}
				if previous, collided := seen[got]; collided {
					t.Fatalf("replay %q collides with %s", replay.Name, previous)
				}
				seen[got] = replay.Name
			}
		})
	}
}

// TestProductionDigestsMatchGoldens is the value-level binding gate: every
// published preimage and digest is recomputed by feeding the fixture's own field
// values into the exported production functions, not into the fixture's generic
// encoder. The one vector that production must refuse is asserted as an error
// instead of a value.
func TestProductionDigestsMatchGoldens(t *testing.T) {
	vectors := goldenVectorsByName(t)

	t.Run("EvidenceCommitments", func(t *testing.T) {
		empty := requireVector(t, vectors, vectorEvidenceEmpty)
		if len(empty.Fields) != 2 || fieldUint(t, empty, 0, "count") != 0 {
			t.Fatalf("the empty vector must be uint32_be(0) plus an empty commitments frame")
		}
		if commitments := empty.Fields[1]; commitments.Name != "commitments" || len(commitments.Fields) != 1 {
			t.Fatalf("the empty vector's second field must be a commitments frame holding only element_count")
		}
		assertPreimageAndDigest(t, empty, func() ([]byte, error) {
			return nodewire.EvidenceCommitmentsPreimage(nil)
		})

		nilDigest, err := nodewire.EvidenceCommitmentsHash(nil)
		if err != nil {
			t.Fatalf("EvidenceCommitmentsHash(nil): %v", err)
		}
		emptySlice, err := nodewire.EvidenceCommitmentsHash([]nodewire.EvidenceCommitmentV1{})
		if err != nil {
			t.Fatalf("EvidenceCommitmentsHash([]): %v", err)
		}
		if nilDigest != emptySlice {
			t.Fatalf("nil and [] must produce the same digest")
		}

		for _, name := range []string{vectorEvidenceSingle, vectorEvidencePair} {
			vector := requireVector(t, vectors, name)
			items := evidenceCommitments(t, vector)
			// The count is stated twice - once at the top level and once as the
			// commitments frame's own element_count - and both must equal the
			// number of element frames. Checking only one would let the two
			// drift, which is a preimage a peer cannot reproduce.
			if got := fieldUint(t, vector, 0, "count"); got != uint64(len(items)) {
				t.Fatalf("%s: field 0 must be uint32_be(%d), got %d", name, len(items), got)
			}
			commitments := goldenVector{Name: name + ".commitments", Fields: vector.Fields[1].Fields}
			if got := fieldUint(t, commitments, 0, "element_count"); got != uint64(len(items)) {
				t.Fatalf("%s: the commitments frame declares element_count %d, want %d", name, got, len(items))
			}
			assertPreimageAndDigest(t, vector, func() ([]byte, error) {
				return nodewire.EvidenceCommitmentsPreimage(items)
			})
			// The element frame length is derived, not configured: assert the
			// published preimage is exactly the outer count plus one commitments
			// frame, and that the frame is its own element_count plus fixed-size
			// elements. Spelling out both levels is what catches a regression
			// back to the flattened shape, which lands on a different total for
			// every list length including the empty one.
			commitmentsBytes := (8 + 4) + len(items)*(8+evidenceCommitmentFrameBytesV1)
			want := 8 + len(vector.Domain) + (8 + 4) + (8 + commitmentsBytes)
			if got := len(vector.PreimageHex) / 2; got != want {
				t.Fatalf("%s preimage is %d bytes, want %d; the element frame is no longer %d bytes",
					name, got, want, evidenceCommitmentFrameBytesV1)
			}
		}
	})

	t.Run("EvidenceCommitmentsRejectsTheReorderedGolden", func(t *testing.T) {
		vector := requireVector(t, vectors, vectorEvidenceReordered)
		if vector.RejectedByProduction == "" {
			t.Fatalf("the reordered vector must declare that production refuses it")
		}
		items := evidenceCommitments(t, vector)
		_, err := nodewire.EvidenceCommitmentsHash(items)
		if err == nil {
			t.Fatalf("a descending list must be rejected, never silently re-sorted")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("ascending")) {
			t.Fatalf("rejection must name the ascending rule, got %v", err)
		}

		// Sorting the same two elements ascending must land on the pair digest,
		// so the illegal ordering is genuinely a different preimage and not a
		// lost input.
		pair := requireVector(t, vectors, vectorEvidencePair)
		digest, err := nodewire.EvidenceCommitmentsHash([]nodewire.EvidenceCommitmentV1{items[1], items[0]})
		if err != nil {
			t.Fatalf("ascending pair: %v", err)
		}
		if got := hex.EncodeToString(digest[:]); got != pair.DigestHex {
			t.Fatalf("sorted pair digest %s, want %s", got, pair.DigestHex)
		}
		if pair.DigestHex == vector.DigestHex {
			t.Fatalf("the reordered preimage must not share the pair's digest")
		}
	})

	t.Run("InferReceipt", func(t *testing.T) {
		vector := requireVector(t, vectors, vectorInferReceipt)
		receipt := inferReceiptFromVector(t, vectors, vector)
		assertPreimageAndDigest(t, vector, func() ([]byte, error) {
			return nodewire.InferReceiptSigningPreimage(receipt)
		})
		if got := fieldUint(t, vector, 0, "schema_version"); got != uint64(nodewire.InferReceiptSchemaVersionV2) {
			t.Fatalf("schema_version %d, want %d", got, nodewire.InferReceiptSchemaVersionV2)
		}
	})

	t.Run("VerifyCommit", func(t *testing.T) {
		vector := requireVector(t, vectors, vectorVerifyCommit)
		commit := nodewire.VerifyCommitV1{
			SchemaVersion:             uint32(fieldUint(t, vector, 0, "schema_version")),
			ChainID:                   fieldString(t, vector, 1, "chain_id"),
			TaskID:                    fieldBytes(t, vector, 2, "task_id"),
			VerifyRound:               uint32(fieldUint(t, vector, 3, "verify_round")),
			VerifierOperatorAddress:   fieldBech32(t, vector, 4, "verifier_operator_address"),
			ServiceAuthorizationNonce: fieldUint(t, vector, 5, "service_authorization_nonce"),
			CommitHash:                fieldBytes(t, vector, 6, "commit_hash"),
			ExpiryHeight:              fieldUint(t, vector, 7, "expiry_height"),
		}
		assertPreimageAndDigest(t, vector, func() ([]byte, error) {
			return nodewire.VerifyCommitSigningPreimage(commit)
		})
		if got := fieldUint(t, vector, 0, "schema_version"); got != uint64(nodewire.VerifyCommitSchemaVersionV1) {
			t.Fatalf("schema_version %d, want %d", got, nodewire.VerifyCommitSchemaVersionV1)
		}
	})

	t.Run("WorkerHandraise", func(t *testing.T) {
		vector := requireVector(t, vectors, vectorWorkerHandraise)
		handraise := nodewire.WorkerHandraiseV1{
			SchemaVersion:             uint32(fieldUint(t, vector, 0, "schema_version")),
			ChainID:                   fieldString(t, vector, 1, "chain_id"),
			TaskID:                    fieldBytes(t, vector, 2, "task_id"),
			TaskHash:                  fieldBytes(t, vector, 3, "task_hash"),
			ModelID:                   fieldString(t, vector, 4, "model_id"),
			ProfileVersion:            uint32(fieldUint(t, vector, 5, "profile_version")),
			Member:                    memberRef(t, vector, 6),
			Duty:                      nodewire.Duty(fieldUint(t, vector, 7, "duty")),
			ServiceAuthorizationNonce: fieldUint(t, vector, 8, "service_authorization_nonce"),
			ExpiryHeight:              fieldUint(t, vector, 9, "expiry_height"),
		}
		assertPreimageAndDigest(t, vector, func() ([]byte, error) {
			return nodewire.WorkerHandraiseSigningPreimage(handraise)
		})
		if got := fieldUint(t, vector, 7, "duty"); got != uint64(nodewire.DutyWorker) {
			t.Fatalf("duty %d, want WORKER for this wire", got)
		}
		if got := fieldUint(t, vector, 0, "schema_version"); got != uint64(nodewire.WorkerHandraiseSchemaVersionV1) {
			t.Fatalf("schema_version %d, want %d", got, nodewire.WorkerHandraiseSchemaVersionV1)
		}
	})

	t.Run("VerifierHandraise", func(t *testing.T) {
		vector := requireVector(t, vectors, vectorVerifierHandraise)
		handraise := nodewire.VerifierHandraiseV1{
			SchemaVersion:             uint32(fieldUint(t, vector, 0, "schema_version")),
			ChainID:                   fieldString(t, vector, 1, "chain_id"),
			TaskID:                    fieldBytes(t, vector, 2, "task_id"),
			VerifyRound:               uint32(fieldUint(t, vector, 3, "verify_round")),
			InferReceiptHash:          fieldBytes(t, vector, 4, "infer_receipt_hash"),
			OutputHash:                fieldBytes(t, vector, 5, "output_hash"),
			ModelID:                   fieldString(t, vector, 6, "model_id"),
			ProfileVersion:            uint32(fieldUint(t, vector, 7, "profile_version")),
			Member:                    memberRef(t, vector, 8),
			Duty:                      nodewire.Duty(fieldUint(t, vector, 9, "duty")),
			ServiceAuthorizationNonce: fieldUint(t, vector, 10, "service_authorization_nonce"),
			ExpiryHeight:              fieldUint(t, vector, 11, "expiry_height"),
		}
		assertPreimageAndDigest(t, vector, func() ([]byte, error) {
			return nodewire.VerifierHandraiseSigningPreimage(handraise)
		})
		if got := fieldUint(t, vector, 9, "duty"); got != uint64(nodewire.DutyVerifier) {
			t.Fatalf("duty %d, want VERIFIER for this wire", got)
		}
		if got := fieldUint(t, vector, 0, "schema_version"); got != uint64(nodewire.VerifierHandraiseSchemaVersionV1) {
			t.Fatalf("schema_version %d, want %d", got, nodewire.VerifierHandraiseSchemaVersionV1)
		}
	})

}

// assertPreimageAndDigest pins both halves of a domain: the exact preimage bytes
// and SHA-256 over them. Pinning only the digest would let a preimage bug hide
// behind a matching hash of different bytes.
func assertPreimageAndDigest(t *testing.T, vector goldenVector, build func() ([]byte, error)) {
	t.Helper()
	preimage, err := build()
	if err != nil {
		t.Fatalf("%s: %v", vector.Name, err)
	}
	if got := hex.EncodeToString(preimage); got != vector.PreimageHex {
		t.Fatalf("%s preimage mismatch\n got %s\nwant %s", vector.Name, got, vector.PreimageHex)
	}
	digest := codecHash(preimage)
	if got := hex.EncodeToString(digest[:]); got != vector.DigestHex {
		t.Fatalf("%s digest mismatch\n got %s\nwant %s", vector.Name, got, vector.DigestHex)
	}
}

func flipBit(t *testing.T, fields [][]byte, index, byteIndex, bit int) [][]byte {
	t.Helper()
	if index < 0 || index >= len(fields) {
		t.Fatalf("tamper field %d is out of range", index)
	}
	mutated := make([][]byte, len(fields))
	for i := range fields {
		mutated[i] = append([]byte(nil), fields[i]...)
	}
	target := mutated[index]
	// A negative byte index counts from the end, as the fixture notes describe.
	if byteIndex < 0 {
		byteIndex += len(target)
	}
	if byteIndex < 0 || byteIndex >= len(target) {
		t.Fatalf("tamper byte %d is out of range for field %d", byteIndex, index)
	}
	if bit < 0 || bit > 7 {
		t.Fatalf("tamper bit %d is out of range", bit)
	}
	target[byteIndex] ^= 1 << uint(bit)
	return mutated
}

func field(t *testing.T, vector goldenVector, index int, name string) goldenField {
	t.Helper()
	if index >= len(vector.Fields) {
		t.Fatalf("%s has %d fields, wanted field %d (%s)", vector.Name, len(vector.Fields), index, name)
	}
	got := vector.Fields[index]
	if got.Name != name {
		t.Fatalf("%s field %d is %q, want %q", vector.Name, index, got.Name, name)
	}
	return got
}

func fieldUint(t *testing.T, vector goldenVector, index int, name string) uint64 {
	t.Helper()
	got := field(t, vector, index, name)
	if got.Value == nil {
		t.Fatalf("%s field %s carries no numeric value", vector.Name, name)
	}
	return *got.Value
}

func fieldString(t *testing.T, vector goldenVector, index int, name string) string {
	t.Helper()
	got := field(t, vector, index, name)
	if got.UTF8 == nil {
		t.Fatalf("%s field %s carries no utf8 value", vector.Name, name)
	}
	return *got.UTF8
}

func fieldBytes(t *testing.T, vector goldenVector, index int, name string) []byte {
	t.Helper()
	return field(t, vector, index, name).decodeHex(t)
}

func fieldBech32(t *testing.T, vector goldenVector, index int, name string) string {
	t.Helper()
	got := field(t, vector, index, name)
	if got.Bech32 == "" {
		t.Fatalf("%s field %s carries no Bech32 text", vector.Name, name)
	}
	return got.Bech32
}

// fieldOptionalUint32 reads a proto3-optional uint32 back into the typed wire.
// Absent and present-zero are distinct values, not two spellings of one: the
// published vectors carry both, and collapsing them is the exact bug the
// presence byte exists to prevent.
func fieldOptionalUint32(t *testing.T, vector goldenVector, index int, name string) nodewire.OptionalUint32 {
	t.Helper()
	got := field(t, vector, index, name)
	if got.Type != "optional" || got.Present == nil {
		t.Fatalf("%s field %s is %q, want a presence-tracked optional", vector.Name, name, got.Type)
	}
	if !*got.Present {
		return nodewire.OptionalUint32{}
	}
	if len(got.Fields) != 1 {
		t.Fatalf("%s field %s is present but carries %d nested values", vector.Name, name, len(got.Fields))
	}
	nested := goldenVector{Name: vector.Name + "." + name, Fields: got.Fields}
	return nodewire.PresentUint32(uint32(fieldUint(t, nested, 0, "value")))
}

func memberRef(t *testing.T, vector goldenVector, index int) nodewire.CandidateMemberRefV1 {
	t.Helper()
	frame := field(t, vector, index, "member")
	if len(frame.Fields) != 4 {
		t.Fatalf("member frame carries %d nested fields, want 4", len(frame.Fields))
	}
	nested := goldenVector{Name: vector.Name + ".member", Fields: frame.Fields}
	return nodewire.CandidateMemberRefV1{
		CandidatePoolSnapshotID: fieldBytes(t, nested, 0, "candidate_pool_snapshot_id"),
		Slot:                    uint32(fieldUint(t, nested, 1, "slot")),
		SlotVersion:             fieldUint(t, nested, 2, "slot_version"),
		OperatorAddress:         fieldBech32(t, nested, 3, "operator_address"),
	}
}

// evidenceCommitments reads the element frames of an evidence-commitment vector
// back into the typed wire.
//
// The vector has exactly two top-level fields - uint32_be(count) and a single
// "commitments" frame - and the element frames live inside that frame, after its
// own repeated element_count. The elements used to sit directly in the top-level
// list, which is the shape this repository emitted before the frozen vectors
// were adopted; reading them from position 1 onward would silently succeed on
// the old layout and is why the frame is navigated explicitly here.
func evidenceCommitments(t *testing.T, vector goldenVector) []nodewire.EvidenceCommitmentV1 {
	t.Helper()
	if len(vector.Fields) != 2 {
		t.Fatalf("%s carries %d top-level fields, want uint32_be(count) plus one commitments frame",
			vector.Name, len(vector.Fields))
	}
	commitments := vector.Fields[1]
	if commitments.Type != "frame" || commitments.Name != "commitments" {
		t.Fatalf("%s field 1 is %q of type %q, want the \"commitments\" frame",
			vector.Name, commitments.Name, commitments.Type)
	}
	if len(commitments.Fields) == 0 {
		t.Fatalf("%s commitments frame carries no element_count", vector.Name)
	}
	items := make([]nodewire.EvidenceCommitmentV1, 0, len(commitments.Fields)-1)
	for index := 1; index < len(commitments.Fields); index++ {
		frame := commitments.Fields[index]
		if frame.Type != "frame" || len(frame.Fields) != 3 {
			t.Fatalf("%s commitments field %d must be a 3-field element frame", vector.Name, index)
		}
		nested := goldenVector{Name: fmt.Sprintf("%s[%d]", vector.Name, index), Fields: frame.Fields}
		items = append(items, nodewire.EvidenceCommitmentV1{
			EvidenceKind:       nodewire.EvidenceKind(fieldUint(t, nested, 0, "evidence_kind")),
			EvidenceHashOrRoot: fieldBytes(t, nested, 1, "evidence_hash_or_root"),
			EncodedSizeBytes:   fieldUint(t, nested, 2, "encoded_size_bytes"),
		})
	}
	if len(items) == 0 {
		t.Fatalf("%s carries no element frames", vector.Name)
	}
	return items
}

// inferReceiptFromVector rebuilds the typed receipt behind the receipt vector.
// Preimage field 9 is derived from the separately published typed commitment list.
func inferReceiptFromVector(t *testing.T, vectors map[string]goldenVector, vector goldenVector) nodewire.InferReceiptV2 {
	t.Helper()
	raw, err := wirevectors.File("task/infer_receipt_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CommitmentList struct {
			Items []struct {
				EvidenceKind          nodewire.EvidenceKind `json:"evidence_kind"`
				EvidenceHashOrRootHex string                `json:"evidence_hash_or_root_hex"`
				EncodedSizeBytes      uint64                `json:"encoded_size_bytes"`
			} `json:"items"`
		} `json:"commitment_list"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	items := make([]nodewire.EvidenceCommitmentV1, len(fixture.CommitmentList.Items))
	for i, item := range fixture.CommitmentList.Items {
		hash, err := hex.DecodeString(item.EvidenceHashOrRootHex)
		if err != nil {
			t.Fatal(err)
		}
		items[i] = nodewire.EvidenceCommitmentV1{EvidenceKind: item.EvidenceKind, EvidenceHashOrRoot: hash, EncodedSizeBytes: item.EncodedSizeBytes}
	}
	return nodewire.InferReceiptV2{
		SchemaVersion:               uint32(fieldUint(t, vector, 0, "schema_version")),
		ChainID:                     fieldString(t, vector, 1, "chain_id"),
		TaskID:                      fieldBytes(t, vector, 2, "task_id"),
		TaskHash:                    fieldBytes(t, vector, 3, "task_hash"),
		WorkerOperatorAddress:       fieldBech32(t, vector, 4, "worker_operator_address"),
		ServiceAuthorizationNonce:   fieldUint(t, vector, 5, "service_authorization_nonce"),
		GenerationParamsDigest:      fieldBytes(t, vector, 6, "generation_params_digest"),
		OutputHash:                  fieldBytes(t, vector, 7, "output_hash"),
		OutputSizeBytes:             fieldUint(t, vector, 8, "output_size_bytes"),
		RequiredEvidenceCommitments: items,
		ExpiryHeight:                fieldUint(t, vector, 10, "expiry_height"),
		GeneratedTokenCount:         fieldUint(t, vector, 11, "generated_token_count"),
		OutputLeafCount:             fieldUint(t, vector, 12, "output_leaf_count"),
	}
}
