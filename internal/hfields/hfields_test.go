package hfields_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

const goldenFixturePath = "testdata/hfields_v1.json"

// testEnum stands in for a generated protobuf enum, which is always ~int32.
type testEnum int32

// TestPreimageFramesHandComputedVector pins the full preimage, not just the
// digest. Every expected segment below is written out by hand from the frozen
// rules so that the assertion is independent of the encoder under test.
func TestPreimageFramesHandComputedVector(t *testing.T) {
	const domain = "CORTEX_HFIELDS_PRIMITIVE_V1"

	var hash codec.Hash
	for i := range hash {
		hash[i] = byte(i)
	}

	// u64_be(27) || "CORTEX_HFIELDS_PRIMITIVE_V1"
	expected := concat(
		mustHex(t, "000000000000001b"), []byte(domain),
		// u64_be(6) || "cortex"
		mustHex(t, "0000000000000006"), []byte("cortex"),
		// u64_be(3) || 00 ff 10
		mustHex(t, "0000000000000003"), mustHex(t, "00ff10"),
		// u64_be(32) || 00..1f
		mustHex(t, "0000000000000020"), mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		// u64_be(4) || uint32 66051 big endian
		mustHex(t, "0000000000000004"), mustHex(t, "00010203"),
		// u64_be(8) || uint64 1 big endian
		mustHex(t, "0000000000000008"), mustHex(t, "0000000000000001"),
		// u64_be(1) || 0x01, then u64_be(1) || 0x00
		mustHex(t, "0000000000000001"), mustHex(t, "01"),
		mustHex(t, "0000000000000001"), mustHex(t, "00"),
		// u64_be(4) || enum 7 as uint32 big endian
		mustHex(t, "0000000000000004"), mustHex(t, "00000007"),
		// u64_be(21) || nested frame: u64_be(1) || "a" || u64_be(4) || uint32 2
		mustHex(t, "0000000000000015"),
		mustHex(t, "0000000000000001"), []byte("a"),
		mustHex(t, "0000000000000004"), mustHex(t, "00000002"),
		// empty string field, then empty nested frame field
		mustHex(t, "0000000000000000"),
		mustHex(t, "0000000000000000"),
	)

	preimage, err := hfields.Preimage(domain,
		hfields.String("cortex"),
		hfields.Bytes([]byte{0x00, 0xff, 0x10}),
		hfields.Hash(hash),
		hfields.Uint32(66051),
		hfields.Uint64(1),
		hfields.Bool(true),
		hfields.Bool(false),
		hfields.Enum(testEnum(7)),
		hfields.Frame(hfields.String("a"), hfields.Uint32(2)),
		hfields.String(""),
		hfields.Frame(),
	)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if !bytes.Equal(preimage, expected) {
		t.Fatalf("preimage mismatch\n got %s\nwant %s", hex.EncodeToString(preimage), hex.EncodeToString(expected))
	}

	digest, err := hfields.Digest(domain,
		hfields.String("cortex"),
		hfields.Bytes([]byte{0x00, 0xff, 0x10}),
		hfields.Hash(hash),
		hfields.Uint32(66051),
		hfields.Uint64(1),
		hfields.Bool(true),
		hfields.Bool(false),
		hfields.Enum(testEnum(7)),
		hfields.Frame(hfields.String("a"), hfields.Uint32(2)),
		hfields.String(""),
		hfields.Frame(),
	)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if digest != codec.HashBytes(expected) {
		t.Fatalf("digest is not SHA-256 over the preimage: got %x", digest)
	}
}

// TestScalarFieldsAreFixedWidthBigEndian isolates one field at a time and
// checks its framed bytes. The values are chosen so that a little-endian or
// decimal-text encoder produces different bytes.
func TestScalarFieldsAreFixedWidthBigEndian(t *testing.T) {
	var hash codec.Hash
	hash[0] = 0xaa
	hash[31] = 0xbb

	cases := []struct {
		name  string
		field hfields.Field
		want  string
	}{
		{"uint32", hfields.Uint32(0x01020304), "0000000000000004" + "01020304"},
		{"uint32_max", hfields.Uint32(^uint32(0)), "0000000000000004" + "ffffffff"},
		{"uint32_zero", hfields.Uint32(0), "0000000000000004" + "00000000"},
		{"uint64", hfields.Uint64(0x0102030405060708), "0000000000000008" + "0102030405060708"},
		{"uint64_one", hfields.Uint64(1), "0000000000000008" + "0000000000000001"},
		{"uint64_max", hfields.Uint64(^uint64(0)), "0000000000000008" + "ffffffffffffffff"},
		{"enum", hfields.Enum(testEnum(0x01020304)), "0000000000000004" + "01020304"},
		{"enum_zero", hfields.Enum(testEnum(0)), "0000000000000004" + "00000000"},
		{"bool_true", hfields.Bool(true), "0000000000000001" + "01"},
		{"bool_false", hfields.Bool(false), "0000000000000001" + "00"},
		{"hash", hfields.Hash(hash), "0000000000000020" + "aa" + strings.Repeat("00", 30) + "bb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := framedFieldHex(t, tc.field); got != tc.want {
				t.Fatalf("framed field = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestEnumFramesAsUint32 pins the frozen rule that an enum is encoded as its
// uint32 big-endian number, so the two constructors must not diverge.
func TestEnumFramesAsUint32(t *testing.T) {
	for _, value := range []int32{0, 1, 7, 255, 256, 0x7fffffff} {
		if got, want := framedFieldHex(t, hfields.Enum(testEnum(value))), framedFieldHex(t, hfields.Uint32(uint32(value))); got != want {
			t.Fatalf("Enum(%d) = %s, Uint32(%d) = %s", value, got, value, want)
		}
	}
}

// TestNestedFrameExcludesDomainPrefix pins that a nested frame is the inner
// field frame only: no domain, and no repetition of the outer domain.
func TestNestedFrameExcludesDomainPrefix(t *testing.T) {
	inner := concat(
		mustHex(t, "000000000000000d"), []byte("model-goal1-a"),
		mustHex(t, "0000000000000004"), mustHex(t, "00000001"),
	)
	if len(inner) != 33 {
		t.Fatalf("hand-built inner frame is %d bytes, want 33", len(inner))
	}

	want := hex.EncodeToString(concat(mustHex(t, "0000000000000021"), inner))
	got := framedFieldHex(t, hfields.Frame(hfields.String("model-goal1-a"), hfields.Uint32(1)))
	if got != want {
		t.Fatalf("nested frame field = %s, want %s", got, want)
	}

	// A nested frame must not embed the outer domain: framing the same two
	// fields under a domain is strictly longer than the nested frame.
	underDomain, err := hfields.Preimage("D", hfields.String("model-goal1-a"), hfields.Uint32(1))
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if bytes.Contains(inner, []byte("D")) || len(underDomain) != len(inner)+9 {
		t.Fatalf("nested frame is not domain-free: inner=%d domained=%d", len(inner), len(underDomain))
	}

	// Nesting must be a real level: one nested frame of two fields differs from
	// the two fields spliced in flat.
	nested, err := hfields.Digest("D", hfields.Frame(hfields.String("a"), hfields.Uint32(2)))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	flat, err := hfields.Digest("D", hfields.String("a"), hfields.Uint32(2))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if nested == flat {
		t.Fatal("nested frame collapses into its flattened fields")
	}
}

// TestEmptyFieldsAndEmptyList pins how the frozen encoding represents absent
// values: an empty field is a bare zero length prefix, and no field at all is
// not the same message as one empty field.
func TestEmptyFieldsAndEmptyList(t *testing.T) {
	const domain = "CORTEX_HFIELDS_NO_FIELDS_V1"

	noFields, err := hfields.Preimage(domain)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	wantNoFields := concat(mustHex(t, "000000000000001b"), []byte(domain))
	if !bytes.Equal(noFields, wantNoFields) {
		t.Fatalf("empty field list preimage = %x, want %x", noFields, wantNoFields)
	}

	oneEmpty, err := hfields.Preimage(domain, hfields.Bytes(nil))
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if !bytes.Equal(oneEmpty, concat(wantNoFields, mustHex(t, "0000000000000000"))) {
		t.Fatalf("one empty field preimage = %x", oneEmpty)
	}
	if bytes.Equal(noFields, oneEmpty) {
		t.Fatal("no fields and one empty field frame identically")
	}

	// Every way of spelling an empty field agrees, including the zero Field.
	empties := map[string]hfields.Field{
		"zero_value":   {},
		"nil_bytes":    hfields.Bytes(nil),
		"empty_bytes":  hfields.Bytes([]byte{}),
		"empty_string": hfields.String(""),
		"empty_frame":  hfields.Frame(),
	}
	want := framedFieldHex(t, hfields.Bytes(nil))
	if want != "0000000000000000" {
		t.Fatalf("empty field frames as %s", want)
	}
	for name, field := range empties {
		if got := framedFieldHex(t, field); got != want {
			t.Fatalf("%s frames as %s, want %s", name, got, want)
		}
	}
}

// TestFieldBoundariesAreUnambiguous pins the reason the length prefix exists:
// regrouping the same concatenated bytes must move the digest.
func TestFieldBoundariesAreUnambiguous(t *testing.T) {
	digests := map[string]codec.Hash{}
	groupings := map[string][]hfields.Field{
		"a|bc":     {hfields.String("a"), hfields.String("bc")},
		"ab|c":     {hfields.String("ab"), hfields.String("c")},
		"abc":      {hfields.String("abc")},
		"a|b|c":    {hfields.String("a"), hfields.String("b"), hfields.String("c")},
		"a|bc|nil": {hfields.String("a"), hfields.String("bc"), hfields.Bytes(nil)},
		"bc|a":     {hfields.String("bc"), hfields.String("a")},
	}
	for name, fields := range groupings {
		digest, err := hfields.Digest("D", fields...)
		if err != nil {
			t.Fatalf("Digest(%s): %v", name, err)
		}
		for other, seen := range digests {
			if seen == digest {
				t.Fatalf("groupings %s and %s share a digest", name, other)
			}
		}
		digests[name] = digest
	}

	// The domain is part of the same framing, so it cannot be shifted into the
	// first field either.
	shifted, err := hfields.Digest("DA", hfields.String("bc"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if shifted == digests["a|bc"] {
		t.Fatal("domain bytes can be shifted into the first field")
	}
}

// TestRejectsInexpressibleInput covers everything the frozen encoding cannot
// carry. Each case must be an error, never a silently framed value.
func TestRejectsInexpressibleInput(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		fields []hfields.Field
		want   string
	}{
		{"empty_domain", "", nil, "domain is required"},
		{"blank_domain", "   ", nil, "domain is required"},
		{"invalid_utf8_domain", "D\xff", nil, "domain is not valid UTF-8"},
		{"invalid_utf8_string_field", "D", []hfields.Field{hfields.String("\xff")}, "field 0: string field is not valid UTF-8"},
		{"invalid_utf8_string_field_index", "D", []hfields.Field{hfields.Uint64(1), hfields.String("ok"), hfields.String("bad\xc3")}, "field 2: string field is not valid UTF-8"},
		{"negative_enum", "D", []hfields.Field{hfields.Enum(testEnum(-1))}, "field 0: enum value -1 is negative"},
		{"nested_frame_error", "D", []hfields.Field{hfields.Frame(hfields.Uint32(1), hfields.String("\xfe"))}, "field 0: nested frame: field 1: string field is not valid UTF-8"},
		{"doubly_nested_frame_error", "D", []hfields.Field{hfields.Frame(hfields.Frame(hfields.Enum(testEnum(-2))))}, "field 0: nested frame: field 0: nested frame: field 0: enum value -2 is negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preimage, err := hfields.Preimage(tc.domain, tc.fields...)
			if err == nil {
				t.Fatalf("Preimage accepted %s and produced %x", tc.name, preimage)
			}
			if preimage != nil {
				t.Fatalf("Preimage returned bytes alongside error: %x", preimage)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.want)
			}

			digest, err := hfields.Digest(tc.domain, tc.fields...)
			if err == nil {
				t.Fatalf("Digest accepted %s", tc.name)
			}
			if digest != (codec.Hash{}) {
				t.Fatalf("Digest returned %x alongside error", digest)
			}
		})
	}
}

// TestFramingMatchesCodecHashWithDomain proves this package did not fork the
// framing already in internal/codec: for raw byte fields the two must agree.
func TestFramingMatchesCodecHashWithDomain(t *testing.T) {
	const domain = "CORTEX_HFIELDS_PRIMITIVE_V1"
	raw := [][]byte{[]byte("cortex"), {0x00, 0xff, 0x10}, nil, codec.Uint64Bytes(1)}

	got, err := hfields.Digest(domain,
		hfields.String("cortex"),
		hfields.Bytes([]byte{0x00, 0xff, 0x10}),
		hfields.Bytes(nil),
		hfields.Uint64(1),
	)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if want := codec.HashWithDomain(domain, raw...); got != want {
		t.Fatalf("Digest = %x, codec.HashWithDomain = %x", got, want)
	}
}

// TestGoldenFixtureRecomputes recomputes every stamped vector. The node_parity
// vectors are copied verbatim from the frozen Node fixture, so passing them
// proves byte-for-byte agreement with the contract at the stamped commit.
func TestGoldenFixtureRecomputes(t *testing.T) {
	fixture := loadGoldenFixture(t)
	if fixture.NodeSourceCommit != "3fe65982fd40462b4053d8e6757de3ec552e36be" {
		t.Fatalf("fixture is stamped with commit %q", fixture.NodeSourceCommit)
	}
	if len(fixture.NodeSources) == 0 {
		t.Fatal("fixture must stamp the exact Node source paths")
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	parity := 0
	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Framing != "" && vector.Framing != "H_FIELDS_V1" {
				t.Fatalf("unexpected framing %q", vector.Framing)
			}
			fields := encodeFixtureFields(t, vector.Fields)

			preimage, err := hfields.Preimage(vector.Domain, fields...)
			if err != nil {
				t.Fatalf("Preimage: %v", err)
			}
			if got := hex.EncodeToString(preimage); got != vector.PreimageHex {
				t.Fatalf("preimage = %s, want %s", got, vector.PreimageHex)
			}

			digest, err := hfields.Digest(vector.Domain, fields...)
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != vector.DigestHex {
				t.Fatalf("digest = %s, want %s", got, vector.DigestHex)
			}
			if len(vector.DigestHex) != 2*len(codec.Hash{}) {
				t.Fatalf("digest_hex is %d chars", len(vector.DigestHex))
			}
		})
		if vector.Kind == "node_parity" {
			parity++
		}
	}
	if parity == 0 {
		t.Fatal("fixture must keep at least one verbatim Node parity vector")
	}
}

// TestGoldenFixtureEncodesNoAddressField guards the deliberate omission: this
// package exposes no address field constructor, because it is the framing
// primitive and carries no Bech32 decoder. Callers resolve the address codec
// bytes themselves and pass them as Bytes - internal/nodewire/address.go
// CanonicalOperatorAddressBytes, used by internal/keepercontract/signing.go:44 -
// so no vector here may pin an address encoding either.
func TestGoldenFixtureEncodesNoAddressField(t *testing.T) {
	fixture := loadGoldenFixture(t)
	var walk func(fields []fixtureField)
	walk = func(fields []fixtureField) {
		for _, field := range fields {
			if field.Type == "address" {
				t.Fatalf("field %q pins an address encoding", field.Name)
			}
			walk(field.Fields)
		}
	}
	for _, vector := range fixture.Vectors {
		walk(vector.Fields)
	}

	// The parity vectors carry operator addresses only as opaque bytes copied
	// from Node, which is what makes them safe to keep.
	for _, vector := range fixture.Vectors {
		for _, field := range vector.Fields {
			if field.Name == "operator_address" && field.Type != "bytes" {
				t.Fatalf("operator_address is framed as %q; only verbatim opaque bytes may be pinned", field.Type)
			}
		}
	}
}

type goldenFixture struct {
	Schema           string          `json:"schema"`
	NodeSourceCommit string          `json:"node_source_commit"`
	NodeSources      []string        `json:"node_sources"`
	Notes            []string        `json:"notes"`
	Vectors          []fixtureVector `json:"vectors"`
}

type fixtureVector struct {
	Name        string         `json:"name"`
	Kind        string         `json:"kind"`
	Domain      string         `json:"domain"`
	Framing     string         `json:"framing"`
	Fields      []fixtureField `json:"fields"`
	PreimageHex string         `json:"preimage_hex"`
	DigestHex   string         `json:"digest_hex"`
}

type fixtureField struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	UTF8   *string        `json:"utf8"`
	Hex    *string        `json:"hex"`
	Value  *uint64        `json:"value"`
	Bool   *bool          `json:"bool"`
	Fields []fixtureField `json:"fields"`
}

func loadGoldenFixture(t *testing.T) goldenFixture {
	t.Helper()
	raw, err := os.ReadFile(goldenFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenFixturePath, err)
	}
	// Strict decoding so a typo'd or silently dropped fixture key fails loudly
	// instead of hashing fewer fields than the vector claims.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var fixture goldenFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode %s: %v", goldenFixturePath, err)
	}
	return fixture
}

func encodeFixtureFields(t *testing.T, fields []fixtureField) []hfields.Field {
	t.Helper()
	encoded := make([]hfields.Field, 0, len(fields))
	for _, field := range fields {
		encoded = append(encoded, encodeFixtureField(t, field))
	}
	return encoded
}

func encodeFixtureField(t *testing.T, field fixtureField) hfields.Field {
	t.Helper()
	switch field.Type {
	case "string":
		if field.UTF8 == nil {
			t.Fatalf("field %q requires utf8", field.Name)
		}
		return hfields.String(*field.UTF8)
	case "bytes":
		return hfields.Bytes(fixtureHex(t, field))
	case "hash":
		raw := fixtureHex(t, field)
		if len(raw) != len(codec.Hash{}) {
			t.Fatalf("field %q is %d bytes, want 32", field.Name, len(raw))
		}
		var hash codec.Hash
		copy(hash[:], raw)
		return hfields.Hash(hash)
	case "uint32":
		value := fixtureValue(t, field)
		if value > uint64(^uint32(0)) {
			t.Fatalf("field %q overflows uint32", field.Name)
		}
		return hfields.Uint32(uint32(value))
	case "uint64":
		return hfields.Uint64(fixtureValue(t, field))
	case "enum":
		value := fixtureValue(t, field)
		if value > uint64(^uint32(0)>>1) {
			t.Fatalf("field %q overflows an int32 enum", field.Name)
		}
		return hfields.Enum(testEnum(value))
	case "bool":
		if field.Bool == nil {
			t.Fatalf("field %q requires bool", field.Name)
		}
		return hfields.Bool(*field.Bool)
	case "frame":
		return hfields.Frame(encodeFixtureFields(t, field.Fields)...)
	default:
		t.Fatalf("unknown fixture field type %q on field %q", field.Type, field.Name)
		return hfields.Field{}
	}
}

func fixtureHex(t *testing.T, field fixtureField) []byte {
	t.Helper()
	if field.Hex == nil {
		t.Fatalf("field %q requires hex", field.Name)
	}
	raw, err := hex.DecodeString(*field.Hex)
	if err != nil {
		t.Fatalf("field %q is not hex: %v", field.Name, err)
	}
	if hex.EncodeToString(raw) != *field.Hex {
		t.Fatalf("field %q must be canonical lowercase hex", field.Name)
	}
	return raw
}

func fixtureValue(t *testing.T, field fixtureField) uint64 {
	t.Helper()
	if field.Value == nil {
		t.Fatalf("field %q requires value", field.Name)
	}
	return *field.Value
}

// framedFieldHex returns the framed bytes of exactly one field by stripping the
// domain prefix that Preimage writes first.
func framedFieldHex(t *testing.T, field hfields.Field) string {
	t.Helper()
	const domain = "D"
	preimage, err := hfields.Preimage(domain, field)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	prefix := 8 + len(domain)
	if len(preimage) < prefix {
		t.Fatalf("preimage %x is shorter than its domain prefix", preimage)
	}
	if !bytes.Equal(preimage[:prefix], concat(mustHex(t, "0000000000000001"), []byte(domain))) {
		t.Fatalf("domain prefix = %x", preimage[:prefix])
	}
	return hex.EncodeToString(preimage[prefix:])
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

func concat(parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	out := make([]byte, 0, size)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
