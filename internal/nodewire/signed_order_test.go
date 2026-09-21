package nodewire

import (
	"encoding/hex"
	"strings"
	"testing"

	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type nexusSignedOrderFixture struct {
	TaskHash         string `json:"task_hash"`
	OrderEnvelopeHex string `json:"order_envelope_hex"`
	OrderOnlyHex     string `json:"order_only_proto_hex"`
	SignatureScheme  string `json:"signature_scheme"`
	UserSignatureHex string `json:"user_signature_hex"`
	UserAddress      string `json:"user_address"`
}

func loadNexusSignedOrderFixture(t *testing.T) nexusSignedOrderFixture {
	t.Helper()
	var order taskv1.TaskOrderV2
	if err := protojson.Unmarshal(goldenTaskOrderJSON(t), &order); err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString(strings.Repeat("01", 64) + "1b")
	signed := &taskv1.SignedOrderV2{Order: &order, SignatureScheme: "eip712", UserSignature: signature}
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	orderRaw, err := proto.Marshal(&order)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := TaskOrderHashJSON(string(goldenTaskOrderJSON(t)))
	if err != nil {
		t.Fatal(err)
	}
	return nexusSignedOrderFixture{TaskHash: hex.EncodeToString(digest[:]), OrderEnvelopeHex: hex.EncodeToString(raw),
		OrderOnlyHex: hex.EncodeToString(orderRaw), SignatureScheme: "eip712", UserSignatureHex: hex.EncodeToString(signature), UserAddress: order.UserAddress}
}

// TestSignedOrderCarrierPreservesFacts checks the generated V2 carrier against
// the local regression document and its independent task hash.
func TestSignedOrderCarrierPreservesFacts(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	digest, facts, err := TaskOrderHashAndFactsSignedOrderHex(fixture.OrderEnvelopeHex)
	if err != nil {
		t.Fatalf("TaskOrderHashAndFactsSignedOrderHex error = %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got != fixture.TaskHash {
		t.Fatalf("task_hash = %s, want %s", got, fixture.TaskHash)
	}
	if facts.SignatureScheme != fixture.SignatureScheme || facts.UserSignature != fixture.UserSignatureHex {
		t.Fatalf("signature facts = %q/%q, want %q/%q", facts.SignatureScheme, facts.UserSignature, fixture.SignatureScheme, fixture.UserSignatureHex)
	}
	want := TaskOrderFacts{
		ChainID: "trueopen-test-1", SessionID: strings.Repeat("12", 32), OrderSequence: 7,
		ModelID: "model-task-order", ProfileVersion: 3, InputHash: strings.Repeat("13", 32),
		InputSizeBytes: 99, SessionAnchorBlockHash: strings.Repeat("14", 32),
		BuilderSetID: "7", BuilderSetHash: strings.Repeat("15", 32), OrderExpireHeight: 80,
		SignatureScheme: fixture.SignatureScheme, UserSignature: fixture.UserSignatureHex,
	}
	facts.Generation = nil // Generation is asserted independently for both carriers.
	if facts != want {
		t.Fatalf("facts = %+v, want %+v", facts, want)
	}
}

// TestOrderEnvelopeCarriersDeriveOneTaskHash states the property the split
// exists for: which carrier a Builder chose must not change the task identity.
func TestOrderEnvelopeCarriersDeriveOneTaskHash(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	fromProto, _, err := TaskOrderHashAndFactsEnvelope(fixture.OrderEnvelopeHex)
	if err != nil {
		t.Fatalf("proto carrier error = %v", err)
	}
	fromJSON, _, err := TaskOrderHashAndFactsEnvelope(string(goldenTaskOrderJSON(t)))
	if err != nil {
		t.Fatalf("JSON carrier error = %v", err)
	}
	if fromProto != fromJSON {
		t.Fatalf("carriers disagree: proto=%x json=%x", fromProto[:], fromJSON[:])
	}
}

// TestOrderEnvelopeCarrierIsChosenByFirstByte pins the dispatch itself: a JSON
// document must never reach the proto decoder and vice versa, because each
// produces a confusing error for the other's bytes.
func TestOrderEnvelopeCarrierIsChosenByFirstByte(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	if _, _, err := TaskOrderHashAndFactsEnvelope("{"); err == nil || !strings.Contains(err.Error(), "decode TaskOrderV2") {
		t.Fatalf("'{' must reach the JSON decoder, got %v", err)
	}
	if _, _, err := TaskOrderHashAndFactsEnvelope(fixture.OrderEnvelopeHex[:8]); err == nil || !strings.Contains(err.Error(), "SignedOrderV2") {
		t.Fatalf("hex must reach the proto decoder, got %v", err)
	}
}

func TestSignedOrderCarrierRefusesMalformedCarriers(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	raw, err := hex.DecodeString(fixture.OrderEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	orderOnly, err := hex.DecodeString(fixture.OrderOnlyHex)
	if err != nil {
		t.Fatal(err)
	}

	appendField := func(base []byte, number protowire.Number, typ protowire.Type, payload []byte) []byte {
		out := append(append([]byte(nil), base...), protowire.AppendTag(nil, number, typ)...)
		if typ == protowire.BytesType {
			return protowire.AppendBytes(out, payload)
		}
		return protowire.AppendVarint(out, uint64(payload[0]))
	}
	// A SignedOrderV2 whose inner order has been rebuilt, so the mutation under
	// test lands inside the signed document rather than beside it.
	rewrap := func(order []byte) string {
		out := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), order)
		out = protowire.AppendString(protowire.AppendTag(out, 2, protowire.BytesType), "eip712")
		signature, _ := hex.DecodeString(fixture.UserSignatureHex)
		return hex.EncodeToString(protowire.AppendBytes(protowire.AppendTag(out, 3, protowire.BytesType), signature))
	}

	for _, tc := range []struct {
		name, carrier, want string
	}{
		{"empty", "", "carrier is empty"},
		{"uppercase hex", strings.ToUpper(fixture.OrderEnvelopeHex), "must be lowercase hex"},
		{"odd hex", fixture.OrderEnvelopeHex[:len(fixture.OrderEnvelopeHex)-1], "must be lowercase hex"},
		{"not hex", "zz", "must be lowercase hex"},
		{"truncated frame", hex.EncodeToString(raw[:len(raw)-4]), "SignedOrderV2 field 3 is truncated"},
		{"trailing garbage", hex.EncodeToString(append(append([]byte(nil), raw...), 0xff)), "SignedOrderV2 is not a well-formed proto message"},
		{"unknown SignedOrderV2 field", hex.EncodeToString(appendField(raw, 4, protowire.VarintType, []byte{1})), "SignedOrderV2 carries unknown field 4"},
		{"unknown TaskOrderV2 field", rewrap(appendField(orderOnly, 31, protowire.VarintType, []byte{1})), "TaskOrderV2 carries unknown field 31"},
		{"duplicate TaskOrderV2 field", rewrap(appendField(orderOnly, 2, protowire.BytesType, []byte("trueopen-test-2"))), "TaskOrderV2 field 2 appears more than once"},
		{"wrong wire type", rewrap(appendField(orderOnly[:0], 2, protowire.VarintType, []byte{1})), "TaskOrderV2 field 2 is not a string on the wire"},
		// A bare TaskOrderV2 is not a SignedOrderV2: its field 1 is the varint
		// schema_version, not a nested message, so it is refused at the tag rather
		// than mistaken for an unsigned order.
		{"bare TaskOrderV2", fixture.OrderOnlyHex, "SignedOrderV2 field 1 is not a message on the wire"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := TaskOrderHashAndFactsSignedOrderHex(tc.carrier)
			if err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestSignedOrderCarrierRefusesUnusableSignatures keeps the two ingress guards
// Nexus applies. Neither shape can be accepted by Keeper, so carrying one
// forward would only defer the refusal to a point where it costs a handraise.
func TestSignedOrderCarrierRefusesUnusableSignatures(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	orderOnly, err := hex.DecodeString(fixture.OrderOnlyHex)
	if err != nil {
		t.Fatal(err)
	}
	build := func(scheme string, signatureLen int) string {
		out := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), orderOnly)
		out = protowire.AppendString(protowire.AppendTag(out, 2, protowire.BytesType), scheme)
		return hex.EncodeToString(protowire.AppendBytes(protowire.AppendTag(out, 3, protowire.BytesType), make([]byte, signatureLen)))
	}
	for _, tc := range []struct{ name, carrier, want string }{
		{"wrong scheme", build("ed25519", 64), "signature_scheme must be"},
		{"old signature scheme", build("secp256k1", 64), "signature_scheme must be"},
		{"short signature", build("eip712", 64), "user_signature must be 65 bytes"},
		{"long signature", build("eip712", 66), "user_signature must be 65 bytes"},
		{"invalid recovery id", build("eip712", 65), "recovery id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := TaskOrderHashAndFactsSignedOrderHex(tc.carrier); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestSignedOrderCarrierReadsBothRepeatedSpellings covers the one field where
// the wire admits two encodings of the same list. Both must decode to the list
// the golden order signs, or a re-encoding Builder would change the task_hash.
func TestSignedOrderCarrierReadsBothRepeatedSpellings(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	packed := []byte{2, 9}
	unpacked := protowire.AppendVarint(protowire.AppendTag(nil, 10, protowire.VarintType), 2)
	unpacked = protowire.AppendVarint(protowire.AppendTag(unpacked, 10, protowire.VarintType), 9)
	packedBytes := protowire.AppendBytes(protowire.AppendTag(nil, 10, protowire.BytesType), packed)

	carrier, err := hex.DecodeString(fixture.OrderEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(carrier), string(packedBytes)) {
		t.Fatalf("fixture does not carry stop_token_ids packed; the unpacked case below would prove nothing")
	}
	// The two spellings of [2, 9] happen to encode to the same length here, so
	// the substitution can be made in place: every enclosing length prefix
	// (DecodingParamsV1 inside GenerationParamsV1 inside TaskOrderV2 inside
	// SignedOrderV2) stays correct, and the whole real frame is exercised rather
	// than one hand-built nested message.
	if len(unpacked) != len(packedBytes) {
		t.Fatalf("in-place respelling needs equal lengths, got %d and %d", len(unpacked), len(packedBytes))
	}
	respelled := strings.Replace(string(carrier), string(packedBytes), string(unpacked), 1)
	if respelled == string(carrier) {
		t.Fatalf("respelling changed nothing")
	}
	digest, _, err := TaskOrderHashAndFactsSignedOrderHex(hex.EncodeToString([]byte(respelled)))
	if err != nil {
		t.Fatalf("unpacked carrier error = %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got != fixture.TaskHash {
		t.Fatalf("unpacked stop_token_ids changed the task_hash: %s, want %s", got, fixture.TaskHash)
	}
}
