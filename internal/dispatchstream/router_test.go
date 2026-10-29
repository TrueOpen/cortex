package dispatchstream

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// The oneof numbers are wire's binding table; pin them to the generated
// descriptor so a regenerated proto cannot silently renumber a variant.
func TestVariantNumbersMatchGeneratedDescriptor(t *testing.T) {
	want := map[protoreflect.Name]variant{
		"binding": variantBinding, "handraise": variantHandraise, "handraise_root": variantHandraiseRoot,
		"offer": variantOffer, "accept": variantAccept, "reject": variantReject,
		"input_request": variantInputRequest, "input_response": variantInputResponse, "revoke": variantRevoke,
		"record_result": variantRecordResult, "open_verify": variantOpenVerify,
		"verifier_handraise": variantVerifierHandraise, "verifier_assignment": variantVerifierAssignment,
		"verify_result_submitted": variantVerifyResultSubmitted, "ack": variantAck, "keepalive": variantKeepalive,
	}
	fields := frameOneof.Fields()
	if fields.Len() != len(want) {
		t.Fatalf("oneof has %d variants, pinned %d", fields.Len(), len(want))
	}
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if want[f.Name()] != variant(f.Number()) {
			t.Fatalf("%s is field %d, pinned %d", f.Name(), f.Number(), want[f.Name()])
		}
		if f.Number() > 3 && !variant(f.Number()).control() {
			if variant(f.Number()).fromCortex() == variant(f.Number()).fromBuilder() {
				t.Fatalf("%s must belong to exactly one direction", f.Name())
			}
		}
	}
}

func TestEncodedFramesPassWireStrictDecode(t *testing.T) {
	nonce := bytes.Repeat([]byte{9}, dispatch.StreamNonceSize)
	ack, err := encodeControl(nonce, &nexusv1.StreamAckV1{AckedCursor: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.ValidateMessage("nexus.v1.DispatchStreamFrameV1", ack); err != nil {
		t.Fatalf("ack frame: %v", err)
	}
	payload, _ := proto.Marshal(&nexusv1.StreamKeepaliveV1{SentAtMs: 1})
	if err := dispatch.ValidateMessage("nexus.v1.DispatchStreamFrameV1", encodeFrame(nonce, 0, variantKeepalive, payload)); err != nil {
		t.Fatalf("keepalive frame: %v", err)
	}
	var got nexusv1.DispatchStreamFrameV1
	if err := proto.Unmarshal(ack, &got); err != nil || got.GetAck().GetAckedCursor() != 4 || got.GetCursor() != 0 {
		t.Fatalf("round trip: %v %v", &got, err)
	}
}

func TestUnwrapEnvelopeIsStrict(t *testing.T) {
	frame := []byte{0x0a, 0x00}
	ok := wrapEnvelope(frame)
	if got, err := unwrapEnvelope(ok); err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("plain envelope: %x %v", got, err)
	}
	for name, raw := range map[string][]byte{
		"empty":    nil,
		"repeated": append(append([]byte(nil), ok...), ok...),
		"unknown":  append(append([]byte(nil), ok...), 0x10, 0x01),
		"varint":   {0x08, 0x01},
		"trunc":    ok[:len(ok)-1],
	} {
		if _, err := unwrapEnvelope(raw); err == nil {
			t.Fatalf("%s envelope accepted", name)
		}
	}
}
