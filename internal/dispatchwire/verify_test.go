package dispatchwire

import (
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// mutateFirstBytesField flips one byte of the first non-empty top-level bytes
// field whose name does not end in "signature". It reports whether it changed
// anything.
func mutateFirstBytesField(msg proto.Message) bool {
	r := msg.ProtoReflect()
	fields := r.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.Kind() != protoreflect.BytesKind || f.IsList() || isSignatureField(f) {
			continue
		}
		b := append([]byte(nil), r.Get(f).Bytes()...)
		if len(b) == 0 {
			continue
		}
		b[0] ^= 0x01
		r.Set(f, protoreflect.ValueOfBytes(b))
		return true
	}
	return false
}

func isSignatureField(f protoreflect.FieldDescriptor) bool {
	return strings.HasSuffix(string(f.Name()), "signature")
}

// builderSignedNames is the set of Builder-signed message types wire 916e393
// publishes vectors for; the test fails if the descriptor-based
// classification ever stops covering one of them.
var builderSignedNames = []string{
	"task.v1.DispatchTicketV1", "task.v1.SignedHandraiseRootV1", "task.v1.DispatchRecordV1",
	"nexus.v1.DispatchInputResponseV1", "nexus.v1.DispatchRevokeV1", "nexus.v1.RecordResultNoticeV1",
	"nexus.v1.DispatchResultHeaderV1", "nexus.v1.OpenVerifyV1", "nexus.v1.VerifierAssignmentNotifyV1",
}

func TestVerifyBuilderSignedVectors(t *testing.T) {
	rows, err := wirevectors.DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	otherKey := pubKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	verified := map[string]bool{}
	for _, row := range rows {
		msg := vectorMessage(t, row)
		pub := mustHex(t, row.PublicKeyHex)
		if msg.ProtoReflect().Descriptor().Fields().ByName(builderSignatureField) == nil {
			// Cortex-signed or unsigned: must be refused, not silently passed.
			if err := VerifyBuilderSigned(msg, pub); !errors.Is(err, ErrNotBuilderSigned) {
				t.Fatalf("%s: err = %v, want ErrNotBuilderSigned", row.Name, err)
			}
			if err := VerifyBuilderSignedRaw(row.MessageName, mustHex(t, row.ProtobufHex), pub); !errors.Is(err, ErrNotBuilderSigned) {
				t.Fatalf("%s raw: err = %v, want ErrNotBuilderSigned", row.Name, err)
			}
			continue
		}
		if row.SignatureHex == "" {
			t.Fatalf("%s: Builder-signed vector publishes no signature", row.Name)
		}
		if err := VerifyBuilderSigned(msg, pub); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		if err := VerifyBuilderSignedRaw(row.MessageName, mustHex(t, row.ProtobufHex), pub); err != nil {
			t.Fatalf("%s raw: %v", row.Name, err)
		}
		tampered := proto.Clone(msg)
		if !mutateFirstBytesField(tampered) {
			t.Fatalf("%s: no bytes field to tamper with", row.Name)
		}
		if err := VerifyBuilderSigned(tampered, pub); !errors.Is(err, ErrBuilderSignature) {
			t.Fatalf("%s: tampered err = %v, want ErrBuilderSignature", row.Name, err)
		}
		if err := VerifyBuilderSigned(msg, otherKey); !errors.Is(err, ErrBuilderSignature) {
			t.Fatalf("%s: other key err = %v, want ErrBuilderSignature", row.Name, err)
		}
		unsigned := proto.Clone(msg)
		unsigned.ProtoReflect().Clear(unsigned.ProtoReflect().Descriptor().Fields().ByName(builderSignatureField))
		if err := VerifyBuilderSigned(unsigned, pub); !errors.Is(err, ErrBuilderSignature) {
			t.Fatalf("%s: unsigned err = %v, want ErrBuilderSignature", row.Name, err)
		}
		verified[row.MessageName] = true
	}
	for _, name := range builderSignedNames {
		if !verified[name] {
			t.Fatalf("no vector exercised %s", name)
		}
	}
}

// A duplicated singular field is accepted by proto.Unmarshal (last wins) but
// is not what the Builder signed; the raw path must refuse it.
func TestVerifyBuilderSignedRawRejectsDuplicatedField(t *testing.T) {
	rows, err := wirevectors.DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, row := range rows {
		msg := newMessage(t, row.MessageName)
		sigNumber, err := builderSignatureNumber(msg.ProtoReflect().Descriptor())
		if err != nil {
			continue // not Builder-signed; covered above
		}
		raw := mustHex(t, row.ProtobufHex)
		num, _, n := protowire.ConsumeField(raw)
		if n < 0 || num == sigNumber {
			t.Fatalf("%s: unexpected first field %d (%d)", row.Name, num, n)
		}
		dup := append(append([]byte(nil), raw...), raw[:n]...)
		if err := proto.Unmarshal(dup, msg); err != nil {
			t.Fatalf("%s: proto.Unmarshal refused the duplicate, test premise broken: %v", row.Name, err)
		}
		err = VerifyBuilderSignedRaw(row.MessageName, dup, mustHex(t, row.PublicKeyHex))
		if !errors.Is(err, dispatch.ErrDecode) {
			t.Fatalf("%s: duplicated field err = %v, want dispatch.ErrDecode", row.Name, err)
		}
		checked++
	}
	if checked != len(builderSignedNames)+1 { // + open_verify_conflicting_output
		t.Fatalf("checked %d Builder-signed rows", checked)
	}
}

func TestVerifyBuilderSignedRefusesUnknownOrNil(t *testing.T) {
	if err := VerifyBuilderSigned(nil, nil); !errors.Is(err, ErrNotBuilderSigned) {
		t.Fatalf("nil message: %v", err)
	}
	if err := VerifyBuilderSignedRaw("task.v1.NoSuchMessageV1", nil, nil); !errors.Is(err, ErrNotBuilderSigned) {
		t.Fatalf("unknown message: %v", err)
	}
}
