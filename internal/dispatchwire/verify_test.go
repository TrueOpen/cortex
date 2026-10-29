package dispatchwire

import (
	"testing"

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
	name := string(f.Name())
	return len(name) >= len("signature") && name[len(name)-len("signature"):] == "signature"
}

func TestVerifyBuilderSignedVectors(t *testing.T) {
	rows, err := wirevectors.DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	verified := map[string]bool{}
	for _, row := range rows {
		msg := vectorMessage(t, row)
		pub := mustHex(t, row.PublicKeyHex)
		if msg.ProtoReflect().Descriptor().Fields().ByName(builderSignatureField) == nil {
			// Cortex-signed or unsigned: must be refused, not silently passed.
			if err := VerifyBuilderSigned(msg, pub); err == nil {
				t.Fatalf("%s: non-Builder message accepted as Builder-signed", row.Name)
			}
			continue
		}
		if row.SignatureHex == "" {
			t.Fatalf("%s: Builder-signed vector publishes no signature", row.Name)
		}
		if err := VerifyBuilderSigned(msg, pub); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		tampered := proto.Clone(msg)
		if !mutateFirstBytesField(tampered) {
			t.Fatalf("%s: no bytes field to tamper with", row.Name)
		}
		if err := VerifyBuilderSigned(tampered, pub); err == nil {
			t.Fatalf("%s: tampered message verified", row.Name)
		}
		if err := VerifyBuilderSigned(msg, pubKey(t, "1111111111111111111111111111111111111111111111111111111111111111")); err == nil {
			t.Fatalf("%s: verified under a different Builder key", row.Name)
		}
		unsigned := proto.Clone(msg)
		unsigned.ProtoReflect().Clear(unsigned.ProtoReflect().Descriptor().Fields().ByName(builderSignatureField))
		if err := VerifyBuilderSigned(unsigned, pub); err == nil {
			t.Fatalf("%s: unsigned message verified", row.Name)
		}
		verified[row.MessageName] = true
	}
	// The nine Builder-signed message types wire 916e393 publishes.
	for _, name := range []string{
		"task.v1.DispatchTicketV1", "task.v1.SignedHandraiseRootV1", "task.v1.DispatchRecordV1",
		"nexus.v1.DispatchInputResponseV1", "nexus.v1.DispatchRevokeV1", "nexus.v1.RecordResultNoticeV1",
		"nexus.v1.DispatchResultHeaderV1", "nexus.v1.OpenVerifyV1", "nexus.v1.VerifierAssignmentNotifyV1",
	} {
		if !verified[name] {
			t.Fatalf("no vector exercised %s", name)
		}
	}
}
