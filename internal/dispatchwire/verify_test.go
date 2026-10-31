package dispatchwire

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

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

// withoutField re-encodes raw with every occurrence of field num dropped.
func withoutField(t *testing.T, raw []byte, num protowire.Number) []byte {
	t.Helper()
	var out []byte
	for b := raw; len(b) > 0; {
		n, _, l := protowire.ConsumeField(b)
		if l < 0 {
			t.Fatalf("malformed vector bytes: %v", protowire.ParseError(l))
		}
		if n != num {
			out = append(out, b[:l]...)
		}
		b = b[l:]
	}
	return out
}

// Byte-level attacks on Builder-signed raw input. Each mutated encoding is one
// proto.Unmarshal accepts, yet it is not what the Builder signed: the raw path
// must refuse it, with a strict-decode error where the shape is illegal and a
// signature error where the shape is legal but the signature is missing.
func TestVerifyBuilderSignedRawRejectsSignatureFieldAttacks(t *testing.T) {
	rows, err := wirevectors.DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	attacks := []struct {
		name   string
		mutate func(t *testing.T, raw []byte, sigNumber protowire.Number) []byte
		want   error
	}{
		{"duplicated first field", func(t *testing.T, raw []byte, sigNumber protowire.Number) []byte {
			num, _, n := protowire.ConsumeField(raw)
			if n < 0 || num == sigNumber {
				t.Fatalf("unexpected first field %d (%d)", num, n)
			}
			return append(append([]byte(nil), raw...), raw[:n]...)
		}, dispatch.ErrDecode},
		{"second signature field", func(_ *testing.T, raw []byte, sigNumber protowire.Number) []byte {
			out := append([]byte(nil), raw...)
			out = protowire.AppendTag(out, sigNumber, protowire.BytesType)
			return protowire.AppendBytes(out, bytes.Repeat([]byte{0x5a}, 64))
		}, dispatch.ErrDecode},
		{"signature as varint", func(_ *testing.T, raw []byte, sigNumber protowire.Number) []byte {
			out := append([]byte(nil), raw...)
			out = protowire.AppendTag(out, sigNumber, protowire.VarintType)
			return protowire.AppendVarint(out, 7)
		}, dispatch.ErrDecode},
		{"signature removed", func(t *testing.T, raw []byte, sigNumber protowire.Number) []byte {
			out := withoutField(t, raw, sigNumber)
			if len(out) == len(raw) {
				t.Fatal("vector carries no signature field to remove")
			}
			return out
		}, ErrBuilderSignature},
	}

	builderNames := map[string]bool{}
	for _, name := range builderSignedNames {
		builderNames[name] = true
	}
	wantRows, checked := 0, 0
	for _, row := range rows {
		if builderNames[row.MessageName] {
			wantRows++
		}
		msg := newMessage(t, row.MessageName)
		sigNumber, err := builderSignatureNumber(msg.ProtoReflect().Descriptor())
		if err != nil {
			continue // not Builder-signed; covered in TestVerifyBuilderSignedVectors
		}
		raw := mustHex(t, row.ProtobufHex)
		pub := mustHex(t, row.PublicKeyHex)
		for _, a := range attacks {
			t.Run(row.Name+"/"+a.name, func(t *testing.T) {
				mutated := a.mutate(t, raw, sigNumber)
				if err := proto.Unmarshal(mutated, newMessage(t, row.MessageName)); err != nil {
					t.Fatalf("proto.Unmarshal refused the attack, test premise broken: %v", err)
				}
				if err := VerifyBuilderSignedRaw(row.MessageName, mutated, pub); !errors.Is(err, a.want) {
					t.Fatalf("err = %v, want %v", err, a.want)
				}
			})
		}
		checked++
	}
	if checked == 0 || checked != wantRows {
		t.Fatalf("attacked %d Builder-signed rows, the vectors hold %d", checked, wantRows)
	}
}

// builderSignatureNumber refuses a builder_service_signature that is not a
// singular bytes field.
func TestBuilderSignatureNumberRefusesWrongShape(t *testing.T) {
	for name, field := range map[string]*descriptorpb.FieldDescriptorProto{
		"uint64": {
			Name: proto.String(builderSignatureField), Number: proto.Int32(1),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:  descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum(),
		},
		"repeated bytes": {
			Name: proto.String(builderSignatureField), Number: proto.Int32(1),
			Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
			Type:  descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
				Name:        proto.String("dispatchwire_test/" + strings.ReplaceAll(name, " ", "_") + ".proto"),
				Package:     proto.String("dispatchwiretest"),
				Syntax:      proto.String("proto3"),
				MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Fake"), Field: []*descriptorpb.FieldDescriptorProto{field}}},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := builderSignatureNumber(fd.Messages().Get(0)); !errors.Is(err, ErrNotBuilderSigned) {
				t.Fatalf("err = %v, want ErrNotBuilderSigned", err)
			}
		})
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
