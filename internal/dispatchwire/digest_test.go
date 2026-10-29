package dispatchwire

import (
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/TrueOpen/cortex/internal/wirevectors"
	_ "github.com/TrueOpen/cortex/proto/nexus/v1"
	_ "github.com/TrueOpen/cortex/proto/task/v1"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return out
}

func newMessage(t *testing.T, fullName string) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(fullName))
	if err != nil {
		t.Fatalf("%s not in generated bindings: %v", fullName, err)
	}
	return mt.New().Interface()
}

// vectorMessage decodes a vector row into its generated type.
func vectorMessage(t *testing.T, row wirevectors.DispatchVector) proto.Message {
	t.Helper()
	msg := newMessage(t, row.MessageName)
	if err := proto.Unmarshal(mustHex(t, row.ProtobufHex), msg); err != nil {
		t.Fatalf("%s: %v", row.Name, err)
	}
	return msg
}

func vectorByName(t *testing.T, name string) wirevectors.DispatchVector {
	t.Helper()
	row, err := wirevectors.DispatchVectorByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// Every message row is checked; none is skipped.
func TestDigestMatchesWireVectors(t *testing.T) {
	rows, err := wirevectors.DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.DigestHex == "" {
			t.Fatalf("%s publishes no digest", row.Name)
		}
		msg := vectorMessage(t, row)
		if Name(msg) != row.MessageName {
			t.Fatalf("%s: name %s, want %s", row.Name, Name(msg), row.MessageName)
		}
		// Re-encoding is not compared byte for byte: wire's fixture places a
		// trailing signature after a higher-numbered field (for example
		// DispatchInputRequestV1 writes 6 before 5), while Go marshals in
		// field-number order. The signing projection is order-independent, so
		// the digest below is the contract.
		got, err := Digest(msg)
		if err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		if hex.EncodeToString(got[:]) != row.DigestHex {
			t.Fatalf("%s: digest %x, want %s", row.Name, got, row.DigestHex)
		}
	}
	// wire 916e393 publishes exactly 19 message rows; a change in that count
	// is a fixture change this test must be revisited for.
	if len(rows) != 19 {
		t.Fatalf("%d message vectors checked, want 19", len(rows))
	}
}

func protoBytes(b []byte) protoreflect.Value { return protoreflect.ValueOfBytes(b) }
