package chainclient

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
)

// The text form of a Hash32 is a coupling between three places that do not
// reference each other, and wire is moving it: TrueOpen/wire#44 respells the
// REST projection and the Nexus ingress as "0x" followed by 64 lowercase hex,
// while leaving preimages and stored hex alone.
//
// Cortex keeps its own copy of the REST spelling -- restProtoJSON renders a
// Keeper protobuf response the way the projection does, so the typed snapshots
// can read a model id as text without a second decoder. Adopting the new
// spelling therefore means editing cortex, and the edit is one line.
//
// These tests exist so that the line cannot be changed alone. The decoder tells
// the two forms apart by length, and the model id is carried as bare text into
// places wire is deliberately NOT respelling, so a respelled encoder either
// stops decoding or silently keys on a value nothing else produces.

const hash32TestHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// TestKeeperRESTSpellingIsBareHex pins what cortex produces. It is the half of
// the coupling wire#44 changes, and it is the only line that has to change here.
func TestKeeperRESTSpellingIsBareHex(t *testing.T) {
	raw, err := hex.DecodeString(hash32TestHex)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := restProtoJSON(&hubv1.QueryModelRequest{ModelId: raw})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"`+hash32TestHex+`"`) {
		t.Fatalf("Keeper REST JSON = %s, want the bare spelling this decoder still expects", encoded)
	}
}

// TestHash32TextIsReadAsBareHexAndRefusesThePrefixedForm pins what cortex
// consumes. The two forms are told apart by length -- 64 hex characters against
// 44 of base64 -- and "0x" plus 64 is 66, which is neither. A respelled encoder
// without a respelled decoder therefore fails at the first Keeper read rather
// than producing a wrong value, which is the good half of this coupling.
func TestHash32TextIsReadAsBareHexAndRefusesThePrefixedForm(t *testing.T) {
	var value ProtoBytes32
	if err := json.Unmarshal([]byte(`"`+hash32TestHex+`"`), &value); err != nil {
		t.Fatalf("the bare spelling is what restProtoJSON writes: %v", err)
	}
	if value.Hex() != hash32TestHex {
		t.Fatalf("value = %q, want %q", value.Hex(), hash32TestHex)
	}
	var prefixed ProtoBytes32
	if err := json.Unmarshal([]byte(`"0x`+hash32TestHex+`"`), &prefixed); err == nil {
		t.Fatalf("the 0x spelling decoded to %q; adopting wire#44 means teaching this decoder, not only the encoder", prefixed.Hex())
	}
}

// TestModelIDKeepsTheSubjectSpelling is the half that fails quietly. A model id
// read as text goes straight into trueopen.task.open.<model_id>, and wire#44
// leaves subjects bare on purpose, so an id carrying "0x" would have a node
// subscribe to a subject no Builder publishes to -- no error, no task, nothing
// in the log to say why.
func TestModelIDKeepsTheSubjectSpelling(t *testing.T) {
	var modelID ProtoBytes32
	if err := json.Unmarshal([]byte(`"`+hash32TestHex+`"`), &modelID); err != nil {
		t.Fatal(err)
	}
	subject := "trueopen.task.open." + modelID.Hex()
	if strings.Contains(subject, "0x") {
		t.Fatalf("subject = %q, want the bare model id a Builder publishes to", subject)
	}
	if want := "trueopen.task.open." + hash32TestHex; subject != want {
		t.Fatalf("subject = %q, want %q", subject, want)
	}
}
