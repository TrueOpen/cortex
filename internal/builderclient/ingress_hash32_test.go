package builderclient

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

const bareHash32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// A Hash32 carried as a string on the IngressAPI is "0x" followed by 64
// lowercase hex characters. Everywhere else in this node the same value stays
// bare: it is a store key and an input to signature
// preimages, none of which wire respelled. So the prefix belongs at the
// boundary and nowhere else, which is what these tests hold in place.

func TestIngressHash32AddsAndRemovesThePrefix(t *testing.T) {
	wire := ToIngressHash32(bareHash32)
	if wire != "0x"+bareHash32 {
		t.Fatalf("toIngressHash32 = %q, want the 0x spelling", wire)
	}
	back, ok := FromIngressHash32(wire)
	if !ok || back != bareHash32 {
		t.Fatalf("FromIngressHash32(%q) = %q, %v; want the bare spelling", wire, back, ok)
	}
}

// An unset field has to stay unset. Several of these fields are optional --
// content_hash is empty for an object identified by its ref alone -- and
// turning "" into "0x" would make an absent value look present and malformed.
func TestIngressHash32LeavesAnUnsetFieldUnset(t *testing.T) {
	if got := ToIngressHash32(""); got != "" {
		t.Fatalf("ToIngressHash32(\"\") = %q, want it left unset", got)
	}
	if got, ok := FromIngressHash32(""); !ok || got != "" {
		t.Fatalf("FromIngressHash32(\"\") = %q, %v; want it left unset", got, ok)
	}
}

// The reader is the half that meets another implementation's output, so it
// refuses anything but the one spelling rather than guessing.
func TestIngressHash32RefusesEverySpellingButOne(t *testing.T) {
	for name, value := range map[string]string{
		"bare hex":        bareHash32,
		"uppercase hex":   "0x" + strings.ToUpper(bareHash32),
		"uppercase 0X":    "0X" + bareHash32,
		"short":           "0x" + bareHash32[:62],
		"long":            "0x" + bareHash32 + "ff",
		"prefix only":     "0x",
		"not hex":         "0x" + strings.Repeat("g", 64),
		"double prefixed": "0x0x" + bareHash32[:62],
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := FromIngressHash32(value); ok {
				t.Fatalf("FromIngressHash32(%q) = %q, true; want it refused", value, got)
			}
		})
	}
}

// TestTaskDataObjectRefCarriesThePrefixedSpelling is the request that failed on
// devnet: FetchTaskData answered NEXUS_DATA_MALFORMED because task_hash arrived
// bare. Every Hash32 string of the ref travels together, so they are checked
// together.
func TestTaskDataObjectRefCarriesThePrefixedSpelling(t *testing.T) {
	key := TaskDataKey{
		TaskHash: bareHash32, SessionID: bareHash32, TaskID: bareHash32,
		ContentHash: bareHash32, Kind: DataKindOutput,
	}
	wire := taskDataKeyToProto(key)
	for field, got := range map[string]string{
		"task_hash": wire.TaskHash, "session_id": wire.SessionId,
		"task_id": wire.TaskId, "content_hash": wire.ContentHash,
	} {
		if got != "0x"+bareHash32 {
			t.Fatalf("%s = %q, want the 0x spelling the IngressAPI requires", field, got)
		}
	}
	back, err := taskDataKeyFromProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if back != key {
		t.Fatalf("round trip = %#v, want the bare spelling restored: %#v", back, key)
	}
}

// TestRequestAuthBodyDigestCarriesThePrefixedSpelling covers the field the
// error message did not name. nexus converts body_digest through the same
// reader, so a request whose ref was fixed and whose auth was not fails one
// step later.
func TestRequestAuthBodyDigestCarriesThePrefixedSpelling(t *testing.T) {
	raw, err := hex.DecodeString(bareHash32)
	if err != nil {
		t.Fatal(err)
	}
	wire := taskDataRequestAuthToProto(TaskDataRequestAuth{BodyDigest: codec.Hash(raw)})
	if wire.BodyDigest != "0x"+bareHash32 {
		t.Fatalf("body_digest = %q, want the 0x spelling", wire.BodyDigest)
	}
}
