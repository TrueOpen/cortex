package nodewire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The local V2 regression fixture separates the canonical task hash from the
// SHA-256 identity of its transport carrier.
func TestAcceptedTaskHashDiffersFromAssignmentOrderDigest(t *testing.T) {
	var fixture struct {
		OrderEnvelopeBase64   string `json:"order_envelope_base64"`
		AcceptedTaskHash      string `json:"accepted_task_hash"`
		AssignmentOrderDigest string `json:"assignment_order_digest"`
	}
	data, err := os.ReadFile("testdata/accepted_task_hash_golden.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode golden fixture: %v", err)
	}

	envelope, err := base64.StdEncoding.DecodeString(fixture.OrderEnvelopeBase64)
	if err != nil {
		t.Fatalf("decode order envelope: %v", err)
	}

	accepted, err := TaskOrderHashJSON(string(envelope))
	if err != nil {
		t.Fatalf("TaskOrderHashJSON: %v", err)
	}
	if got := hex.EncodeToString(accepted[:]); got != fixture.AcceptedTaskHash {
		t.Fatalf("accepted task hash = %s, want %s", got, fixture.AcceptedTaskHash)
	}

	orderDigest := sha256.Sum256(envelope)
	if got := hex.EncodeToString(orderDigest[:]); got != fixture.AssignmentOrderDigest {
		t.Fatalf("assignment order digest = %s, want %s", got, fixture.AssignmentOrderDigest)
	}

	if fixture.AcceptedTaskHash == fixture.AssignmentOrderDigest {
		t.Fatal("accepted task hash equals assignment order digest")
	}
}
