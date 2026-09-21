package codec

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestHashLegacyJSONEncodingRoundTrips verifies that codec.Hash marshals to the
// legacy 32-element JSON number array that pre-cutover storage used, and that
// such an array can be unmarshalled back. This gives #222 genuine pre-cutover
// bytes to test against instead of synthesised hashes.
func TestHashLegacyJSONEncodingRoundTrips(t *testing.T) {
	h := HashBytes([]byte("pre-cutover fixture payload"))

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal Hash: %v", err)
	}

	// The legacy encoding is exactly 32 decimal byte values inside an array.
	var numbers []uint8
	if err := json.Unmarshal(data, &numbers); err != nil {
		t.Fatalf("unmarshal legacy hash array: %v", err)
	}
	if len(numbers) != 32 {
		t.Fatalf("legacy hash length = %d, want 32", len(numbers))
	}
	var decoded Hash
	copy(decoded[:], numbers)
	if decoded != h {
		t.Fatalf("decoded hash %v != original %v", decoded, h)
	}

	// Verify the raw JSON shape for a known fixture: no hex string, no object.
	if data[0] != '[' || data[len(data)-1] != ']' {
		t.Fatalf("legacy hash JSON should be an array, got %s", string(data))
	}
	if bytes.Contains(data, []byte("\"")) {
		t.Fatalf("legacy hash JSON should not contain string quotes")
	}
}
