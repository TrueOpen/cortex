package layout

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStoredHashMarshalRoundTrip(t *testing.T) {
	want := StoredHash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	got, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if want := "\"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\""; string(got) != want {
		t.Fatalf("Marshal = %s, want %s", got, want)
	}
	var round StoredHash
	if err := json.Unmarshal(got, &round); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if round != want {
		t.Fatalf("round trip = %x, want %x", round, want)
	}
}

func TestStoredHashUnmarshalRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "\"\"", "empty"},
		{"single char", "\"0\"", "64"},
		{"prefix only", "\"0x\"", "0x"},
		{"short", "\"0102\"", "64"},
		{"long", "\"" + strings.Repeat("00", 33) + "\"", "64"},
		{"odd length", "\"" + strings.Repeat("0", 63) + "\"", "64"},
		{"uppercase", "\"" + strings.Repeat("AB", 32) + "\"", "lowercase"},
		{"prefix 0x", "\"0x" + strings.Repeat("00", 32) + "\"", "0x"},
		{"null", "null", "empty"},
		{"number", "123", "64"},
		{"boolean", "true", "64"},
		{"array too short", "[1,2,3]", "exactly 32 bytes"},
		{"array too long", "[" + strings.Repeat("0,", 33) + "0]", "exactly 32 bytes"},
		{"trailing content", "\"" + strings.Repeat("00", 32) + "extra\"", "64"},
		{"invalid hex", "\"" + strings.Repeat("00", 31) + "gg\"", "valid hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h StoredHash
			err := json.Unmarshal([]byte(tc.input), &h)
			if err == nil {
				t.Fatalf("Unmarshal(%q) = nil, want error containing %q", tc.input, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Unmarshal(%q) error = %q, want containing %q", tc.input, err.Error(), tc.want)
			}
		})
	}
}

func TestStoredHashUnmarshalLeavesReceiverUnchangedOnError(t *testing.T) {
	original := StoredHash{0x01}
	h := original
	if err := json.Unmarshal([]byte("\"GG\""), &h); err == nil {
		t.Fatal("expected error")
	}
	if h != original {
		t.Fatalf("receiver mutated on error: %x", h)
	}
}

func TestStoredHashUnmarshalLegacyArray(t *testing.T) {
	input := "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]"
	var h StoredHash
	if err := json.Unmarshal([]byte(input), &h); err != nil {
		t.Fatalf("Unmarshal legacy array error = %v", err)
	}
	for i := 0; i < 32; i++ {
		if h[i] != byte(i+1) {
			t.Fatalf("legacy byte %d = %d, want %d", i, h[i], i+1)
		}
	}
}

func TestStoredHashZeroValue(t *testing.T) {
	var h StoredHash
	if !h.IsZero() {
		t.Fatal("zero StoredHash.IsZero() = false")
	}
	h[0] = 1
	if h.IsZero() {
		t.Fatal("non-zero StoredHash.IsZero() = true")
	}
}
