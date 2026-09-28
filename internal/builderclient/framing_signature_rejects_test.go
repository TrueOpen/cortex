package builderclient

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// TestSignatureRejectVectors applies each of wire's named signature_rejects
// mutations and requires the service-signature path (hex decoding, then the
// compact R||S scalar checks) to refuse the result, while the unmutated
// signatures pass.
func TestSignatureRejectVectors(t *testing.T) {
	raw, err := wirevectors.File("shared/framing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Signatures []struct {
			Name         string `json:"name"`
			SignatureHex string `json:"signature_hex"`
		} `json:"signature_v1"`
		Rejects []struct {
			Name     string `json:"name"`
			From     string `json:"from"`
			Mutation string `json:"mutation"`
		} `json:"signature_rejects"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	accepts := func(text string) bool {
		signature, ok := decodeCanonicalTaskDataSignature(text)
		return ok && validateCompactSignature(signature) == nil
	}
	signatures := map[string]string{}
	for _, vector := range fixture.Signatures {
		if !accepts(vector.SignatureHex) {
			t.Fatalf("%s: the published signature is refused", vector.Name)
		}
		signatures[vector.Name] = vector.SignatureHex
	}
	rawOf := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	mutations := map[string]func(string) string{
		"uppercase_hex":                strings.ToUpper,
		"prepend_space":                func(s string) string { return " " + s },
		"append_space":                 func(s string) string { return s + " " },
		"append_zero_byte":             func(s string) string { return s + "00" },
		"prepend_recovery_byte":        func(s string) string { return "1b" + s },
		"drop_last_byte":               func(s string) string { return s[:len(s)-2] },
		"drop_last_hex_char":           func(s string) string { return s[:len(s)-1] },
		"replace_last_hex_char_with_z": func(s string) string { return s[:len(s)-1] + "z" },
		"negate_s": func(s string) string {
			signature := rawOf(s)
			var scalar secp256k1.ModNScalar
			scalar.SetByteSlice(signature[32:])
			scalar.Negate()
			negated := scalar.Bytes()
			return hex.EncodeToString(append(signature[:32:32], negated[:]...))
		},
		"zero_r": func(s string) string { return strings.Repeat("0", 64) + s[64:] },
		"zero_s": func(s string) string { return s[:64] + strings.Repeat("0", 64) },
	}
	if len(fixture.Rejects) == 0 {
		t.Fatal("framing fixture publishes no signature rejects")
	}
	for _, reject := range fixture.Rejects {
		mutate, ok := mutations[reject.Mutation]
		base, found := signatures[reject.From]
		if !ok || !found {
			t.Fatalf("%s: unknown mutation %q or base %q", reject.Name, reject.Mutation, reject.From)
		}
		if accepts(mutate(base)) {
			t.Errorf("%s: the mutated signature was accepted", reject.Name)
		}
	}
}
