package modelservice

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestTokenIDArtifactsUseProtocolRawCountVector(t *testing.T) {
	env := traceEnvelope{InputTokenIDs: []int{1, 4294967295}, OutTokens: []tokenLogprob{{TokenID: 7}}, GeneratedTokenCount: 1}
	env.InputTokenIDsHash = hashTokenIDs(env.InputTokenIDs)
	env.GeneratedTokenIDsHash = hashGeneratedTokenIDs(env.OutTokens)
	trace, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	input, generated, err := TokenIDArtifacts(trace, trace)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(input) != "0000000200000001ffffffff" || hex.EncodeToString(generated) != "0000000100000007" {
		t.Fatalf("unexpected raw vectors: %x/%x", input, generated)
	}
	if err := ValidateTokenIDArtifacts(trace, trace, input, generated); err != nil {
		t.Fatal(err)
	}
	generated[len(generated)-1] ^= 1
	if err := ValidateTokenIDArtifacts(trace, trace, input, generated); err == nil {
		t.Fatal("token artifact tampering was accepted")
	}
	for _, mutate := range []func(*traceEnvelope){func(e *traceEnvelope) { e.InputTokenIDs = []int{-1} }, func(e *traceEnvelope) { e.OutTokens[0].TokenID = -1 }, func(e *traceEnvelope) { e.GeneratedTokenCount = 2 }} {
		var changed traceEnvelope
		if err := json.Unmarshal(trace, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		payload, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := TokenIDArtifacts(payload, payload); err == nil {
			t.Fatal("invalid token sequence was accepted")
		}
	}
}
