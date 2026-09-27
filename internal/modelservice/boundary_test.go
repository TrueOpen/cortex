package modelservice

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/metric"
)

func TestMaterialArtifactsRoundTripAndRefuseMalformedValues(t *testing.T) {
	ids := TokenIDs{Input: []uint32{1, 2}, Generated: []uint32{10, 0}}
	raw, err := EncodeTokenIDsArtifact(ids)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTokenIDsArtifact(raw)
	if err != nil || !reflect.DeepEqual(got, ids) {
		t.Fatalf("token ids round trip = %+v, %v", got, err)
	}
	values := []metric.PositionValue{
		{TokenID: 10, Logprob: -0.5, Rank: 1, TopK: []metric.TokenLogprob{{TokenID: 10, Logprob: -0.5}, {TokenID: 3, Logprob: -2}}},
		{TokenID: 0, Missing: true},
	}
	raw, err = EncodePositionValuesArtifact(values)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePositionValuesArtifact(raw)
	if err != nil || len(decoded) != 2 || decoded[0].TopK[1].TokenID != 3 || !decoded[1].Missing {
		t.Fatalf("position values round trip = %+v, %v", decoded, err)
	}
	// A top-k that repeats a token cannot be framed as a leaf.
	values[0].TopK[1].TokenID = 10
	raw, err = EncodePositionValuesArtifact(values)
	if err == nil {
		if _, err := DecodePositionValuesArtifact(raw); err == nil {
			t.Fatal("a top-k that repeats a token was accepted")
		}
	}
}

func TestValidateGenerationMaterialBindsValuesToGeneratedTokens(t *testing.T) {
	g := localTestGeneration(testQwenModelID(), 1)
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ids := TokenIDs{Input: []uint32{1}, Generated: []uint32{10, 11}}
	values := []metric.PositionValue{{TokenID: 10, Logprob: -0.1, Rank: 1}, {TokenID: 11, Logprob: -0.2, Rank: 1}}
	if count, err := ValidateGenerationMaterial(g, digest[:], ids, values); err != nil || count != 2 {
		t.Fatalf("ValidateGenerationMaterial = %d, %v", count, err)
	}
	if _, err := ValidateGenerationMaterial(g, digest[:], ids, values[:1]); err == nil {
		t.Fatal("a missing position value was accepted")
	}
	swapped := []metric.PositionValue{values[1], values[0]}
	if _, err := ValidateGenerationMaterial(g, digest[:], ids, swapped); err == nil {
		t.Fatal("a value measured for another token was accepted")
	}
}

// A /v1/completions top_logprobs object is read in the engine's own key order
// and never re-sorted; a row that is not exactly required_top_k distinct ids
// with non-increasing logprobs is refused.
func TestCompletionTopKKeepsTheEngineOrder(t *testing.T) {
	var row TopLogprobRow
	if err := json.Unmarshal([]byte(`{"token_id:9":-0.5,"token_id:4":-0.5,"token_id:2":-1,"token_id:7":-3}`), &row); err != nil {
		t.Fatal(err)
	}
	topK, err := completionTopK(0, row, 4)
	if err != nil {
		t.Fatal(err)
	}
	var order []uint32
	for _, entry := range topK {
		order = append(order, entry.TokenID)
	}
	if !reflect.DeepEqual(order, []uint32{9, 4, 2, 7}) {
		t.Fatalf("order = %v, want the engine's key order [9 4 2 7]", order)
	}
	if rankIn(2, topK) != 3 || rankIn(8, topK) != 0 {
		t.Fatal("rankIn does not read the engine-ordered list")
	}
	encoded, err := json.Marshal(row)
	if err != nil || string(encoded) != `{"token_id:9":-0.5,"token_id:4":-0.5,"token_id:2":-1,"token_id:7":-3}` {
		t.Fatalf("row re-encodes as %s, %v", encoded, err)
	}
	for name, bad := range map[string]TopLogprobRow{
		"too few":      {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -3}},
		"too many":     {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -3}, {"token_id:4", -4}, {"token_id:5", -5}},
		"duplicate":    {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:1", -3}, {"token_id:4", -4}},
		"out of order": {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -0.5}, {"token_id:4", -4}},
		"text key":     {{"hello", -1}, {"token_id:2", -2}, {"token_id:3", -3}, {"token_id:4", -4}},
	} {
		if _, err := completionTopK(0, bad, 4); err == nil {
			t.Fatalf("%s row was accepted", name)
		}
	}
}

func TestPromptTopKKeepsTheEngineRankOrder(t *testing.T) {
	topK, _, err := promptTopK(0, map[string]logprobEntry{"5": {Logprob: -1, Rank: 2}, "6": {Logprob: -1.5, Rank: 1}, "7": {Logprob: -0.1, Rank: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if topK[0].TokenID != 6 || topK[1].TokenID != 5 || topK[2].TokenID != 7 {
		t.Fatalf("prompt top-k = %+v, want the engine's rank order", topK)
	}
}

// Infer returns the token-id and position-value material, and every request
// asks the engine for token ids rather than token text.
func TestLocalInferReturnsTokenIDAndPositionValueMaterial(t *testing.T) {
	generated := genResponse()
	generated.Choices[0].Logprobs.TopLogprobs = []TopLogprobRow{
		fullTopRow(TopLogprob{"token_id:10", -0.1}, TopLogprob{"token_id:12", -2}),
		fullTopRow(TopLogprob{"token_id:13", -0.05}, TopLogprob{"token_id:11", -0.2}),
	}
	srv, seen := newVLLMStub(t, generated, verifyResponse())
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false)
	resp, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID: "infer-material", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range *seen {
		if !request.ReturnTokensAsTokenIDs {
			t.Fatal("an engine request did not set return_tokens_as_token_ids")
		}
	}
	tokenArtifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TokenIDsRef})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := DecodeTokenIDsArtifact(tokenArtifact.Data)
	if err != nil || !reflect.DeepEqual(ids.Input, []uint32{1, 2, 3}) || !reflect.DeepEqual(ids.Generated, []uint32{10, 11}) {
		t.Fatalf("token ids = %+v, %v", ids, err)
	}
	valueArtifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.PositionValuesRef})
	if err != nil {
		t.Fatal(err)
	}
	values, err := DecodePositionValuesArtifact(valueArtifact.Data)
	if err != nil || len(values) != 2 {
		t.Fatalf("position values = %+v, %v", values, err)
	}
	// Position 1 emitted token 11, which the engine ranked second.
	if values[1].TokenID != 11 || values[1].Rank != 2 || values[1].TopK[0].TokenID != 13 {
		t.Fatalf("position 1 = %+v, want token 11 at rank 2 behind 13", values[1])
	}
}

// Verify prefills the Worker's token ids only and returns this node's values.
func TestLocalVerifyScoresTheWorkerTokenIDs(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	resp, err := svc.Verify(context.Background(), boundLocalVerifyFixture(t, VerifyRequest{
		RequestID: "verify-material", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Sample: []byte("seed"), TokenIDs: TokenIDs{Input: []uint32{1, 2, 3}, Generated: []uint32{10, 11}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.VerifierValues) != 2 || resp.VerifierValues[0].TokenID != 10 || resp.VerifierValues[1].Logprob != -0.2 || resp.VerifierValues[1].Rank != 1 {
		t.Fatalf("verifier values = %+v", resp.VerifierValues)
	}
	last := (*seen)[len(*seen)-1]
	prompt, _ := json.Marshal(last.Prompt)
	if !last.ReturnTokensAsTokenIDs || string(prompt) != "[1,2,3,10,11]" {
		t.Fatalf("verify request prompt = %s, want the token ids", prompt)
	}
}
