package modelservice

import (
	"context"
	"encoding/json"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

// vLLM writes the sampled token first, not in rank order, so completionTopK
// sorts the row by logprob (stable for ties) before it becomes evidence. A row
// that is not K (or K plus the appended emitted token) distinct, non-NaN ids is
// refused.
func TestCompletionTopKSortsByLogprob(t *testing.T) {
	// The sampled token 2 leads the object (as vLLM writes it) but is only the
	// third most likely; sorting must move it to rank 3.
	var row TopLogprobRow
	if err := json.Unmarshal([]byte(`{"token_id:2":-1,"token_id:9":-0.5,"token_id:4":-0.5,"token_id:7":-3}`), &row); err != nil {
		t.Fatal(err)
	}
	topK, err := completionTopK(0, 2, row, 4)
	if err != nil {
		t.Fatal(err)
	}
	var order []uint32
	for _, entry := range topK {
		order = append(order, entry.TokenID)
	}
	// 9 and 4 tie at -0.5; the stable sort keeps the engine's order (9 before 4).
	if !reflect.DeepEqual(order, []uint32{9, 4, 2, 7}) {
		t.Fatalf("order = %v, want logprob-sorted [9 4 2 7]", order)
	}
	if rankIn(2, topK) != 3 || rankIn(8, topK) != 0 {
		t.Fatalf("emitted rank = %d, want 3 (its logprob rank, not its leading position)", rankIn(2, topK))
	}
	for name, bad := range map[string]TopLogprobRow{
		"too few":   {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -3}},
		"two extra": {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -3}, {"token_id:4", -4}, {"token_id:5", -5}, {"token_id:6", -6}},
		"duplicate": {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:1", -3}, {"token_id:4", -4}},
		"nan":       {{"token_id:1", -1}, {"token_id:2", math.NaN()}, {"token_id:3", -3}, {"token_id:4", -4}},
		"text key":  {{"hello", -1}, {"token_id:2", -2}, {"token_id:3", -3}, {"token_id:4", -4}},
		// K+1 entries are only legal when the extra one is the emitted token that
		// fell outside a top-k not holding it.
		"extra is not the emitted token": {{"token_id:1", -1}, {"token_id:2", -2}, {"token_id:3", -3}, {"token_id:4", -4}, {"token_id:5", -5}},
		"emitted both in and after":      {{"token_id:1", -1}, {"token_id:9", -2}, {"token_id:3", -3}, {"token_id:4", -4}, {"token_id:9", -2}},
	} {
		if _, err := completionTopK(0, 9, bad, 4); err == nil {
			t.Fatalf("%s row was accepted", name)
		}
	}
}

// With sampling on, the emitted token can fall outside the top-k; vLLM then
// includes it as entry K+1, written first. After sorting by logprob that entry
// is the lowest, it is dropped, the K highest are kept, and the emitted token's
// leaf rank is 0.
func TestCompletionTopKDropsTheAppendedSampledToken(t *testing.T) {
	// The sampled token 9 leads the row (vLLM's placement) but has the lowest logprob.
	row := TopLogprobRow{{"token_id:9", -4.2}, {"token_id:1", -0.1}, {"token_id:2", -0.9}, {"token_id:3", -1.5}, {"token_id:4", -2}}
	topK, err := completionTopK(3, 9, row, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(topK) != 4 || topK[3].TokenID != 4 || rankIn(9, topK) != 0 {
		t.Fatalf("top-k = %+v, want the four highest logprobs and the sampled token unranked", topK)
	}
	leaves, err := metric.ValueLeaves([]metric.PositionValue{{TokenID: 9, Logprob: -4.2, Rank: rankIn(9, topK), TopK: topK}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !leaves[0].Finite || leaves[0].Missing || leaves[0].Rank != 0 || len(leaves[0].TopK) != 4 || leaves[0].LogprobFP1e6 != -4200000 {
		t.Fatalf("leaf = %+v, want a finite rank-0 leaf with four top-k entries", leaves[0])
	}
}

// A sampled generation in which vLLM reports no logprob for one position and
// no top-k for another yields missing values there, and the out-of-top-k
// sampled token at the last position keeps its logprob with rank 0.
func TestLocalSampledInferMarksPositionsWithoutValuesMissing(t *testing.T) {
	const k = 4
	// vLLM writes each object in rank order; a Go map would not, so the
	// response body is written by hand.
	body := `{"choices":[{"text":"abcd","finish_reason":"stop","prompt_token_ids":[1,2,3],"token_ids":[10,11,12,151645],` +
		`"logprobs":{"tokens":["token_id:10","token_id:11","token_id:12","token_id:151645"],"token_logprobs":[-0.1,null,-0.3,-3.5],` +
		`"top_logprobs":[` +
		`{"token_id:10":-0.1,"token_id:20":-0.2,"token_id:21":-0.3,"token_id:22":-0.4},` +
		`{"token_id:11":-0.1,"token_id:20":-0.2,"token_id:21":-0.3,"token_id:22":-0.4},` +
		`null,` +
		`{"token_id:30":-0.1,"token_id:31":-0.2,"token_id:32":-0.3,"token_id:33":-0.4,"token_id:151645":-3.5}]}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
			return
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["logprobs"] != float64(k) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
	svc.SetStreamInference(false)
	svc.SetOutputDecodingSource(testOutputDecodingSource())
	svc.SetProfileResolver(&countingProfileResolver{snapshot: liveLikeProfileSnapshotWithTopK(k)})
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.DecodingParams = nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 900, TopPPPM: 950000, Seed: 11, RepetitionPenaltyPPM: 1000000}
	resp, err := svc.Infer(context.Background(), localGenerationInfer(t, g))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.PositionValuesRef})
	if err != nil {
		t.Fatal(err)
	}
	values, err := DecodePositionValuesArtifact(artifact.Data)
	if err != nil {
		t.Fatal(err)
	}
	leaves, err := metric.ValueLeaves(values, k)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 4 || !leaves[0].Finite || leaves[0].Rank != 1 {
		t.Fatalf("leaf 0 = %+v, want a normal rank-1 value", leaves)
	}
	for _, i := range []int{1, 2} {
		if l := leaves[i]; !l.Missing || l.Finite || l.LogprobFP1e6 != 0 || l.Rank != 0 || len(l.TopK) != 0 {
			t.Fatalf("leaf %d = %+v, want a missing value", i, l)
		}
	}
	if l := leaves[3]; !l.Finite || l.Rank != 0 || l.LogprobFP1e6 != -3500000 || len(l.TopK) != k || l.TopK[0].TokenID != 30 {
		t.Fatalf("leaf 3 = %+v, want the sampled out-of-top-k token with rank 0 and the engine's top-k", l)
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

// A null token logprob keeps its position when streamed chunks are joined.
func TestStreamedNullLogprobKeepsItsPosition(t *testing.T) {
	var first, second completionLogprobs
	if err := json.Unmarshal([]byte(`{"token_logprobs":[-0.1,-0.2]}`), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"token_logprobs":[-0.3,null]}`), &second); err != nil {
		t.Fatal(err)
	}
	var joined completionLogprobs
	joined.appendFrom(&first)
	joined.appendFrom(&second)
	if len(joined.TokenLogprobs) != 4 {
		t.Fatalf("joined = %+v", joined)
	}
	for i, want := range []bool{false, false, false, true} {
		if joined.logprobAbsent(i) != want {
			t.Fatalf("position %d absent = %t, want %t", i, joined.logprobAbsent(i), want)
		}
	}
}

// Verify marks a position Missing when vLLM's prompt_logprobs stop short of it
// or do not score the Worker's token there, and asks vLLM for exactly the
// profile's required_top_k prompt logprobs.
func TestLocalVerifyMarksUnscoredPositionsMissing(t *testing.T) {
	short := verifyResponse()
	short.Choices[0].PromptLogprobs = short.Choices[0].PromptLogprobs[:4] // no row for the second generated token
	absent := verifyResponse()
	absent.Choices[0].PromptLogprobs[3] = map[string]logprobEntry{"99": {Logprob: -0.3, Rank: 1}} // token 10 not scored
	for name, verify := range map[string]completionResponse{"short prompt_logprobs": short, "scored token absent": absent} {
		t.Run(name, func(t *testing.T) {
			srv, seen := newVLLMStub(t, genResponse(), verify)
			svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
			svc.SetOutputDecodingSource(testOutputDecodingSource())
			svc.SetProfileResolver(&countingProfileResolver{snapshot: liveLikeProfileSnapshotWithTopK(7)})
			resp, err := svc.Verify(context.Background(), boundLocalVerifyFixture(t, VerifyRequest{
				RequestID: "verify-missing", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
				Sample: []byte("seed"), TokenIDs: TokenIDs{Input: []uint32{1, 2, 3}, Generated: []uint32{10, 11}},
			}))
			if err != nil {
				t.Fatal(err)
			}
			missing := 1
			if name == "scored token absent" {
				missing = 0
			}
			if !resp.VerifierValues[missing].Missing || resp.VerifierValues[1-missing].Missing {
				t.Fatalf("verifier values = %+v, want position %d missing only", resp.VerifierValues, missing)
			}
			last := (*seen)[len(*seen)-1]
			if last.PromptLogprobs == nil || *last.PromptLogprobs != 7 {
				t.Fatalf("prompt_logprobs = %v, want the profile's required_top_k 7", last.PromptLogprobs)
			}
		})
	}
}

// A model id that is not bound, or whose repository vLLM does not serve, is
// refused before any generation.
func TestLocalServiceRefusesUnboundAndUnservedModels(t *testing.T) {
	srv, seen := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	unbound := NewLocalService(srv.URL, "local", 4, 0, 0)
	unbound.SetStreamInference(false)
	if _, err := unbound.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID: "unbound", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi"),
	})); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound Infer = %v, want a refusal naming the missing binding", err)
	}
	unserved := NewLocalService(srv.URL, "local", 4, 0, 0)
	unserved.SetStreamInference(false)
	if err := unserved.BindModel(testQwenModelID(), LocalModelProvider, "Qwen/Qwen3-32B"); err != nil {
		t.Fatal(err)
	}
	if _, err := unserved.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID: "unserved", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi"),
	})); err == nil || !strings.Contains(err.Error(), "vLLM serves") {
		t.Fatalf("unserved Infer = %v, want a refusal naming what vLLM serves", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("a refused model reached generation: %d requests", len(*seen))
	}
}
