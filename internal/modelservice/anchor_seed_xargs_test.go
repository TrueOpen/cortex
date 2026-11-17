package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// The engine derives the canonical sampler's seed from (chain id, task id,
// order seed); the Worker passes those facts and nothing it could choose.
func TestAnchorSeedXArgs(t *testing.T) {
	g := &nodewire.GenerationContext{}
	g.Params.DecodingParams.Seed = 18446744073709551615 // above 2^53: must survive as a decimal string
	req := InferRequest{TaskID: strings.Repeat("ab", 32), ChainID: "trueopen-localnet-1", Generation: g, RequireAnchorCommit: true}
	got := anchorSeedXArgs(req)
	want := map[string]string{"slp_chain_id": "trueopen-localnet-1", "slp_task_id": strings.Repeat("ab", 32), "slp_order_seed": "18446744073709551615"}
	if len(got) != len(want) {
		t.Fatalf("xargs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("xargs[%s] = %q, want %q", k, got[k], v)
		}
	}
	body, err := json.Marshal(chatCompletionRequest{VLLMXArgs: got})
	if err != nil || !strings.Contains(string(body), `"vllm_xargs":{"slp_chain_id":"trueopen-localnet-1","slp_order_seed":"18446744073709551615","slp_task_id":"`) {
		t.Fatalf("chat request body = %s (err %v)", body, err)
	}

	// No anchor commitment required, or a fact missing: no xargs, and the
	// request bodies are exactly what they were before.
	for name, r := range map[string]InferRequest{
		"not an anchor task": {TaskID: req.TaskID, ChainID: req.ChainID, Generation: g},
		"no chain id":        {TaskID: req.TaskID, Generation: g, RequireAnchorCommit: true},
		"no task id":         {ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"no generation":      {TaskID: req.TaskID, ChainID: req.ChainID, RequireAnchorCommit: true},
	} {
		if x := anchorSeedXArgs(r); x != nil {
			t.Fatalf("%s: xargs = %v, want none", name, x)
		}
	}
	for _, v := range []any{chatCompletionRequest{}, completionRequest{}} {
		body, err := json.Marshal(v)
		if err != nil || strings.Contains(string(body), "vllm_xargs") {
			t.Fatalf("request without xargs carries the field: %s (err %v)", body, err)
		}
	}
}

// generationBodies fronts srv and records the body of every generation
// request the model service sends to the engine.
func generationBodies(t *testing.T, srv *httptest.Server) (*httptest.Server, func() []string) {
	t.Helper()
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var mu sync.Mutex
	var bodies []string
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/completions") {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			bodies = append(bodies, string(raw))
			mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	return front, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// End to end through Infer: the generation request of an anchor task reaches
// the engine with the three seed facts, and the request of any other task
// reaches it without the field.
func TestInferSendsSeedXArgsOnlyForAnchorTasks(t *testing.T) {
	for _, anchor := range []bool{true, false} {
		a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, testAnchorCommit }}
		engine, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
		front, bodies := generationBodies(t, a.front(t, engine))
		svc := newBoundLocalService(front.URL, "local", 4, 0, 0)
		svc.SetStreamInference(false)
		req := chatInferReq(t)
		req.ChainID, req.RequireAnchorCommit = "trueopen-localnet-1", anchor
		if _, err := svc.Infer(context.Background(), req); err != nil {
			t.Fatalf("anchor=%v: %v", anchor, err)
		}
		checkSeedXArgsBody(t, "chat", anchor, req, bodies())
	}
}

// The raw-text path (localGenerationRequest) carries the same xargs: an
// anchor task's /v1/completions request names the three seed facts, any other
// task's request has no vllm_xargs key at all.
func TestInferSendsSeedXArgsOnlyForAnchorTasksRaw(t *testing.T) {
	for _, anchor := range []bool{true, false} {
		// The commitment of the completion asked for: the fetch refuses one
		// recorded under another completion id.
		rawCommit := strings.Replace(testAnchorCommit, `"request_id":"chatcmpl-test"`, `"request_id":"cmpl-test"`, 1)
		a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, rawCommit }}
		gen := genResponse() // prompt 1 2 3, generated 10 11: what testAnchorCommit names
		gen.ID = "cmpl-test"
		engine, _ := newVLLMStub(t, gen, verifyResponse())
		front, bodies := generationBodies(t, a.front(t, engine))
		svc := newBoundLocalService(front.URL, "local", 4, 0, 0)
		svc.SetStreamInference(false)
		svc.anchorCommitBackoff = time.Millisecond
		req := boundLocalInferFixture(t, InferRequest{
			RequestID:  "raw-seed",
			TaskID:     "raw-task",
			ModelID:    testQwenModelID(),
			Capability: CapabilityLLMTextV1,
			Input:      []byte("say cat"),
		})
		req.Generation.Params.DecodingParams.Seed = 1<<53 + 1 // above 2^53, within the backend integer range
		digest, err := req.Generation.Digest()
		if err != nil {
			t.Fatal(err)
		}
		req.GenerationParamsDigest = digest[:]
		req.ChainID, req.RequireAnchorCommit = "trueopen-localnet-1", anchor
		resp, err := svc.Infer(context.Background(), req)
		if err != nil {
			t.Fatalf("anchor=%v: %v", anchor, err)
		}
		if got := resp.AnchorCommitRef != ""; got != anchor {
			t.Fatalf("anchor=%v: anchor ref set=%t", anchor, got)
		}
		checkSeedXArgsBody(t, "raw", anchor, req, bodies())
	}
}

// checkSeedXArgsBody asserts the one generation request sent: with anchor it
// carries exactly the three seed facts of req, without it no vllm_xargs key.
func checkSeedXArgsBody(t *testing.T, path string, anchor bool, req InferRequest, sent []string) {
	t.Helper()
	if len(sent) != 1 {
		t.Fatalf("%s anchor=%v: %d generation requests, want 1", path, anchor, len(sent))
	}
	var body struct {
		XArgs map[string]string `json:"vllm_xargs"`
	}
	if err := json.Unmarshal([]byte(sent[0]), &body); err != nil {
		t.Fatal(err)
	}
	if !anchor {
		if strings.Contains(sent[0], "vllm_xargs") {
			t.Fatalf("%s: a task without an anchor commitment carries vllm_xargs: %s", path, sent[0])
		}
		return
	}
	seed, ok := body.XArgs[anchorXArgOrderSeed]
	if len(body.XArgs) != 3 || body.XArgs[anchorXArgChainID] != "trueopen-localnet-1" || body.XArgs[anchorXArgTaskID] != req.TaskID || !ok {
		t.Fatalf("%s: vllm_xargs = %v", path, body.XArgs)
	}
	if want := strconv.FormatUint(req.Generation.Params.DecodingParams.Seed, 10); seed != want {
		t.Fatalf("%s: order seed %q, want the order's %q", path, seed, want)
	}
}
