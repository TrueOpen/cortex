package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// seedTestTaskID is a task id as the chain writes it: 64 lowercase hex.
var seedTestTaskID = strings.Repeat("ab", 32)

// The engine derives the canonical sampler's seed from (chain id, task id,
// order seed); the Worker passes those facts and nothing it could choose.
func TestAnchorSeedXArgs(t *testing.T) {
	g := &nodewire.GenerationContext{}
	g.Params.DecodingParams.Seed = 18446744073709551615 // above 2^53: must survive as a decimal string
	req := InferRequest{TaskID: seedTestTaskID, ChainID: "trueopen-localnet-1", Generation: g, RequireAnchorCommit: true}
	got, err := anchorSeedXArgs(req)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"slp_chain_id": "trueopen-localnet-1", "slp_task_id": seedTestTaskID, "slp_order_seed": "18446744073709551615"}
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

	// No anchor commitment required: no xargs and no error.
	if x, err := anchorSeedXArgs(InferRequest{TaskID: "any", Generation: g}); x != nil || err != nil {
		t.Fatalf("not an anchor task: xargs = %v, err = %v, want neither", x, err)
	}
	// A fact missing, or a task id that is not the chain's 64 lowercase hex:
	// the engine would derive a seed the validators do not reproduce (or fall
	// back to another seed without saying so), so nothing is sent.
	for name, r := range map[string]InferRequest{
		"no chain id":         {TaskID: req.TaskID, Generation: g, RequireAnchorCommit: true},
		"no task id":          {ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"no generation":       {TaskID: req.TaskID, ChainID: req.ChainID, RequireAnchorCommit: true},
		"task id not hex":     {TaskID: "chat-task", ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"task id upper case":  {TaskID: strings.Repeat("AB", 32), ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"task id 0x prefixed": {TaskID: "0x" + req.TaskID, ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"task id 31 bytes":    {TaskID: req.TaskID[2:], ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
		"task id padded":      {TaskID: req.TaskID + " ", ChainID: req.ChainID, Generation: g, RequireAnchorCommit: true},
	} {
		if x, err := anchorSeedXArgs(r); x != nil || err == nil {
			t.Fatalf("%s: xargs = %v, err = %v, want an error and no xargs", name, x, err)
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
		svc.SetAnchorSeedRule(AnchorSeedRuleV2)
		req := chatInferReq(t)
		req.TaskID = seedTestTaskID
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
		svc.SetAnchorSeedRule(AnchorSeedRuleV2)
		svc.anchorCommitBackoff = time.Millisecond
		req := boundLocalInferFixture(t, InferRequest{
			RequestID:  "raw-seed",
			TaskID:     seedTestTaskID,
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

// The seed binding is off unless model_management.anchor_seed_rule turns it
// on: a generation that requires an anchor commitment is then sampled like
// any other, on both paths, and its request body carries no vllm_xargs.
func TestInferSendsNoSeedXArgsWhileTheSeedRuleIsOff(t *testing.T) {
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, testAnchorCommit }}
	engine, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	front, bodies := generationBodies(t, a.front(t, engine))
	svc := newBoundLocalService(front.URL, "local", 4, 0, 0)
	svc.SetStreamInference(false)
	req := chatInferReq(t) // its task id is not even a Hash32: nothing looks at it while the rule is off
	req.ChainID, req.RequireAnchorCommit = "trueopen-localnet-1", true
	resp, err := svc.Infer(context.Background(), req)
	if err != nil || resp.AnchorCommitRef == "" {
		t.Fatalf("Infer() = %+v, %v, want the anchor task served as before", resp, err)
	}
	checkSeedXArgsBody(t, "chat, rule off", false, req, bodies())
}

// With the seed binding on, a task whose id is not the chain's Hash32 is not
// generated at all: the engine would fall back to another seed without
// saying so, and the validators would reject what it sampled.
func TestInferRefusesToGenerateWithoutTheSeedFacts(t *testing.T) {
	for name, edit := range map[string]func(*InferRequest){
		"task id is not a Hash32": func(r *InferRequest) { r.TaskID = "chat-task" },
		"no chain id":             func(r *InferRequest) { r.ChainID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, testAnchorCommit }}
			engine, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
			front, bodies := generationBodies(t, a.front(t, engine))
			svc := newBoundLocalService(front.URL, "local", 4, 0, 0)
			svc.SetStreamInference(false)
			svc.SetAnchorSeedRule(AnchorSeedRuleV2)
			req := chatInferReq(t)
			req.TaskID, req.ChainID, req.RequireAnchorCommit = seedTestTaskID, "trueopen-localnet-1", true
			edit(&req)
			_, err := svc.Infer(context.Background(), req)
			if ClassOf(err) != FaultDeterministic || FaultCode(err) != FaultCodeAnchorSeedInputs {
				t.Fatalf("err = %v (class %v, code %q), want a deterministic %s", err, ClassOf(err), FaultCode(err), FaultCodeAnchorSeedInputs)
			}
			if sent := bodies(); len(sent) != 0 || len(a.calls()) != 0 {
				t.Fatalf("%d generation requests and %d commitment fetches after the refusal, want none", len(sent), len(a.calls()))
			}
		})
	}
}

// With the seed binding on, the engine must declare the rule on /slp/info or
// it is not capable: it would ignore the xargs and sample with the order's
// seed, and no answer of its would show that. Off, the declaration is not
// looked at.
func TestAnchorCommitCapableRequiresTheDeclaredSeedRule(t *testing.T) {
	ok := func() int { return http.StatusOK }
	for _, c := range []struct {
		name, rule, body string
		capable          bool
	}{
		{"declared", AnchorSeedRuleV2, `{"fmt":"anc2","seed_rules":["seed-v2"]}`, true},
		{"declared among others", AnchorSeedRuleV2, `{"seed_rules":["seed-v3","seed-v2"]}`, true},
		{"not declared", AnchorSeedRuleV2, `{"fmt":"anc2"}`, false},
		{"another rule only", AnchorSeedRuleV2, `{"seed_rules":["seed-v1"]}`, false},
		{"empty list", AnchorSeedRuleV2, `{"seed_rules":[]}`, false},
		{"a string, not a list", AnchorSeedRuleV2, `{"seed_rules":"seed-v2"}`, false},
		{"not JSON", AnchorSeedRuleV2, `ok`, false},
		{"binding off, not declared", "", `{"fmt":"anc2"}`, true},
		{"binding off, not JSON", "", `ok`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			svc := anchorTestService(t, &anchorSidecar{info: ok, infoBody: c.body})
			svc.SetAnchorSeedRule(c.rule)
			err := svc.AnchorCommitCapable(context.Background())
			switch {
			case c.capable && err != nil:
				t.Fatalf("err = %v, want a capable engine", err)
			case !c.capable && (!errors.Is(err, ErrAnchorCommitUnsupported) || errors.Is(err, ErrAnchorCommitProbeFailed)):
				t.Fatalf("err = %v, want ErrAnchorCommitUnsupported (a fact, so the Profile is left out)", err)
			}
		})
	}
	t.Run("turning the binding on asks the engine again", func(t *testing.T) {
		a := &anchorSidecar{info: ok, infoBody: `{}`}
		svc := anchorTestService(t, a)
		if err := svc.AnchorCommitCapable(context.Background()); err != nil {
			t.Fatal(err)
		}
		svc.SetAnchorSeedRule(AnchorSeedRuleV2)
		if err := svc.AnchorCommitCapable(context.Background()); !errors.Is(err, ErrAnchorCommitUnsupported) || a.infoCalls.Load() != 2 {
			t.Fatalf("err = %v after %d probes, want the cached verdict dropped and the engine refused", err, a.infoCalls.Load())
		}
	})
}

// With the seed binding on, the commitment of a sampled order must declare
// the rule, or no receipt is signed over it. A greedy order draws nothing
// from the seed and is not checked; nor is anything while the binding is off.
func TestInferChecksTheCommitmentSeedRuleOfSampledOrders(t *testing.T) {
	withRule := strings.Replace(testAnchorCommit, `"roots":["00"]`, `"roots":["00"],"sampling":"canon-v1","seed_rule":"seed-v2"`, 1)
	otherRule := strings.Replace(withRule, `"seed-v2"`, `"seed-v1"`, 1)
	greedyWithRule := strings.Replace(testAnchorCommit, `"roots":["00"]`, `"roots":["00"],"sampling":"greedy","temperature":0.0,"seed":"","seed_rule":"seed-v2"`, 1)
	for _, c := range []struct {
		name    string
		rule    string
		sampled bool
		commit  string
		signed  bool
	}{
		{"sampled, rule declared", AnchorSeedRuleV2, true, withRule, true},
		{"sampled, rule missing", AnchorSeedRuleV2, true, testAnchorCommit, false},
		{"sampled, another rule", AnchorSeedRuleV2, true, otherRule, false},
		{"greedy, rule missing", AnchorSeedRuleV2, false, testAnchorCommit, true},
		// The engine writes the rule whenever it was given the three facts,
		// with an empty seed for a greedy order; that is not asserted absent.
		{"greedy, rule declared with an empty seed", AnchorSeedRuleV2, false, greedyWithRule, true},
		{"greedy, another rule", AnchorSeedRuleV2, false, otherRule, true},
		{"binding off, rule declared", "", true, withRule, true},
		{"binding off, sampled, rule missing", "", true, testAnchorCommit, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, c.commit }}
			svc := anchorTestService(t, a)
			svc.SetAnchorSeedRule(c.rule)
			req := chatInferReq(t)
			req.TaskID, req.ChainID, req.RequireAnchorCommit = seedTestTaskID, "trueopen-localnet-1", true
			if c.sampled {
				req.Generation.Params.DecodingParams.SamplingEnabled = true
				req.Generation.Params.DecodingParams.TemperatureMilli = 700
				req.Generation.Params.DecodingParams.TopPPPM = 1_000_000
			}
			digest, err := req.Generation.Digest()
			if err != nil {
				t.Fatal(err)
			}
			req.GenerationParamsDigest = digest[:]
			resp, err := svc.Infer(context.Background(), req)
			if c.signed {
				if err != nil || resp.AnchorCommitRef == "" {
					t.Fatalf("Infer() = %+v, %v, want the commitment signed", resp, err)
				}
				return
			}
			if !errors.Is(err, ErrAnchorCommitSeedRule) || resp.AnchorCommitRef != "" {
				t.Fatalf("Infer() = %+v, %v, want ErrAnchorCommitSeedRule", resp, err)
			}
			if ClassOf(err) != FaultDeterministic || IsRetryable(err) || FaultCode(err) != FaultCodeAnchorCommitSeedRule {
				t.Fatalf("err = %v (class %v, code %q), want a deterministic %s", err, ClassOf(err), FaultCode(err), FaultCodeAnchorCommitSeedRule)
			}
		})
	}
}

// An engine that implements the seed rule answers 400 with the code
// slp_seed_xargs_unsupported to a generation request whose seed facts it
// cannot use, instead of sampling with another seed. The task halts with
// that reason and is not generated again; any other 400 is what it was.
func TestInferHaltsWhenTheEngineRefusesTheSeedXArgs(t *testing.T) {
	for _, c := range []struct {
		name, body string
		rejected   bool
	}{
		{"seed xargs refused", `{"error":{"message":"slp_task_id must be 64 hex characters","type":"BadRequestError","code":"slp_seed_xargs_unsupported"}}`, true},
		{"another bad request", `{"error":{"message":"max_tokens is too large","type":"BadRequestError","code":400}}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			engine, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
			target, err := url.Parse(engine.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/completions") {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(c.body))
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)
			svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
			svc.SetStreamInference(false)
			svc.SetAnchorSeedRule(AnchorSeedRuleV2)
			req := chatInferReq(t)
			req.TaskID, req.ChainID, req.RequireAnchorCommit = seedTestTaskID, "trueopen-localnet-1", true
			_, err = svc.Infer(context.Background(), req)
			if err == nil || IsRetryable(err) || calls.Load() != 1 {
				t.Fatalf("err = %v after %d generation requests, want one request and no retry", err, calls.Load())
			}
			if got := ClassOf(err) == FaultDeterministic && FaultCode(err) == FaultCodeAnchorSeedXArgsRejected; got != c.rejected {
				t.Fatalf("err = %v (class %v, code %q), deterministic %s = %v, want %v", err, ClassOf(err), FaultCode(err), FaultCodeAnchorSeedXArgsRejected, got, c.rejected)
			}
		})
	}
}
