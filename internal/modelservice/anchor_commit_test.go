package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// testAnchorCommit names the tokens chatGenResponse delivers (prompt 1 2 3,
// generated 10 11): the Worker-side self-check compares them.
const testAnchorCommit = `{"request_id":"chatcmpl-test","roots":["00"],"token_ids":[1,2,3,10,11],"prompt_tokens":3,"rows":4}`

// anchorSidecar fronts an engine stub with the ADR-0040 /slp routes. commit
// answers GET /slp/commit/{id}; info answers GET /slp/info (nil: 404).
type anchorSidecar struct {
	mu          sync.Mutex
	commitCalls []string
	infoCalls   atomic.Int32
	commit      func(call int, id string) (int, string)
	// commitAt, when set, answers instead of commit and also sees the
	// delivered prefix the fetch named ("" when it named none).
	commitAt func(call int, id, generated string) (int, string)
	queries  []string // the raw query of every commit call
	info     func() int
	// infoBody is what GET /slp/info answers with; "" means {}.
	infoBody string
}

func (a *anchorSidecar) front(t *testing.T, engine *httptest.Server) *httptest.Server {
	t.Helper()
	target, err := url.Parse(engine.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/slp/commit/"):
			id := strings.TrimPrefix(r.URL.Path, "/slp/commit/")
			a.mu.Lock()
			a.commitCalls = append(a.commitCalls, id)
			a.queries = append(a.queries, r.URL.RawQuery)
			call := len(a.commitCalls)
			a.mu.Unlock()
			status, body := http.StatusNotFound, `{"error":"no such route"}`
			switch {
			case a.commitAt != nil:
				status, body = a.commitAt(call, id, r.URL.Query().Get(anchorCommitGeneratedParam))
			case a.commit != nil:
				status, body = a.commit(call, id)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case r.URL.Path == "/slp/info":
			a.infoCalls.Add(1)
			status := http.StatusNotFound
			if a.info != nil {
				status = a.info()
			}
			w.WriteHeader(status)
			body := a.infoBody
			if body == "" {
				body = `{}`
			}
			_, _ = w.Write([]byte(body))
		default:
			proxy.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (a *anchorSidecar) calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.commitCalls...)
}

func anchorTestService(t *testing.T, a *anchorSidecar) *LocalService {
	t.Helper()
	engine, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(a.front(t, engine).URL, "local", 4, 0, 0)
	svc.SetStreamInference(false)
	svc.anchorCommitBackoff = time.Millisecond
	return svc
}

// A task whose Profile does not require kind 5 never asks the sidecar, even
// when the sidecar would refuse.
func TestInferWithoutAnchorRequirementNeverAsksTheSidecar(t *testing.T) {
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusInternalServerError, "boom" }}
	svc := anchorTestService(t, a)
	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.AnchorCommitRef != "" || len(a.calls()) != 0 {
		t.Fatalf("anchor ref %q after %d sidecar calls, want none", resp.AnchorCommitRef, len(a.calls()))
	}
}

// 503 means the sidecar is still finalizing: the fetch polls until the bytes
// are served and returns them exactly.
func TestInferPollsAnchorCommitThroughFinalizing(t *testing.T) {
	a := &anchorSidecar{commit: func(call int, _ string) (int, string) {
		if call < 3 {
			return http.StatusServiceUnavailable, `{"error":"finalizing"}`
		}
		return http.StatusOK, testAnchorCommit
	}}
	svc := anchorTestService(t, a)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	resp, err := svc.Infer(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	calls := a.calls()
	if len(calls) != 3 || calls[0] != "chatcmpl-test" {
		t.Fatalf("sidecar calls %v, want three for chatcmpl-test", calls)
	}
	artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.AnchorCommitRef})
	if err != nil || string(artifact.Data) != testAnchorCommit {
		t.Fatalf("anchor artifact %q, %v", artifact.Data, err)
	}
}

// 404 under a Profile that requires kind 5 is an explicit failure, not a
// silently missing commitment. Without a grace it is not polled.
func TestInferRequiredAnchorCommitNotFoundFails(t *testing.T) {
	a := &anchorSidecar{}
	svc := anchorTestService(t, a)
	svc.anchorCommitNotFoundGrace = -1
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	_, err := svc.Infer(context.Background(), req)
	if !errors.Is(err, ErrAnchorCommitNotFound) || !strings.Contains(err.Error(), "WORKER_ANCHOR_OPENING") {
		t.Fatalf("err = %v, want ErrAnchorCommitNotFound naming WORKER_ANCHOR_OPENING", err)
	}
	if IsRetryable(err) {
		t.Fatal("a missing commitment must not re-run the generation")
	}
	if n := len(a.calls()); n != 1 {
		t.Fatalf("404 polled %d times, want once", n)
	}
}

// A 404 for a completion that has just ended is polled for the grace: a
// sidecar that registers the completion a moment late is waited for, and one
// that never does fails the task with ErrAnchorCommitNotFound, not with the
// end of the whole commitment window.
func TestInferPollsAnchorCommitThroughAnEarlyNotFound(t *testing.T) {
	t.Run("registered late", func(t *testing.T) {
		a := &anchorSidecar{commit: func(call int, _ string) (int, string) {
			switch call {
			case 1, 2:
				return http.StatusNotFound, `{"error":"unknown request"}`
			case 3:
				return http.StatusServiceUnavailable, `{"error":"request still finishing"}`
			}
			return http.StatusOK, testAnchorCommit
		}}
		svc := anchorTestService(t, a)
		svc.anchorCommitNotFoundGrace = time.Minute
		req := chatInferReq(t)
		req.RequireAnchorCommit = true
		resp, err := svc.Infer(context.Background(), req)
		if err != nil || resp.AnchorCommitRef == "" {
			t.Fatalf("Infer() = %+v, %v, want the commitment served on the fourth poll", resp, err)
		}
		if n := len(a.calls()); n != 4 {
			t.Fatalf("polled %d times, want 4", n)
		}
	})
	t.Run("never registered", func(t *testing.T) {
		a := &anchorSidecar{}
		svc := anchorTestService(t, a)
		svc.anchorCommitNotFoundGrace = 30 * time.Millisecond
		svc.SetAnchorCommitTimeout(time.Minute)
		req := chatInferReq(t)
		req.RequireAnchorCommit = true
		start := time.Now()
		_, err := svc.Infer(context.Background(), req)
		if !errors.Is(err, ErrAnchorCommitNotFound) || IsRetryable(err) {
			t.Fatalf("err = %v, want a non-retryable ErrAnchorCommitNotFound", err)
		}
		if n := len(a.calls()); n < 2 {
			t.Fatalf("404 polled %d times, want it polled through the grace", n)
		}
		if took := time.Since(start); took > 10*time.Second {
			t.Fatalf("gave up after %s, want the grace, not the commitment window", took)
		}
	})
}

// A sidecar that never finishes is given up on at the end of the anchor
// window, with an error naming the window.
func TestInferAnchorCommitWindowExpires(t *testing.T) {
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusServiceUnavailable, "finalizing" }}
	svc := anchorTestService(t, a)
	svc.SetAnchorCommitTimeout(50 * time.Millisecond)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	start := time.Now()
	_, err := svc.Infer(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "anchor commitment window") || IsRetryable(err) {
		t.Fatalf("err = %v, want a non-retryable window expiry", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("gave up after %s", elapsed)
	}
	if len(a.calls()) < 2 {
		t.Fatalf("polled %d times inside the window", len(a.calls()))
	}
}

// A body that is not an AnchorCommitV1 document is refused, not committed.
func TestInferRefusesMalformedAnchorCommit(t *testing.T) {
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, `{"roots":[]}` }}
	svc := anchorTestService(t, a)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	if _, err := svc.Infer(context.Background(), req); err == nil || !strings.Contains(err.Error(), "AnchorCommitV1") {
		t.Fatalf("err = %v, want a malformed-document refusal", err)
	}
}

// A document recorded under another completion id is refused, not signed
// into this completion's receipt, and is not polled again.
func TestInferRefusesAnchorCommitOfAnotherCompletion(t *testing.T) {
	a := &anchorSidecar{commit: func(int, string) (int, string) {
		return http.StatusOK, `{"request_id":"chatcmpl-SOMEONE-ELSE","roots":["00"]}`
	}}
	svc := anchorTestService(t, a)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	resp, err := svc.Infer(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "chatcmpl-SOMEONE-ELSE") {
		t.Fatalf("Infer() = %+v, %v, want a refusal naming the foreign request_id", resp, err)
	}
	if IsRetryable(err) {
		t.Fatal("a mismatched commitment must not re-run the generation")
	}
	if calls := a.calls(); len(calls) != 1 || calls[0] != "chatcmpl-test" {
		t.Fatalf("sidecar calls %v, want one for chatcmpl-test", calls)
	}
}

// A generation stopped at max_output_duration has spent its budget and the
// budget grace, but the commitment fetch has its own window: the task is not
// failed by the time the sidecar needs, and without the requirement the
// sidecar is not asked at all.
func TestTruncatedGenerationKeepsItsAnchorWindow(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(map[bool]string{false: "not required", true: "required"}[required], func(t *testing.T) {
			chunks := chatContentChunks()[:2]
			chunks[1].Choices[0].FinishReason = ""
			engine := newSlowChatStreamStub(t, chunks, 150*time.Millisecond, []string{"Qwen/Qwen3-8B"})
			a := &anchorSidecar{commit: func(call int, _ string) (int, string) {
				// The sidecar needs longer than what is left of the
				// generation's infer timeout to finalize.
				time.Sleep(250 * time.Millisecond)
				if call < 3 {
					return http.StatusServiceUnavailable, "finalizing"
				}
				return http.StatusOK, testAnchorCommit
			}}
			// The generation stops at ~300 ms (budget 200 ms, frames every
			// 150 ms); the infer timeout ends at 450 ms and the commitment is
			// only served at ~750 ms, so it must be fetched outside every
			// generation deadline.
			svc := newBoundLocalService(a.front(t, engine).URL, "local-svc", 4, 450*time.Millisecond, 0)
			svc.anchorCommitBackoff = time.Millisecond
			req := chatInferReq(t)
			req.Generation.Params.MaxOutputDuration = 200
			digest, err := req.Generation.Digest()
			if err != nil {
				t.Fatal(err)
			}
			req.GenerationParamsDigest = digest[:]
			req.RequireAnchorCommit = required
			resp, err := svc.Infer(context.Background(), req)
			if err != nil {
				t.Fatalf("Infer() error = %v, want a successful truncation", err)
			}
			if resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration {
				t.Fatalf("finish reason %v, want MAX_OUTPUT_DURATION", resp.FinishReason)
			}
			if got := resp.AnchorCommitRef != ""; got != required {
				t.Fatalf("anchor ref set=%t, want %t", got, required)
			}
			if !required && len(a.calls()) != 0 {
				t.Fatalf("sidecar asked %d times for a task that does not require it", len(a.calls()))
			}
		})
	}
}

// The capability probe answers from /slp/info and caches the verdict, so the
// handraise gates can ask on every pass.
func TestAnchorCommitCapableProbesAndCaches(t *testing.T) {
	status := atomic.Int32{}
	status.Store(http.StatusOK)
	a := &anchorSidecar{info: func() int { return int(status.Load()) }}
	svc := anchorTestService(t, a)
	ctx := context.Background()
	for range 3 {
		if err := svc.AnchorCommitCapable(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := a.infoCalls.Load(); n != 1 {
		t.Fatalf("/slp/info probed %d times, want one cached probe", n)
	}
	// A failure is cached too (for a shorter time).
	status.Store(http.StatusNotFound)
	svc.anchorInfo.checked = time.Now().Add(-anchorInfoOKTTL)
	for range 2 {
		if err := svc.AnchorCommitCapable(ctx); !errors.Is(err, ErrAnchorCommitUnsupported) {
			t.Fatalf("err = %v, want ErrAnchorCommitUnsupported", err)
		}
	}
	if n := a.infoCalls.Load(); n != 2 {
		t.Fatalf("/slp/info probed %d times, want the failure cached", n)
	}
	// The failure expires sooner and the engine is picked up again.
	status.Store(http.StatusOK)
	svc.anchorInfo.checked = time.Now().Add(-anchorInfoFailTTL)
	if err := svc.AnchorCommitCapable(ctx); err != nil {
		t.Fatal(err)
	}
}

// An engine without the sidecar (404 on /slp/info) is not capable.
func TestAnchorCommitCapableWithoutSidecar(t *testing.T) {
	svc := anchorTestService(t, &anchorSidecar{})
	if err := svc.AnchorCommitCapable(context.Background()); !errors.Is(err, ErrAnchorCommitUnsupported) {
		t.Fatalf("err = %v, want ErrAnchorCommitUnsupported", err)
	}
}

// An engine that does not answer the probe in time, refuses the connection or
// answers 5xx says nothing about the sidecar: the probe failed, and the error
// is not ErrAnchorCommitUnsupported.
func TestAnchorCommitCapableTransientFailureIsNotAVerdict(t *testing.T) {
	for _, c := range []struct {
		name string
		svc  func(t *testing.T) *LocalService
	}{
		{"503", func(t *testing.T) *LocalService {
			return anchorTestService(t, &anchorSidecar{info: func() int { return http.StatusServiceUnavailable }})
		}},
		{"500", func(t *testing.T) *LocalService {
			return anchorTestService(t, &anchorSidecar{info: func() int { return http.StatusInternalServerError }})
		}},
		{"timeout", func(t *testing.T) *LocalService {
			svc := anchorTestService(t, &anchorSidecar{info: func() int {
				time.Sleep(200 * time.Millisecond)
				return http.StatusOK
			}})
			svc.probeTimeout = 20 * time.Millisecond
			return svc
		}},
		{"connection refused", func(t *testing.T) *LocalService {
			srv := httptest.NewServer(http.NotFoundHandler())
			srv.Close()
			return newBoundLocalService(srv.URL, "local", 4, 0, 0)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.svc(t).AnchorCommitCapable(context.Background())
			if !errors.Is(err, ErrAnchorCommitProbeFailed) || errors.Is(err, ErrAnchorCommitUnsupported) {
				t.Fatalf("err = %v, want ErrAnchorCommitProbeFailed and not ErrAnchorCommitUnsupported", err)
			}
		})
	}
}

// The Worker refuses to sign a receipt over a commitment that names other
// tokens than the completion delivered: the validators would reject it
// deterministically (slash and jail), so the task fails here instead. The
// refusal is itself deterministic: another generation cannot make this
// completion's commitment name other tokens, and on the streaming path the
// frames are already signed, so the scheduler must halt with this reason
// rather than retry into OUTPUT_FRAMES_ALREADY_SIGNED.
func TestInferRefusesAnchorCommitWithOtherTokens(t *testing.T) {
	cases := map[string]string{
		"one generated token differs": `{"request_id":"chatcmpl-test","roots":["00"],"token_ids":[1,2,3,10,12],"prompt_tokens":3,"rows":4}`,
		"prompt length forged":        `{"request_id":"chatcmpl-test","roots":["00"],"token_ids":[1,2,3,10,11],"prompt_tokens":2,"rows":4}`,
		"rows forged":                 `{"request_id":"chatcmpl-test","roots":["00"],"token_ids":[1,2,3,10,11],"prompt_tokens":3,"rows":5}`,
		"another trajectory":          `{"request_id":"chatcmpl-test","roots":["00"],"token_ids":[7,8,9,10,11,12],"prompt_tokens":3,"rows":5}`,
		"no token ids":                `{"request_id":"chatcmpl-test","roots":["00"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, body }}
			svc := anchorTestService(t, a)
			req := chatInferReq(t)
			req.RequireAnchorCommit = true
			_, err := svc.Infer(context.Background(), req)
			if !errors.Is(err, ErrAnchorCommitMismatch) {
				t.Fatalf("err = %v, want ErrAnchorCommitMismatch", err)
			}
			if ClassOf(err) != FaultDeterministic || IsRetryable(err) || FaultCode(err) != "ANCHOR_COMMIT_TOKEN_MISMATCH" {
				t.Fatalf("err = %v (class %v, code %q), want a deterministic ANCHOR_COMMIT_TOKEN_MISMATCH", err, ClassOf(err), FaultCode(err))
			}
		})
	}
}

func TestCheckAnchorCommitTokens(t *testing.T) {
	ids := TokenIDs{Input: []uint32{1, 2, 3}, Generated: []uint32{10, 11}}
	if err := checkAnchorCommitTokens([]byte(testAnchorCommit), ids); err != nil {
		t.Fatalf("matching commitment refused: %v", err)
	}
	if err := checkAnchorCommitTokens([]byte(`{"request_id":"x","token_ids":[1,2,3,10,11]}`), ids); err != nil {
		t.Fatalf("prompt_tokens and rows are optional: %v", err)
	}
	if err := checkAnchorCommitTokens([]byte(`{"request_id":"x","token_ids":[1,2,3,10,-1]}`), ids); !errors.Is(err, ErrAnchorCommitMismatch) {
		t.Fatalf("negative id accepted: %v", err)
	}
}

// A probe that got no answer is asked again after a few seconds: while it is
// cached every offer for a kind 5 Profile goes unanswered. A definitive "no
// sidecar" keeps its longer cache.
func TestAnchorCommitCapableRetriesAFailedProbeSoonerThanAVerdict(t *testing.T) {
	age := func(svc *LocalService, d time.Duration) {
		svc.anchorInfo.mu.Lock()
		svc.anchorInfo.checked = svc.anchorInfo.checked.Add(-d)
		svc.anchorInfo.mu.Unlock()
	}
	status := atomic.Int32{}
	status.Store(http.StatusServiceUnavailable)
	a := &anchorSidecar{info: func() int { return int(status.Load()) }}
	svc := anchorTestService(t, a)
	ctx := context.Background()
	if err := svc.AnchorCommitCapable(ctx); !errors.Is(err, ErrAnchorCommitProbeFailed) {
		t.Fatalf("err = %v, want ErrAnchorCommitProbeFailed", err)
	}
	status.Store(http.StatusOK)
	if err := svc.AnchorCommitCapable(ctx); !errors.Is(err, ErrAnchorCommitProbeFailed) || a.infoCalls.Load() != 1 {
		t.Fatalf("err = %v after %d probes, want the failure reused at once", err, a.infoCalls.Load())
	}
	age(svc, anchorInfoProbeFailTTL)
	if err := svc.AnchorCommitCapable(ctx); err != nil || a.infoCalls.Load() != 2 {
		t.Fatalf("err = %v after %d probes, want a fresh probe after anchorInfoProbeFailTTL", err, a.infoCalls.Load())
	}

	b := &anchorSidecar{}
	none := anchorTestService(t, b)
	if err := none.AnchorCommitCapable(ctx); !errors.Is(err, ErrAnchorCommitUnsupported) {
		t.Fatalf("err = %v, want ErrAnchorCommitUnsupported", err)
	}
	age(none, anchorInfoProbeFailTTL)
	if err := none.AnchorCommitCapable(ctx); !errors.Is(err, ErrAnchorCommitUnsupported) || b.infoCalls.Load() != 1 {
		t.Fatalf("err = %v after %d probes, want the verdict still cached", err, b.infoCalls.Load())
	}
}

// The fetch names the delivered prefix, and a sidecar that honours it serves
// a commitment the Worker can sign even though the engine generated past the
// point the Worker stopped reading: chatGenResponse delivers prompt 1 2 3 and
// generated 10 11, the engine's own trajectory went on to 12.
func TestInferFetchesTheAnchorCommitAtTheDeliveredPrefix(t *testing.T) {
	// An engine that finalises at a prefix says so on /slp/info.
	const prefixInfo = `{"fmt":"anc2","commit_prefix":["generated","rows"]}`
	prefixEngine := func() int { return http.StatusOK }
	const ranAhead = `{"request_id":"chatcmpl-test","roots":["ff"],"token_ids":[1,2,3,10,11,12],"prompt_tokens":3,"rows":5}`
	t.Run("the sidecar finalises at the prefix", func(t *testing.T) {
		a := &anchorSidecar{info: prefixEngine, infoBody: prefixInfo, commitAt: func(call int, _, generated string) (int, string) {
			switch {
			case generated != "2":
				return http.StatusOK, ranAhead
			case call == 1:
				return http.StatusServiceUnavailable, `{"error":"request still finishing"}`
			}
			return http.StatusOK, testAnchorCommit
		}}
		svc := anchorTestService(t, a)
		req := chatInferReq(t)
		req.RequireAnchorCommit = true
		resp, err := svc.Infer(context.Background(), req)
		if err != nil || resp.AnchorCommitRef == "" {
			t.Fatalf("Infer() = %+v, %v, want the prefix commitment signed", resp, err)
		}
		artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.AnchorCommitRef})
		if err != nil || string(artifact.Data) != testAnchorCommit {
			t.Fatalf("anchor artifact %q, %v", artifact.Data, err)
		}
		a.mu.Lock()
		queries := append([]string(nil), a.queries...)
		a.mu.Unlock()
		if len(queries) != 2 || queries[0] != "generated=2" || queries[1] != "generated=2" {
			t.Fatalf("commit queries %q, want generated=2 on every poll", queries)
		}
	})
	t.Run("an engine that does not declare the prefix is asked without it", func(t *testing.T) {
		for name, info := range map[string]string{
			"declares nothing":     `{"fmt":"anc2"}`,
			"declares only rows":   `{"commit_prefix":["rows"]}`,
			"declares a string":    `{"commit_prefix":"generated"}`,
			"answers no JSON":      `ok`,
			"has no /slp/info yet": "",
		} {
			a := &anchorSidecar{infoBody: info, commit: func(int, string) (int, string) { return http.StatusOK, testAnchorCommit }}
			if info != "" {
				a.info = prefixEngine
			}
			svc := anchorTestService(t, a)
			req := chatInferReq(t)
			req.RequireAnchorCommit = true
			if resp, err := svc.Infer(context.Background(), req); err != nil || resp.AnchorCommitRef == "" {
				t.Fatalf("%s: Infer() = %+v, %v, want the whole-trajectory commitment signed", name, resp, err)
			}
			a.mu.Lock()
			queries := append([]string(nil), a.queries...)
			a.mu.Unlock()
			if len(queries) != 1 || queries[0] != "" {
				t.Fatalf("%s: commit queries %q, want one fetch without a parameter", name, queries)
			}
		}
	})
	t.Run("a sidecar that ignores the prefix is refused, not signed", func(t *testing.T) {
		a := &anchorSidecar{info: prefixEngine, infoBody: prefixInfo, commit: func(int, string) (int, string) { return http.StatusOK, ranAhead }}
		svc := anchorTestService(t, a)
		req := chatInferReq(t)
		req.RequireAnchorCommit = true
		resp, err := svc.Infer(context.Background(), req)
		if !errors.Is(err, ErrAnchorCommitMismatch) || resp.AnchorCommitRef != "" {
			t.Fatalf("Infer() = %+v, %v, want ErrAnchorCommitMismatch", resp, err)
		}
		if ClassOf(err) != FaultDeterministic || FaultCode(err) != FaultCodeAnchorCommitTokenMismatch {
			t.Fatalf("err = %v (class %v, code %q), want a deterministic %s", err, ClassOf(err), FaultCode(err), FaultCodeAnchorCommitTokenMismatch)
		}
	})
	t.Run("a prefix the engine cannot serve is not polled", func(t *testing.T) {
		for status, body := range map[int]string{
			http.StatusConflict:   `{"error":"generated 1 token, asked for 2"}`,
			http.StatusBadRequest: `{"error":"generated must be a non-negative integer"}`,
		} {
			a := &anchorSidecar{info: prefixEngine, infoBody: prefixInfo, commit: func(int, string) (int, string) { return status, body }}
			svc := anchorTestService(t, a)
			req := chatInferReq(t)
			req.RequireAnchorCommit = true
			if _, err := svc.Infer(context.Background(), req); err == nil || IsRetryable(err) || len(a.calls()) != 1 {
				t.Fatalf("status %d: err = %v after %d polls, want one poll and a permanent failure", status, err, len(a.calls()))
			}
		}
	})
}

// The engine records a commitment under its own key for the completion, the
// completion id followed by "-<choice index>-<8 hex>", and request_id
// carries that key. Such a document is the asked completion's and is signed;
// any other request_id is another completion's.
func TestInferAcceptsTheEngineKeyOfTheAskedCompletion(t *testing.T) {
	for id, want := range map[string]bool{
		"chatcmpl-test":                 true,
		"chatcmpl-test-0-bd50afd1":      true,
		"chatcmpl-test-12-0123abcd":     true,
		"chatcmpl-test-bd50afd1":        true,
		"chatcmpl-test2-0-bd50afd1":     false,
		"chatcmpl-test-0-BD50AFD1":      false,
		"chatcmpl-test-0-bd50afd":       false,
		"chatcmpl-test-0-bd50afd1-x":    false,
		"chatcmpl-test-other":           false,
		"chatcmpl-tes":                  false,
		"xchatcmpl-test-0-bd50afd1":     false,
		"chatcmpl-test-0-1-bd50afd1":    false,
		"chatcmpl-SOMEONE-0-bd50afd1":   false,
		"chatcmpl-test--bd50afd1":       false,
		"chatcmpl-test-0-bd50afd1\n":    false,
		"chatcmpl-test-0-bd50afd1 ":     false,
		"chatcmpl-test-0-bd50afd10":     false,
		"chatcmpl-test-0x-bd50afd1":     false,
		"chatcmpl-test-00000000":        true,
		"chatcmpl-test-0-00000000-0000": false,
	} {
		if got := anchorCommitNamesCompletion(id, "chatcmpl-test"); got != want {
			t.Errorf("anchorCommitNamesCompletion(%q) = %v, want %v", id, got, want)
		}
	}
	body := strings.Replace(testAnchorCommit, `"request_id":"chatcmpl-test"`, `"request_id":"chatcmpl-test-0-bd50afd1"`, 1)
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, body }}
	svc := anchorTestService(t, a)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	resp, err := svc.Infer(context.Background(), req)
	if err != nil || resp.AnchorCommitRef == "" {
		t.Fatalf("Infer() = %+v, %v, want the commitment recorded under the engine's key signed", resp, err)
	}
	artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.AnchorCommitRef})
	if err != nil || string(artifact.Data) != body {
		t.Fatalf("anchor artifact %q, %v, want the served bytes unchanged", artifact.Data, err)
	}
}

// A completion that delivered no generated token (a budget that ran out
// before the first one) has no anchor commitment: the engine issues none
// over a prompt alone and would answer 409. The Worker does not ask, does
// not loop and signs nothing: the call ends with a deterministic fault.
func TestAttachAnchorCommitRefusesAnEmptyGeneration(t *testing.T) {
	a := &anchorSidecar{
		info: func() int { return http.StatusOK }, infoBody: `{"commit_prefix":["generated","rows"]}`,
		commit: func(int, string) (int, string) {
			return http.StatusConflict, `{"error":"generated=0: no commitment over a prompt alone"}`
		},
	}
	svc := anchorTestService(t, a)
	raw, err := EncodeTokenIDsArtifact(TokenIDs{Input: []uint32{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	delivered := InferResponse{EngineRequestID: "chatcmpl-test", TokenIDsRef: svc.putArtifact(raw)}
	resp, err := svc.attachAnchorCommit(context.Background(), InferRequest{RequireAnchorCommit: true}, delivered)
	if !errors.Is(err, ErrAnchorCommitEmptyGeneration) || resp.AnchorCommitRef != "" {
		t.Fatalf("attachAnchorCommit() = %+v, %v, want ErrAnchorCommitEmptyGeneration and no anchor ref", resp, err)
	}
	if ClassOf(err) != FaultDeterministic || IsRetryable(err) || FaultCode(err) != FaultCodeAnchorCommitEmptyGeneration {
		t.Fatalf("err = %v (class %v, code %q), want a deterministic %s", err, ClassOf(err), FaultCode(err), FaultCodeAnchorCommitEmptyGeneration)
	}
	if n := len(a.calls()); n != 0 {
		t.Fatalf("the sidecar was asked %d times for a commitment that cannot exist", n)
	}
	// Without the requirement an empty generation is what it always was.
	if resp, err := svc.attachAnchorCommit(context.Background(), InferRequest{}, delivered); err != nil || resp.AnchorCommitRef != "" {
		t.Fatalf("a task that requires no anchor: %+v, %v", resp, err)
	}
}

// The two shapes of the engine's key seen on a real engine, and what must
// not pass for them: the tail is one optional run of digits and exactly
// eight lowercase hex characters, each after its own "-", and the asked id
// must be followed by that "-", so a completion whose id merely starts with
// the asked one is another completion.
func TestAnchorCommitNamesCompletionRealForms(t *testing.T) {
	for _, c := range []struct {
		requestID, asked string
		want             bool
	}{
		{"cmpl-822ecaa38c0c278b-0-bd50afd1", "cmpl-822ecaa38c0c278b", true},         // completions
		{"cmpl-822ecaa38c0c278b-3-bd50afd1", "cmpl-822ecaa38c0c278b", true},         // another choice index
		{"chatcmpl-9f3a61c2d4e5f607-bd50afd1", "chatcmpl-9f3a61c2d4e5f607", true},   // chat completions: no index
		{"chatcmpl-9f3a61c2d4e5f607", "chatcmpl-9f3a61c2d4e5f607", true},            // the id itself
		{"chatcmpl-9f3a61c2d4e5f607-bd50afd", "chatcmpl-9f3a61c2d4e5f607", false},   // 7 hex
		{"chatcmpl-9f3a61c2d4e5f607-bd50afd12", "chatcmpl-9f3a61c2d4e5f607", false}, // 9 hex
		{"chatcmpl-9f3a61c2d4e5f607-BD50AFD1", "chatcmpl-9f3a61c2d4e5f607", false},  // upper case
		{"chatcmpl-9f3a61c2d4e5f607-bd50afg1", "chatcmpl-9f3a61c2d4e5f607", false},  // not hex
		{"chatcmpl-9f3a61c2d4e5f607-0-1-bd50afd1", "chatcmpl-9f3a61c2d4e5f607", false},
		{"chatcmpl-9f3a61c2d4e5f607-bd50afd1-0", "chatcmpl-9f3a61c2d4e5f607", false},
		{"chatcmpl-9f3a61c2d4e5f607-bd50afd1-bd50afd1", "chatcmpl-9f3a61c2d4e5f607", false},
		{"chatcmpl-9f3a61c2d4e5f607--bd50afd1", "chatcmpl-9f3a61c2d4e5f607", false},
		{"chatcmpl-9f3a61c2d4e5f607bd50afd1", "chatcmpl-9f3a61c2d4e5f607", false}, // no separator
		{"cmpl-12-0-bd50afd1", "cmpl-1", false},                                   // id that starts with the asked one
		{"cmpl-12-bd50afd1", "cmpl-1", false},
		{"cmpl-1bd50afd1", "cmpl-1", false},
		{"cmpl-10-bd50afd1", "cmpl-1", false},
		{"cmpl-1-0-bd50afd1", "cmpl-1", true},
		{"cmpl-1-bd50afd1", "cmpl-1", true},
		{"cmpl-1-0-bd50afd1", "cmpl-1-0", true},   // asked by the id with its index
		{"cmpl-1-0-bd50afd1", "cmpl-1-0-", false}, // not an id the engine issues
		{"cmpl-1-0-bd50afd1", "", false},
		{"", "cmpl-1", false},
	} {
		if got := anchorCommitNamesCompletion(c.requestID, c.asked); got != c.want {
			t.Errorf("anchorCommitNamesCompletion(%q, asked %q) = %v, want %v", c.requestID, c.asked, got, c.want)
		}
	}
	// End to end, in the chat form: the stub completion is chatcmpl-test.
	body := strings.Replace(testAnchorCommit, `"request_id":"chatcmpl-test"`, `"request_id":"chatcmpl-test-bd50afd1"`, 1)
	a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, body }}
	svc := anchorTestService(t, a)
	req := chatInferReq(t)
	req.RequireAnchorCommit = true
	if resp, err := svc.Infer(context.Background(), req); err != nil || resp.AnchorCommitRef == "" {
		t.Fatalf("Infer() = %+v, %v, want the chat-form commitment signed", resp, err)
	}
}

// zeroTokenRawEngine is a /v1/completions stream that emits the prompt and
// no generated token before the output budget runs out.
func zeroTokenRawEngine(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 2; i++ {
			frame := `{"id":"cmpl-test","choices":[{"text":"","prompt_token_ids":[1,2,3],"token_ids":[]}]}`
			if i > 0 {
				frame = `{"id":"cmpl-test","choices":[{"text":"","token_ids":[]}]}`
			}
			fmt.Fprintf(w, "data: %s\n\n", frame)
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(150 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// zeroTokenChatEngine is a /v1/chat/completions stream that names the
// completion and the prompt and then generates nothing before the output
// budget runs out, or (finishAtOnce) ends at once with no token at all.
func zeroTokenChatEngine(t *testing.T, finishAtOnce bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			writeVLLMMetrics(w, 0, 0)
			return
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]any{{"id": "Qwen/Qwen3-8B", "object": "model"}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "data: %s\n\n", `{"id":"chatcmpl-test","model":"Qwen/Qwen3-8B","prompt_token_ids":[1,2,3],"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`)
		flusher.Flush()
		if finishAtOnce {
			fmt.Fprintf(w, "data: %s\n\n", `{"id":"chatcmpl-test","model":"Qwen/Qwen3-8B","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
			fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}
		// The engine is still working on its first token when the budget
		// runs out: frames keep arriving, none carries a token.
		for i := 0; i < 2; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(150 * time.Millisecond):
			}
			fmt.Fprintf(w, "data: %s\n\n", `{"id":"chatcmpl-test","model":"Qwen/Qwen3-8B","choices":[{"index":0,"delta":{"content":""}}]}`)
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// An engine that never sends a generated token, through Infer, on both paths.
// Without the anchor requirement a budget that ran out before the first token
// is the legal empty MAX_OUTPUT_DURATION generation on the raw path and on
// the chat path alike. Under a Profile requiring WORKER_ANCHOR_OPENING the
// budget stop is not taken before the first token (an empty generation has no
// anchor commitment, see TestBudgetStopUnderAnAnchorProfileWaitsForTheFirstToken
// for an engine that does generate): a stream that ends without one is the
// truncated stream it is on every path, the sidecar is not asked, and no
// anchor ref is produced.
func TestInferEmptyGenerationOnBothPaths(t *testing.T) {
	type path struct {
		name   string
		engine func(t *testing.T) *httptest.Server
		req    func(t *testing.T) InferRequest
	}
	budget := func(t *testing.T, req InferRequest) InferRequest {
		t.Helper()
		req.Generation.Params.MaxOutputDuration = 50
		digest, err := req.Generation.Digest()
		if err != nil {
			t.Fatal(err)
		}
		req.GenerationParamsDigest = digest[:]
		return req
	}
	paths := []path{
		{"raw", zeroTokenRawEngine, func(t *testing.T) InferRequest {
			return budget(t, localGenerationInfer(t, localTestGeneration(testQwenModelID(), 1)))
		}},
		{"chat", func(t *testing.T) *httptest.Server { return zeroTokenChatEngine(t, false) }, func(t *testing.T) InferRequest {
			return budget(t, chatInferReq(t))
		}},
	}
	for _, p := range paths {
		t.Run(p.name+", no anchor required", func(t *testing.T) {
			a := &anchorSidecar{}
			svc := newBoundLocalService(a.front(t, p.engine(t)).URL, "local", 4, 0, 0)
			resp, err := svc.Infer(context.Background(), p.req(t))
			if err != nil {
				t.Fatalf("Infer() error = %v, want the legal empty generation", err)
			}
			if resp.GeneratedTokenCount != 0 || resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration || resp.AnchorCommitRef != "" {
				t.Fatalf("response = %+v, want zero tokens, MAX_OUTPUT_DURATION and no anchor ref", resp)
			}
			if n := len(a.calls()); n != 0 {
				t.Fatalf("the sidecar was asked %d times for a task that requires no anchor", n)
			}
		})
		t.Run(p.name+", anchor required", func(t *testing.T) {
			a := &anchorSidecar{
				info: func() int { return http.StatusOK }, infoBody: `{"commit_prefix":["generated","rows"]}`,
				commit: func(int, string) (int, string) { return http.StatusConflict, `{"error":"generated=0"}` },
			}
			svc := newBoundLocalService(a.front(t, p.engine(t)).URL, "local", 4, 0, 0)
			req := p.req(t)
			req.RequireAnchorCommit = true
			resp, err := svc.Infer(context.Background(), req)
			if err == nil || resp.AnchorCommitRef != "" || resp.GeneratedTokenCount != 0 {
				t.Fatalf("Infer() = %+v, %v, want no empty generation and no anchor ref", resp, err)
			}
			if FaultCode(err) != "MODEL_STREAM_TRUNCATED" || errors.Is(err, ErrAnchorCommitEmptyGeneration) {
				t.Fatalf("err = %v (code %q), want the truncated stream of an engine that sent no token", err, FaultCode(err))
			}
			if n := len(a.calls()); n != 0 {
				t.Fatalf("the sidecar was asked %d times for a commitment that cannot exist", n)
			}
		})
	}
	// A chat completion the engine ends at once, with a finish reason and no
	// token. The chat path used to fail here on its own, with an unclassified
	// "token_ids (0) / logprobs (0) length mismatch". Now it is treated as on
	// the completions path: the model service reports it and the Worker's
	// finish check refuses it by name; under an anchor Profile the missing
	// commitment is named first.
	t.Run("chat, finished at once", func(t *testing.T) {
		svc := newBoundLocalService(zeroTokenChatEngine(t, true).URL, "local", 4, 0, 0)
		req := chatInferReq(t)
		resp, err := svc.Infer(context.Background(), req)
		if err != nil || resp.GeneratedTokenCount != 0 {
			t.Fatalf("Infer() = %+v, %v, want the zero-token response reported", resp, err)
		}
		if err := ValidateFinishReason(req.Generation, nil, resp.FinishReason); FaultCode(err) != FaultCodeFinishReasonInconsistent {
			t.Fatalf("finish check = %v, want %s", err, FaultCodeFinishReasonInconsistent)
		}
		a := &anchorSidecar{}
		svc = newBoundLocalService(a.front(t, zeroTokenChatEngine(t, true)).URL, "local", 4, 0, 0)
		req.RequireAnchorCommit = true
		if _, err := svc.Infer(context.Background(), req); FaultCode(err) != FaultCodeAnchorCommitEmptyGeneration || len(a.calls()) != 0 {
			t.Fatalf("err = %v after %d sidecar calls, want %s and none", err, len(a.calls()), FaultCodeAnchorCommitEmptyGeneration)
		}
	})
}

// lateTokenRawEngine is a /v1/completions stream of a real engine under a
// budget that runs out during the prefill: a first frame that names the prompt
// and carries no token, then one generated token per frame every gap.
func lateTokenRawEngine(t *testing.T, gap time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		time.Sleep(gap) // the prefill outlasts the budget
		fmt.Fprintf(w, "data: %s\n\n", `{"id":"cmpl-test","choices":[{"text":"","prompt_token_ids":[1,2,3],"token_ids":[]}]}`)
		flusher.Flush()
		for i := 0; i < 6; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(gap):
			}
			id := 10 + i
			frame := map[string]any{"id": "cmpl-test", "choices": []map[string]any{{"text": "x", "token_ids": []int{id},
				"logprobs": map[string]any{"token_logprobs": []float64{-0.1},
					"top_logprobs": []TopLogprobRow{fullTopRow(TopLogprob{Token: fmt.Sprintf("token_id:%d", id), Logprob: -0.1})}}}}}
			payload, _ := json.Marshal(frame)
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// lateTokenChatEngine is the chat counterpart: the role preamble a chat
// stream opens with (no token), then one generated token per frame.
func lateTokenChatEngine(t *testing.T, gap time.Duration) *httptest.Server {
	t.Helper()
	chunks := []chatCompletionChunk{{
		ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B", PromptTokenIDs: []int{1, 2, 3},
		Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{Role: "assistant"}}},
	}}
	for i := 0; i < 6; i++ {
		id := 10 + i
		key := fmt.Sprintf("token_id:%d", id)
		chunks = append(chunks, chatCompletionChunk{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{Index: 0, Delta: chatChunkDelta{Content: "x"}, TokenIDs: []int{id},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: key, Logprob: -0.1, Bytes: helloBytes, TopLogprobs: []chatRespTopLogprob{{Token: key, Logprob: -0.1}}},
				}}}},
		})
	}
	return newSlowChatStreamStub(t, chunks, gap, []string{"Qwen/Qwen3-8B"})
}

// The output budget runs out before the engine's first token (a long prefill,
// a short max_output_duration). Without the anchor requirement the stop is
// taken at the first frame past the budget and the generation is the legal
// empty one, exactly as before. Under a Profile requiring
// WORKER_ANCHOR_OPENING an empty generation would leave the Worker with no
// commitment and no receipt, so the stop is taken at the first frame that
// leaves a token delivered: one token, MAX_OUTPUT_DURATION, the commitment
// fetched at ?generated=1 and signed.
func TestBudgetStopUnderAnAnchorProfileWaitsForTheFirstToken(t *testing.T) {
	const gap = 120 * time.Millisecond
	budget := func(t *testing.T, req InferRequest) InferRequest {
		t.Helper()
		req.Generation.Params.MaxOutputDuration = 40 // over at the first frame of both engines
		digest, err := req.Generation.Digest()
		if err != nil {
			t.Fatal(err)
		}
		req.GenerationParamsDigest = digest[:]
		return req
	}
	type path struct {
		name, completion string
		engine           func(t *testing.T) *httptest.Server
		req              func(t *testing.T) InferRequest
	}
	paths := []path{
		{"raw", "cmpl-test", func(t *testing.T) *httptest.Server { return lateTokenRawEngine(t, gap) }, func(t *testing.T) InferRequest {
			return budget(t, localGenerationInfer(t, localTestGeneration(testQwenModelID(), 1)))
		}},
		{"chat", "chatcmpl-test", func(t *testing.T) *httptest.Server { return lateTokenChatEngine(t, gap) }, func(t *testing.T) InferRequest {
			return budget(t, chatInferReq(t))
		}},
	}
	for _, p := range paths {
		t.Run(p.name+", no anchor required", func(t *testing.T) {
			a := &anchorSidecar{}
			svc := newBoundLocalService(a.front(t, p.engine(t)).URL, "local", 4, 0, 0)
			resp, err := svc.Infer(context.Background(), p.req(t))
			if err != nil {
				t.Fatalf("Infer() error = %v, want the legal empty generation", err)
			}
			if resp.GeneratedTokenCount != 0 || resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration || resp.AnchorCommitRef != "" {
				t.Fatalf("response = %+v, want zero tokens, MAX_OUTPUT_DURATION and no anchor ref (unchanged behaviour)", resp)
			}
			if n := len(a.calls()); n != 0 {
				t.Fatalf("the sidecar was asked %d times for a task that requires no anchor", n)
			}
		})
		t.Run(p.name+", anchor required", func(t *testing.T) {
			commit := fmt.Sprintf(`{"request_id":%q,"roots":["00"],"token_ids":[1,2,3,10],"prompt_tokens":3,"rows":3}`, p.completion)
			a := &anchorSidecar{
				info: func() int { return http.StatusOK }, infoBody: `{"commit_prefix":["generated","rows"]}`,
				commitAt: func(_ int, _, generated string) (int, string) {
					if generated != "1" {
						return http.StatusConflict, `{"error":"a commitment needs at least one generated token"}`
					}
					return http.StatusOK, commit
				},
			}
			svc := newBoundLocalService(a.front(t, p.engine(t)).URL, "local", 4, 0, 0)
			svc.anchorCommitBackoff = time.Millisecond
			req := p.req(t)
			req.RequireAnchorCommit = true
			start := time.Now()
			resp, err := svc.Infer(context.Background(), req)
			if err != nil {
				t.Fatalf("Infer() error = %v, want a one-token MAX_OUTPUT_DURATION generation with its commitment", err)
			}
			if resp.GeneratedTokenCount != 1 || resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration || resp.AnchorCommitRef == "" {
				t.Fatalf("response = %+v, want exactly one token, MAX_OUTPUT_DURATION and an anchor ref", resp)
			}
			if took := time.Since(start); took > 3*gap+time.Second {
				t.Fatalf("the stop was taken after %s, want it at the first token frame", took)
			}
			a.mu.Lock()
			queries := append([]string(nil), a.queries...)
			a.mu.Unlock()
			if len(queries) != 1 || queries[0] != "generated=1" {
				t.Fatalf("commit queries %q, want one fetch at generated=1", queries)
			}
			artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.AnchorCommitRef})
			if err != nil || string(artifact.Data) != commit {
				t.Fatalf("anchor artifact %q, %v, want the served commitment", artifact.Data, err)
			}
			if err := ValidateFinishReason(req.Generation, nil, resp.FinishReason); err != nil {
				t.Fatalf("the Worker's finish check refuses the one-token budget stop: %v", err)
			}
		})
	}
}

// budgetStopAllowed is the whole rule: without the anchor requirement any
// frame boundary past the budget is a stopping point; with it, only one that
// leaves a generated token delivered.
func TestBudgetStopAllowed(t *testing.T) {
	for _, c := range []struct {
		needs     bool
		delivered int
		want      bool
	}{{false, 0, true}, {false, 1, true}, {true, 0, false}, {true, 1, true}, {true, 7, true}} {
		if got := (inferStreamIdentity{budgetStopNeedsToken: c.needs}).budgetStopAllowed(c.delivered); got != c.want {
			t.Fatalf("budgetStopAllowed(needs=%t, delivered=%d) = %t, want %t", c.needs, c.delivered, got, c.want)
		}
	}
}
