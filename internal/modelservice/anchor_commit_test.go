package modelservice

import (
	"context"
	"errors"
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
			_, _ = w.Write([]byte(`{}`))
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
	const ranAhead = `{"request_id":"chatcmpl-test","roots":["ff"],"token_ids":[1,2,3,10,11,12],"prompt_tokens":3,"rows":5}`
	t.Run("the sidecar finalises at the prefix", func(t *testing.T) {
		a := &anchorSidecar{commitAt: func(call int, _, generated string) (int, string) {
			switch {
			case generated != "2":
				return http.StatusOK, ranAhead
			case call == 1:
				return http.StatusServiceUnavailable, `{"error":"finalising the prefix"}`
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
	t.Run("a sidecar that ignores the prefix is refused, not signed", func(t *testing.T) {
		a := &anchorSidecar{commit: func(int, string) (int, string) { return http.StatusOK, ranAhead }}
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
	t.Run("a prefix the engine never reached is not polled", func(t *testing.T) {
		a := &anchorSidecar{commit: func(int, string) (int, string) {
			return http.StatusConflict, `{"error":"generated 1 token, asked for 2"}`
		}}
		svc := anchorTestService(t, a)
		req := chatInferReq(t)
		req.RequireAnchorCommit = true
		if _, err := svc.Infer(context.Background(), req); err == nil || IsRetryable(err) || len(a.calls()) != 1 {
			t.Fatalf("err = %v after %d polls, want one poll and a permanent failure", err, len(a.calls()))
		}
	})
}
