package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ADR-0040 anchor commitments. An engine with the anchor sidecar serves, for
// every finished completion, an AnchorCommitV1 document under the completion
// id (GET /slp/commit/{id}) and advertises itself on GET /slp/info. Only a
// task whose locked Profile requires WORKER_ANCHOR_OPENING ever asks for it.
//
// The delivered prefix. The Worker signs a receipt over the tokens it
// delivered, and those can be fewer than the engine generated. There is one
// place where this node, not the engine, ends a generation that then gets a
// receipt: max_output_duration. The stream readers stop at the first frame
// boundary past that budget (reassembleChatStream and its completions
// counterpart) while the engine runs on until the disconnect reaches it.
// max_output_tokens is not such a place: it is handed to the engine as
// max_tokens, the engine stops there itself and does not run ahead of it. A
// caller that goes away fails the call, and no commitment is fetched for it.
// So it is duration cut-offs that exercise the prefix. The fetch names the
// prefix it wants,
//
//	GET /slp/commit/{id}?generated=<n>
//
// where n is the number of generated token ids this completion delivered
// (the prompt is not counted, a delivered EOS is). A sidecar that knows the
// parameter answers with the commitment finalised at exactly that prefix:
// token_ids is the prompt followed by the first n generated ids,
// prompt_tokens the prompt length, rows prompt + n - 1, and every root is
// over those rows only. It finalises the prefix while it answers, and
// answers 409 when it cannot serve that prefix: it generated fewer than n
// tokens, it already finalised this completion at another n, n is 0 (it
// issues no commitment over a prompt alone), or the prefix ends inside a
// prefill segment that was preempted and recomputed; 400 is a malformed
// parameter. Neither is polled.
//
// An engine says that it knows the parameter by listing "generated" under
// "commit_prefix" in GET /slp/info, and the parameter is sent only to an
// engine that does. One that does not is asked without it and serves the
// whole trajectory; the self-check below then refuses a commitment that
// names more than was delivered, so nothing is signed over it either way.
//
// A completion that delivered no generated token has no commitment to fetch
// and none is asked for: the call fails with ErrAnchorCommitEmptyGeneration.
// The engine cannot issue one. Its rows are positions 0..L+G-2, the last of
// them bound to the next token, so a prompt alone would end one row short of
// its own prefill segment, and that segment cannot be cut (its length fixes
// how the engine computed it). The one honest way to such a completion was a
// max_output_duration that ran out before the first token, and for a request
// with RequireAnchorCommit the stream readers no longer stop there: they take
// the budget stop at the first frame that leaves a token delivered
// (inferStreamIdentity.budgetStopNeedsToken), so the Worker has a
// commitment, at ?generated=1 or later, and a receipt. What is left for
// ErrAnchorCommitEmptyGeneration is an engine that ends a completion itself
// with no token, which the finish-reason check refuses under every Profile.

const (
	// maxAnchorCommitBytes bounds the AnchorCommitV1 document: it holds token
	// ids, Merkle roots and checkpoint hashes, never anchors themselves.
	maxAnchorCommitBytes = 16 << 20
	// maxAnchorInfoBytes bounds what is read of GET /slp/info.
	maxAnchorInfoBytes = 1 << 20
	// anchorCommitGeneratedParam is the query parameter of GET
	// /slp/commit/{id} that names the delivered prefix.
	anchorCommitGeneratedParam = "generated"
	// defaultAnchorCommitTimeout is the default commitment window after the
	// generation has ended.
	defaultAnchorCommitTimeout = 120 * time.Second
	// defaultAnchorCommitBackoff is the first wait after a 503; it doubles up
	// to maxAnchorCommitBackoff.
	defaultAnchorCommitBackoff = 250 * time.Millisecond
	maxAnchorCommitBackoff     = 5 * time.Second
	// defaultAnchorCommitNotFoundGrace is how long a 404 for a completion
	// that has just ended is polled before it is believed. The sidecar
	// answers 503 from the engine step that first schedules a request until
	// its commitment is final, and 404 only for an id it does not hold, so a
	// 404 here should already be final; the grace covers a sidecar (or a
	// proxy in front of it) that learns of the completion a moment after the
	// response was written, at the price of failing a truly lost commitment
	// ten seconds later.
	defaultAnchorCommitNotFoundGrace = 10 * time.Second
	// anchorInfoOKTTL and anchorInfoFailTTL are how long a /slp/info verdict
	// is reused. A failure is retried sooner so an engine that has just come
	// up is picked up quickly.
	anchorInfoOKTTL   = 5 * time.Minute
	anchorInfoFailTTL = time.Minute
	// anchorInfoProbeFailTTL is how long a probe that got no answer
	// (ErrAnchorCommitProbeFailed) is reused. It is not a verdict about the
	// engine, and while it is cached every offer for a kind 5 Profile is left
	// unanswered, so it is asked again after a few seconds, not a minute.
	anchorInfoProbeFailTTL = 5 * time.Second
)

// ErrAnchorCommitNotFound is a 404 from /slp/commit/{id} that outlasted
// anchorCommitNotFoundGrace: the engine has no anchor sidecar, or the sidecar
// does not hold the completion.
var ErrAnchorCommitNotFound = errors.New("engine has no anchor commitment for the completion")

// ErrAnchorCommitUnsupported means the model service cannot serve ADR-0040
// anchor commitments at all.
var ErrAnchorCommitUnsupported = errors.New("model service does not serve anchor commitments")

// ErrAnchorCommitProbeFailed means the capability probe got no answer: the
// engine did not respond in time, refused the connection or answered 5xx.
// It says nothing about whether the engine serves anchor commitments.
var ErrAnchorCommitProbeFailed = errors.New("anchor capability probe failed")

// ErrAnchorCommitMismatch means the engine's AnchorCommitV1 commits to a token
// sequence other than the one this completion delivered. The validators bind
// the commitment's token_ids to the receipt's token hashes, so signing a receipt
// over such a commitment would hand them a deterministic reason to slash and
// jail the Worker; the call fails instead and no receipt is produced.
var ErrAnchorCommitMismatch = errors.New("anchor commitment does not match the delivered tokens")

// checkAnchorCommitTokens is the Worker-side self-check of a fetched
// AnchorCommitV1 against the token ids this completion delivered: token_ids must
// be exactly input ++ generated, prompt_tokens (when present) the input length
// and rows (when present) input + generated − 1 — the relations the chain
// (anchorRowsOf) and the validators (check_token_binding) enforce.
func checkAnchorCommitTokens(data []byte, ids TokenIDs) error {
	var doc struct {
		TokenIDs     []int64 `json:"token_ids"`
		PromptTokens *int64  `json:"prompt_tokens"`
		Rows         *int64  `json:"rows"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrAnchorCommitMismatch, err)
	}
	l, g := len(ids.Input), len(ids.Generated)
	if doc.TokenIDs == nil {
		return fmt.Errorf("%w: the commitment carries no token_ids", ErrAnchorCommitMismatch)
	}
	if len(doc.TokenIDs) != l+g {
		return fmt.Errorf("%w: the commitment names %d token ids, the completion delivered %d prompt + %d generated", ErrAnchorCommitMismatch, len(doc.TokenIDs), l, g)
	}
	for i, id := range doc.TokenIDs {
		want := uint32(0)
		if i < l {
			want = ids.Input[i]
		} else {
			want = ids.Generated[i-l]
		}
		if id < 0 || id > math.MaxUint32 || uint32(id) != want {
			return fmt.Errorf("%w: token id at position %d is %d in the commitment, %d delivered", ErrAnchorCommitMismatch, i, id, want)
		}
	}
	if doc.PromptTokens != nil && *doc.PromptTokens != int64(l) {
		return fmt.Errorf("%w: prompt_tokens %d in the commitment, %d prompt ids delivered", ErrAnchorCommitMismatch, *doc.PromptTokens, l)
	}
	if doc.Rows != nil && l+g > 0 && *doc.Rows != int64(l+g-1) {
		return fmt.Errorf("%w: rows %d in the commitment, %d expected (prompt + generated − 1)", ErrAnchorCommitMismatch, *doc.Rows, l+g-1)
	}
	return nil
}

// AnchorCommitProber is implemented by a model service that can tell whether
// its engine serves ADR-0040 anchor commitments. A Worker consults it before
// offering a Profile that requires WORKER_ANCHOR_OPENING.
type AnchorCommitProber interface {
	// AnchorCommitCapable returns nil when the engine serves anchor
	// commitments. The verdict may be cached for a few minutes.
	AnchorCommitCapable(context.Context) error
}

var _ AnchorCommitProber = (*LocalService)(nil)

type anchorInfoCache struct {
	mu      sync.Mutex
	checked time.Time
	err     error
	// info is what the last answered probe declared; it outlives a later
	// probe that got no answer.
	info anchorEngineInfo
}

// anchorEngineInfo is the part of GET /slp/info this node reads. An engine
// that predates a field simply does not send it.
type anchorEngineInfo struct {
	// CommitPrefix lists the query parameters of GET /slp/commit/{id} that
	// name a prefix to finalise the commitment at.
	CommitPrefix []string `json:"commit_prefix"`
}

// anchorCommitPrefixDeclared reports whether the engine declared, on its last
// answered probe, that it finalises a commitment at ?generated=<n>. The probe
// is cached, so this costs a request only when the cache has run out.
func (s *LocalService) anchorCommitPrefixDeclared(ctx context.Context) bool {
	_ = s.AnchorCommitCapable(ctx)
	s.anchorInfo.mu.Lock()
	defer s.anchorInfo.mu.Unlock()
	return slices.Contains(s.anchorInfo.info.CommitPrefix, anchorCommitGeneratedParam)
}

// SetAnchorCommitTimeout sets the commitment window after the generation
// (anchorCommitTimeout). Zero or negative restores the default.
func (s *LocalService) SetAnchorCommitTimeout(d time.Duration) {
	s.anchorCommitTimeout = d
}

func (s *LocalService) anchorCommitWindow() time.Duration {
	if s.anchorCommitTimeout > 0 {
		return s.anchorCommitTimeout
	}
	return defaultAnchorCommitTimeout
}

// attachAnchorCommit fetches the AnchorCommitV1 of a finished generation when
// the request requires it and adds it to resp as AnchorCommitRef. ctx must be
// the caller's context: the fetch runs under its own anchorCommitWindow, not
// under any deadline of the generation, so a generation stopped at
// max_output_duration is not failed by the time the engine needs to finalize.
func (s *LocalService) attachAnchorCommit(ctx context.Context, req InferRequest, resp InferResponse) (InferResponse, error) {
	if !req.RequireAnchorCommit {
		return resp, nil
	}
	if resp.EngineRequestID == "" {
		return InferResponse{}, fmt.Errorf("modelservice local: the locked Profile requires WORKER_ANCHOR_OPENING but the engine returned no completion id to fetch its anchor commitment by")
	}
	// The delivered token ids come first: the fetch names their count as the
	// prefix the commitment must be finalised at, and the self-check compares
	// the commitment with them before anything is signed.
	artifact, err := s.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.TokenIDsRef})
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local: anchor commitment self-check: token ids artifact: %w", err)
	}
	ids, err := DecodeTokenIDsArtifact(artifact.Data)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local: anchor commitment self-check: %w", err)
	}
	if len(ids.Generated) == 0 {
		// Deterministic: the engine commits to rows, and a prompt with no
		// generated token has none to open. Asking would be answered 409;
		// generating again would spend another generation on the same order.
		return InferResponse{}, Deterministic(FaultCodeAnchorCommitEmptyGeneration,
			fmt.Errorf("modelservice local: the locked Profile requires WORKER_ANCHOR_OPENING: %w", ErrAnchorCommitEmptyGeneration),
			FaultStr("completion_id", resp.EngineRequestID))
	}
	data, err := s.fetchAnchorCommit(ctx, resp.EngineRequestID, len(ids.Generated))
	if err != nil {
		if errors.Is(err, ErrAnchorCommitNotFound) {
			return InferResponse{}, fmt.Errorf("modelservice local: the locked Profile requires WORKER_ANCHOR_OPENING: %w", err)
		}
		return InferResponse{}, err
	}
	if err := checkAnchorCommitTokens(data, ids); err != nil {
		// Deterministic: retrying spends another generation (and on the
		// streaming path stops at OUTPUT_FRAMES_ALREADY_SIGNED, hiding this
		// reason) on an engine that commits to other tokens.
		return InferResponse{}, Deterministic(FaultCodeAnchorCommitTokenMismatch,
			fmt.Errorf("modelservice local: refusing to sign a receipt over an anchor commitment that does not match this completion: %w", err),
			FaultStr("completion_id", resp.EngineRequestID))
	}
	if err := s.checkAnchorCommitSeedRule(data, req); err != nil {
		// Deterministic for the same reason: the commitment of this
		// completion will not change.
		return InferResponse{}, Deterministic(FaultCodeAnchorCommitSeedRule,
			fmt.Errorf("modelservice local: refusing to sign a receipt over an anchor commitment sampled outside the seed rule: %w", err),
			FaultStr("completion_id", resp.EngineRequestID))
	}
	resp.AnchorCommitRef = s.putArtifact(data)
	return resp, nil
}

// ErrAnchorCommitSeedRule means the seed binding is on, the order was
// sampled, and the engine's AnchorCommitV1 does not declare the seed rule:
// the engine sampled with a seed the validators will not reproduce.
var ErrAnchorCommitSeedRule = errors.New("anchor commitment does not declare the seed rule")

// checkAnchorCommitSeedRule is the second half of the self-check, made only
// while the seed binding is on and only for an order that samples
// (sampling_enabled with a temperature above zero): the commitment's
// "seed_rule" must be the configured rule. The validators require exactly
// that field of a sampled order's commitment before they recompute the seed.
// A greedy order draws nothing from the seed and is not checked.
func (s *LocalService) checkAnchorCommitSeedRule(data []byte, req InferRequest) error {
	if s.anchorSeedRule == "" || req.Generation == nil {
		return nil
	}
	if d := req.Generation.Params.DecodingParams; !d.SamplingEnabled || d.TemperatureMilli == 0 {
		return nil
	}
	var doc struct {
		SeedRule *string `json:"seed_rule"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrAnchorCommitSeedRule, err)
	}
	if doc.SeedRule == nil {
		return fmt.Errorf("%w: no \"seed_rule\", %q is required of a sampled order (does the engine predate the rule?)", ErrAnchorCommitSeedRule, s.anchorSeedRule)
	}
	if *doc.SeedRule != s.anchorSeedRule {
		return fmt.Errorf("%w: \"seed_rule\" is %q, %q is required", ErrAnchorCommitSeedRule, *doc.SeedRule, s.anchorSeedRule)
	}
	return nil
}

// fetchAnchorCommit polls GET /slp/commit/{id}, with ?generated=<generated>
// for an engine that declares the parameter, until the engine serves the
// commitment or the anchorCommitWindow ends. 503 means the sidecar is still
// finalizing it and is retried with backoff, as are transport errors and other
// 5xx; 404 is polled for anchorCommitNotFoundGrace from the first one and then
// ends the poll with ErrAnchorCommitNotFound; any other answer, or a body
// that is not an AnchorCommitV1 document, ends it with an error. None of
// these errors is retryable at the Infer level: generating again would yield
// another completion, not this one's commitment.
func (s *LocalService) fetchAnchorCommit(parent context.Context, completionID string, generated int) ([]byte, error) {
	window := s.anchorCommitWindow()
	ctx, cancel := context.WithTimeout(parent, window)
	defer cancel()
	path := "/slp/commit/" + url.PathEscape(completionID)
	if s.anchorCommitPrefixDeclared(ctx) {
		path += "?" + anchorCommitGeneratedParam + "=" + strconv.Itoa(generated)
	}
	backoff := s.anchorCommitBackoff
	if backoff <= 0 {
		backoff = defaultAnchorCommitBackoff
	}
	grace := s.anchorCommitNotFoundGrace
	if grace == 0 {
		grace = defaultAnchorCommitNotFoundGrace
	}
	var last error
	var notFoundSince time.Time
	for attempt := 1; ; attempt++ {
		data, retry, err := s.getAnchorCommitOnce(ctx, path, completionID)
		if err == nil {
			return data, nil
		}
		if !retry {
			return nil, err
		}
		if errors.Is(err, ErrAnchorCommitNotFound) {
			if notFoundSince.IsZero() {
				notFoundSince = time.Now()
			}
			if time.Since(notFoundSince) >= grace {
				return nil, err
			}
		}
		last = err
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			if err := parent.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("modelservice local: %s not served within the %s anchor commitment window (%d attempts): %w", path, window, attempt, last)
		case <-timer.C:
		}
		backoff = min(backoff*2, maxAnchorCommitBackoff)
	}
}

// getAnchorCommitOnce is one GET. retry reports a failure worth polling again
// within the window. A document recorded under another completion id is
// refused: signing it into this completion's receipt would fail the audit.
func (s *LocalService) getAnchorCommitOnce(ctx context.Context, path, completionID string) (data []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return nil, false, fmt.Errorf("modelservice local: create request %s: %w", path, err)
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, true, err // the select in the caller reports the window
		}
		return nil, true, fmt.Errorf("modelservice local: request %s: %w", path, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, true, fmt.Errorf("%w (GET %s returned 404: no anchor sidecar, or the completion was not recorded)", ErrAnchorCommitNotFound, path)
	case resp.StatusCode == http.StatusServiceUnavailable:
		return nil, true, fmt.Errorf("modelservice local: %s returned 503: the anchor commitment is still being finalized", path)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		err := fmt.Errorf("modelservice local: %s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(detail)))
		return nil, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, err
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxAnchorCommitBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("modelservice local: read %s: %w", path, err)
	}
	if len(data) > maxAnchorCommitBytes {
		return nil, false, fmt.Errorf("modelservice local: %s exceeds %d bytes", path, maxAnchorCommitBytes)
	}
	var head struct {
		RequestID string `json:"request_id"`
	}
	if !json.Valid(data) || json.Unmarshal(data, &head) != nil || head.RequestID == "" {
		return nil, false, fmt.Errorf("modelservice local: %s is not an AnchorCommitV1 document", path)
	}
	if !anchorCommitNamesCompletion(head.RequestID, completionID) {
		return nil, false, fmt.Errorf("modelservice local: %s serves the anchor commitment of request_id %q, not of completion %q", path, head.RequestID, completionID)
	}
	return data, false, nil
}

// ErrAnchorCommitEmptyGeneration means the completion delivered no generated
// token, so the engine has no anchor commitment for it and the Worker has
// nothing to put into the receipt's WORKER_ANCHOR_OPENING commitment.
var ErrAnchorCommitEmptyGeneration = errors.New("the completion delivered no generated token: there is no anchor commitment to sign")

// anchorEngineKeyTail is what the engine appends to a completion id to form
// its own request key: "-<choice index>-<8 hex>" for a completion
// ("cmpl-822ecaa38c0c278b-0-bd50afd1") and "-<8 hex>", without a choice
// index, for a chat completion ("chatcmpl-9f3a61c2d4e5f607-bd50afd1").
var anchorEngineKeyTail = regexp.MustCompile(`^(?:[0-9]+-)?[0-9a-f]{8}$`)

// anchorCommitNamesCompletion reports whether a commitment's request_id is
// the one of the completion asked for. The Worker asks by the completion id
// of the response ("cmpl-822ecaa38c0c278b"); the engine records the
// commitment under its own key for that completion, which is the completion
// id itself or the completion id followed by "-<choice index>-<8 hex>"
// ("cmpl-822ecaa38c0c278b-0-bd50afd1"), and that key is what request_id
// carries. The sidecar resolves the id it is asked for by the same rule and
// answers 409 when more than one key matches, so a document it serves under
// this rule is the asked completion's. Anything else is another completion's
// commitment.
func anchorCommitNamesCompletion(requestID, completionID string) bool {
	if requestID == completionID {
		return true
	}
	tail, ok := strings.CutPrefix(requestID, completionID+"-")
	return ok && anchorEngineKeyTail.MatchString(tail)
}

// AnchorCommitCapable probes GET /slp/info under the probe timeout. A 2xx
// answer means the engine serves anchor commitments, provided, while the
// seed binding is on, that its JSON lists the configured rule under
// "seed_rules" (an engine that does not is ErrAnchorCommitUnsupported: the
// Profile is not offered rather than served with a seed nobody can check); any other answer,
// including a 404 from an engine without the sidecar, is
// ErrAnchorCommitUnsupported. No answer in time, a refused connection, 429 or
// 5xx is ErrAnchorCommitProbeFailed instead. The verdict is cached
// (anchorInfoOKTTL, anchorInfoFailTTL, anchorInfoProbeFailTTL) so a caller
// may ask on every pass.
func (s *LocalService) AnchorCommitCapable(ctx context.Context) error {
	s.anchorInfo.mu.Lock()
	defer s.anchorInfo.mu.Unlock()
	now := time.Now()
	if !s.anchorInfo.checked.IsZero() {
		ttl := anchorInfoOKTTL
		switch {
		case errors.Is(s.anchorInfo.err, ErrAnchorCommitProbeFailed):
			ttl = anchorInfoProbeFailTTL
		case s.anchorInfo.err != nil:
			ttl = anchorInfoFailTTL
		}
		if now.Sub(s.anchorInfo.checked) < ttl {
			return s.anchorInfo.err
		}
	}
	err := s.probeAnchorInfo(ctx)
	if ctx.Err() != nil && err != nil {
		return err // the caller gave up; do not cache its cancellation
	}
	s.anchorInfo.checked, s.anchorInfo.err = now, err
	return err
}

func (s *LocalService) probeAnchorInfo(ctx context.Context) error {
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	const path = "/slp/info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("%w: create request %s: %v", ErrAnchorCommitUnsupported, path, err)
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: GET %s: %v", ErrAnchorCommitProbeFailed, path, err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAnchorInfoBytes))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return fmt.Errorf("%w: GET %s returned status %d", ErrAnchorCommitProbeFailed, path, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: GET %s returned status %d", ErrAnchorCommitUnsupported, path, resp.StatusCode)
	}
	// The engine answered: what it declares replaces what was known. A body
	// that cannot be read or parsed declares nothing, like an engine that
	// predates the fields. The caller holds anchorInfo.mu.
	var info anchorEngineInfo
	if readErr == nil {
		_ = json.Unmarshal(body, &info)
	}
	s.anchorInfo.info = info
	if s.anchorSeedRule == "" {
		return nil
	}
	// The seed binding is on: the engine must say it implements the rule. An
	// engine that does not know the vllm_xargs ignores them and samples with
	// the order's seed, and nothing in its answers would show it.
	if readErr != nil {
		return fmt.Errorf("%w: read %s: %v", ErrAnchorCommitProbeFailed, path, readErr)
	}
	var declared struct {
		SeedRules []string `json:"seed_rules"`
	}
	if err := json.Unmarshal(body, &declared); err != nil {
		return fmt.Errorf("%w: GET %s is not a JSON object, so it declares no seed rule (%q is required)", ErrAnchorCommitUnsupported, path, s.anchorSeedRule)
	}
	if !slices.Contains(declared.SeedRules, s.anchorSeedRule) {
		return fmt.Errorf("%w: the engine does not declare seed rule %q (GET %s \"seed_rules\" is %q)", ErrAnchorCommitUnsupported, s.anchorSeedRule, path, declared.SeedRules)
	}
	return nil
}
