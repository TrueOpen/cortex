package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ADR-0040 anchor commitments. An engine with the anchor sidecar serves, for
// every finished completion, an AnchorCommitV1 document under the completion
// id (GET /slp/commit/{id}) and advertises itself on GET /slp/info. Only a
// task whose locked Profile requires WORKER_ANCHOR_OPENING ever asks for it.

const (
	// maxAnchorCommitBytes bounds the AnchorCommitV1 document: it holds token
	// ids, Merkle roots and checkpoint hashes, never anchors themselves.
	maxAnchorCommitBytes = 16 << 20
	// defaultAnchorCommitTimeout is the default commitment window after the
	// generation has ended.
	defaultAnchorCommitTimeout = 120 * time.Second
	// defaultAnchorCommitBackoff is the first wait after a 503; it doubles up
	// to maxAnchorCommitBackoff.
	defaultAnchorCommitBackoff = 250 * time.Millisecond
	maxAnchorCommitBackoff     = 5 * time.Second
	// anchorInfoOKTTL and anchorInfoFailTTL are how long a /slp/info verdict
	// is reused. A failure is retried sooner so an engine that has just come
	// up is picked up quickly.
	anchorInfoOKTTL   = 5 * time.Minute
	anchorInfoFailTTL = time.Minute
)

// ErrAnchorCommitNotFound is a 404 from /slp/commit/{id}: the engine has no
// anchor sidecar, or the sidecar never recorded the completion.
var ErrAnchorCommitNotFound = errors.New("engine has no anchor commitment for the completion")

// ErrAnchorCommitUnsupported means the model service cannot serve ADR-0040
// anchor commitments at all.
var ErrAnchorCommitUnsupported = errors.New("model service does not serve anchor commitments")

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
	data, err := s.fetchAnchorCommit(ctx, resp.EngineRequestID)
	if err != nil {
		if errors.Is(err, ErrAnchorCommitNotFound) {
			return InferResponse{}, fmt.Errorf("modelservice local: the locked Profile requires WORKER_ANCHOR_OPENING: %w", err)
		}
		return InferResponse{}, err
	}
	resp.AnchorCommitRef = s.putArtifact(data)
	return resp, nil
}

// fetchAnchorCommit polls GET /slp/commit/{id} until the engine serves the
// commitment or the anchorCommitWindow ends. 503 means the sidecar is still
// finalizing it and is retried with backoff, as are transport errors and other
// 5xx; 404 ends the poll with ErrAnchorCommitNotFound; any other answer, or a
// body that is not an AnchorCommitV1 document, ends it with an error. None of
// these errors is retryable at the Infer level: generating again would yield
// another completion, not this one's commitment.
func (s *LocalService) fetchAnchorCommit(parent context.Context, completionID string) ([]byte, error) {
	window := s.anchorCommitWindow()
	ctx, cancel := context.WithTimeout(parent, window)
	defer cancel()
	path := "/slp/commit/" + url.PathEscape(completionID)
	backoff := s.anchorCommitBackoff
	if backoff <= 0 {
		backoff = defaultAnchorCommitBackoff
	}
	var last error
	for attempt := 1; ; attempt++ {
		data, retry, err := s.getAnchorCommitOnce(ctx, path)
		if err == nil {
			return data, nil
		}
		if !retry {
			return nil, err
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
// within the window.
func (s *LocalService) getAnchorCommitOnce(ctx context.Context, path string) (data []byte, retry bool, err error) {
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
		return nil, false, fmt.Errorf("%w (GET %s returned 404: no anchor sidecar, or the completion was not recorded)", ErrAnchorCommitNotFound, path)
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
	return data, false, nil
}

// AnchorCommitCapable probes GET /slp/info under the probe timeout. A 2xx
// answer means the engine serves anchor commitments; anything else, including
// a 404 from an engine without the sidecar, is an error. The verdict is cached
// (anchorInfoOKTTL, anchorInfoFailTTL) so a caller may ask on every pass.
func (s *LocalService) AnchorCommitCapable(ctx context.Context) error {
	s.anchorInfo.mu.Lock()
	defer s.anchorInfo.mu.Unlock()
	now := time.Now()
	if !s.anchorInfo.checked.IsZero() {
		ttl := anchorInfoOKTTL
		if s.anchorInfo.err != nil {
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
		return fmt.Errorf("%w: GET %s: %v", ErrAnchorCommitUnsupported, path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: GET %s returned status %d", ErrAnchorCommitUnsupported, path, resp.StatusCode)
	}
	return nil
}
