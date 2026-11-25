package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// WorkerQuotaReader reads the chain's order quota and pause state of a Worker.
type WorkerQuotaReader interface {
	WorkerQuota(ctx context.Context, operatorAddress string) (chainclient.WorkerQuotaSnapshot, error)
}

// ChainPause is the chain's own "no new orders for this Worker" state
// (dispatch_paused: a late submission is pending, the bond is unbonding, or the
// node is jailed). While it is set the standing handraise is withdrawn and
// offers are refused, and both resume when the chain clears it. It also
// reports when the period's order quota is used up, which the Builders
// enforce by not offering.
//
// A nil *ChainPause is the unconfigured gate and never refuses. A chain that
// does not serve the query is treated the same way.
type ChainPause struct {
	reader   WorkerQuotaReader
	operator string
	refresh  time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu          sync.Mutex
	readAt      time.Time
	known       bool
	last        chainclient.WorkerQuotaSnapshot
	unsupported time.Time // retry after
	exhausted   bool      // the last log line said the quota was used up
}

const (
	// DefaultChainPauseRefresh is how old a pause answer may be.
	DefaultChainPauseRefresh = 5 * time.Second
	chainPauseUnsupportedFor = 5 * time.Minute
	chainPauseReadTimeout    = 3 * time.Second
)

// ChainPausedReason is the reason a handraise is withdrawn or an offer refused
// while the chain has paused dispatch to this Worker. It is distinct from
// every local reason so an operator can tell the two apart.
const ChainPausedReason = "dispatch_paused"

// NewChainPause returns the gate, or nil when reader is nil.
func NewChainPause(reader WorkerQuotaReader, operator string, refresh time.Duration, now func() time.Time, logger *slog.Logger) *ChainPause {
	if reader == nil {
		return nil
	}
	if refresh <= 0 {
		refresh = DefaultChainPauseRefresh
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ChainPause{reader: reader, operator: operator, refresh: refresh, now: now, log: logger.With("component", "chain-pause")}
}

// Refusal is nil while the chain lets this Worker take orders, and otherwise
// names the pause and its reasons.
func (p *ChainPause) Refusal(ctx context.Context) error {
	if p == nil {
		return nil
	}
	snap, known := p.Snapshot(ctx)
	if !known || !snap.DispatchPaused {
		return nil
	}
	return fmt.Errorf("%s: the chain has paused dispatch to this Worker (%s)", ChainPausedReason,
		strings.Join(chainclient.PauseReasonNames(snap.PauseReasons), ", "))
}

// Snapshot is the last answer of the chain, read again when it is older than
// the refresh interval. known is false until the chain has answered once, and
// on a chain that does not serve the query. A failed read keeps the previous
// answer: a pause does not end because the node could not be reached.
func (p *ChainPause) Snapshot(ctx context.Context) (snap chainclient.WorkerQuotaSnapshot, known bool) {
	if p == nil {
		return chainclient.WorkerQuotaSnapshot{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if now.Before(p.unsupported) || (!p.readAt.IsZero() && now.Sub(p.readAt) < p.refresh) {
		return p.last, p.known
	}
	p.readAt = now
	rctx, cancel := context.WithTimeout(ctx, chainPauseReadTimeout)
	defer cancel()
	got, err := p.reader.WorkerQuota(rctx, p.operator)
	switch {
	case errors.Is(err, chainclient.ErrQueryUnsupported):
		p.unsupported = now.Add(chainPauseUnsupportedFor)
		p.known, p.last = false, chainclient.WorkerQuotaSnapshot{}
		return p.last, false
	case err != nil:
		p.log.Debug("Worker quota read failed; keeping the previous answer", "error", err)
		return p.last, p.known
	}
	p.note(got)
	p.last, p.known = got, true
	return got, true
}

// note logs the transitions an operator needs to see. Caller holds the lock.
func (p *ChainPause) note(got chainclient.WorkerQuotaSnapshot) {
	wasPaused := p.known && p.last.DispatchPaused
	switch {
	case got.DispatchPaused && (!wasPaused || got.PauseReasons != p.last.PauseReasons):
		p.log.Warn("the chain has paused dispatch to this Worker; the standing handraise is withdrawn until it is cleared",
			"reason", ChainPausedReason, "pause_reasons", chainclient.PauseReasonNames(got.PauseReasons))
	case !got.DispatchPaused && wasPaused:
		p.log.Info("the chain has cleared the dispatch pause; the standing handraise resumes")
	}
	exhausted := got.Enforced && got.Remaining == 0
	if exhausted && !p.exhausted {
		p.log.Warn("this Worker's order quota for the settlement period is used up; Builders offer no orders until the next period or a larger bond",
			"reason", "worker_quota_exhausted", "period", got.Period, "quota", got.Quota,
			"reserved_value", got.ReservedValue, "settled_value", got.SettledValue)
	} else if !exhausted && p.exhausted {
		p.log.Info("this Worker has order quota again", "period", got.Period, "remaining", got.Remaining)
	}
	p.exhausted = exhausted
}
