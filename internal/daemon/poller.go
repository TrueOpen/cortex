package daemon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/store"
)

const (
	defaultKeeperPollRetries     = 5
	defaultKeeperRetryBackoff    = time.Second
	defaultKeeperMaxRetryBackoff = 30 * time.Second
)

// maxConsecutiveRepositions bounds how many times in a row the chain may tell
// this node its cursor is ahead. A deep reorg legitimately needs several; a chain
// that never settles must not keep a node polling forever without scanning.
const maxConsecutiveRepositions = 32

type KeeperPollerConfig struct {
	Interval    time.Duration
	MaxChainLag uint64
	EffectSink  func(context.Context, []ReconcilerEffect) error

	MaxRetryAttempts     int
	RetryBackoff         time.Duration
	MaxRetryBackoff      time.Duration
	OnRetryableFailure   func(attempt int, delay time.Duration, err error)
	ObserveChainProgress func(ChainProgress)
}

type ChainProgress struct {
	CursorHeight uint64
	ChainHeight  uint64
	Refusal      error
}

func (p ChainProgress) Lag() uint64 { return lagBehind(p.ChainHeight, p.CursorHeight) }

type KeeperEventClient interface {
	// FinalizedEvents returns one explicitly bounded scan. A caller may advance
	// durable progress only when RangeComplete is true, NextPageToken is empty,
	// and the range reaches FinalizedHeight.
	FinalizedEvents(context.Context, chainclient.EventPosition) (chainclient.KeeperEventsPage, error)
}

type KeeperPoller struct {
	store      *store.Store
	keeper     KeeperEventClient
	reconciler *Reconciler
	cfg        KeeperPollerConfig
	// repositions counts consecutive cursor repositions. A reorg that keeps
	// retreating is real progress on every pass, so it must not spend the shared
	// poll retry budget; but it cannot be unlimited either, or a chain answering
	// with a new height forever would spin without ever scanning anything.
	repositions int
}

func NewKeeperPoller(db *store.Store, keeper KeeperEventClient, reconciler *Reconciler, cfg KeeperPollerConfig) *KeeperPoller {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.MaxRetryAttempts <= 0 {
		cfg.MaxRetryAttempts = defaultKeeperPollRetries
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaultKeeperRetryBackoff
	}
	if cfg.MaxRetryBackoff <= 0 {
		cfg.MaxRetryBackoff = defaultKeeperMaxRetryBackoff
	}
	if cfg.MaxRetryBackoff < cfg.RetryBackoff {
		cfg.MaxRetryBackoff = cfg.RetryBackoff
	}
	return &KeeperPoller{store: db, keeper: keeper, reconciler: reconciler, cfg: cfg}
}

func (p *KeeperPoller) RunOnce(ctx context.Context) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("keeper poller store is required")
	}
	if p.keeper == nil {
		return fmt.Errorf("keeper event client is required")
	}
	if p.reconciler == nil {
		return fmt.Errorf("keeper reconciler is required")
	}
	processedHeight, err := p.store.KeeperLastProcessedHeight(ctx)
	if err != nil {
		return err
	}
	page, err := p.keeper.FinalizedEvents(ctx, keeperPosition(processedHeight))
	if err != nil {
		var ahead *chainclient.CursorAheadOfChainError
		if errors.As(err, &ahead) {
			p.observeProgress(ChainProgress{CursorHeight: ahead.CursorHeight, ChainHeight: ahead.ChainHeight, Refusal: err})
			return p.recoverCursorAhead(ctx, ahead)
		}
		return err
	}
	// The chain answered without refusing the cursor, so any reorg has settled.
	p.repositions = 0
	p.observeProgress(ChainProgress{CursorHeight: processedHeight, ChainHeight: page.ChainHeight})

	if page.RangeStartHeight > processedHeight+1 {
		if err := p.recoverGap(ctx, processedHeight, page.RangeStartHeight-1); err != nil {
			return err
		}
		// Recovery advanced the cursor, so this page was computed against a
		// cursor that no longer exists. Applying it now is not merely redundant:
		// a recovery page overlapping this one leaves the cursor mid-range, and
		// validateKeeperEventsRange rejects a page that does not start at
		// processedHeight+1 with a permanent error - turning a filled gap into a
		// dead poller. Re-query on the next pass instead.
		return nil
	}

	return p.applyPage(ctx, page, processedHeight)
}

// recoverCursorAhead repositions the local cursor to the authoritative chain
// height when the cursor is ahead of the tip, which a chain reset can cause.
//
// The refusal is a claim from the chain about this node's own cursor, so it is
// checked before it is acted on. An unbounded reposition is a rewind by whatever
// number arrived - zero is a uint64 like any other, so "reposition to genesis"
// was an accepted answer, and rescanning from genesis is not a recovery.
func (p *KeeperPoller) recoverCursorAhead(ctx context.Context, ahead *chainclient.CursorAheadOfChainError) error {
	stored, err := p.store.KeeperLastProcessedHeight(ctx)
	if err != nil {
		return err
	}
	if ahead.CursorHeight != stored {
		return fmt.Errorf("refusing cursor reposition: refusal names cursor %d but the stored cursor is %d", ahead.CursorHeight, stored)
	}
	if ahead.ChainHeight == 0 || ahead.ChainHeight >= stored {
		return fmt.Errorf("refusing cursor reposition from %d to %d: not a regression this node can act on", stored, ahead.ChainHeight)
	}
	if err := p.store.SetKeeperLastProcessedHeight(ctx, ahead.ChainHeight); err != nil {
		return fmt.Errorf("reposition cursor to authoritative height %d: %w", ahead.ChainHeight, err)
	}
	p.observeProgress(ChainProgress{CursorHeight: ahead.ChainHeight, ChainHeight: ahead.ChainHeight})
	// A reposition is progress, not a failed poll, so it must not spend the poll
	// retry budget: a reorg whose tip keeps retreating repositions correctly on
	// every pass, and charging each one against MaxRetryAttempts would kill the
	// node for recovering exactly as intended. Count repositions separately and
	// fail only when the chain will not settle.
	p.repositions++
	if p.repositions > maxConsecutiveRepositions {
		return fmt.Errorf("cursor repositioned %d consecutive times, last to %d: the chain is not settling", p.repositions, ahead.ChainHeight)
	}
	return nil
}

// recoverGap asks the authoritative event source for the heights the local cursor
// has not consumed, and applies them.
//
// It never advances the cursor past a range it could not obtain. Reconciliation
// is event-driven - ReconcileFromKeeperQuery reaches Apply, which needs the events
// themselves - so there is no inventory query that can rebuild the affected
// responsibilities without them. That leaves exactly two safe answers, "wait" and
// "stop", and skipping is neither: the cursor would move past history nothing ever
// scanned, and the loss would be silent and permanent.
func (p *KeeperPoller) recoverGap(ctx context.Context, processedHeight, gapEnd uint64) error {
	gapPage, err := p.keeper.FinalizedEvents(ctx, keeperPosition(processedHeight))
	if err != nil {
		return fmt.Errorf("recover Keeper event gap %d-%d: %w", processedHeight+1, gapEnd, err)
	}
	if gapPage.FinalizedHeight <= processedHeight || gapPage.RangeStartHeight > processedHeight+1 {
		// Retryable so Run backs off and retries: an event source that is merely
		// lagging will fill this in. If it never does, MaxRetryAttempts turns the
		// wait into a named, bounded failure instead of a silent skip.
		return chainclient.Retryable(fmt.Errorf("Keeper event gap %d-%d is unfilled: source range starts at %d, finalized %d",
			processedHeight+1, gapEnd, gapPage.RangeStartHeight, gapPage.FinalizedHeight))
	}
	return p.applyPage(ctx, gapPage, processedHeight)
}

func (p *KeeperPoller) applyPage(ctx context.Context, page chainclient.KeeperEventsPage, processedHeight uint64) error {
	if err := validateKeeperEventsRange(page, processedHeight); err != nil {
		return err
	}

	finalizedHeight := page.FinalizedHeight
	if finalizedHeight <= processedHeight {
		return nil
	}

	blocks := make(map[uint64][]chainclient.KeeperEvent)
	heights := make([]uint64, 0)
	for _, event := range page.Events {
		if event.Height <= processedHeight {
			return fmt.Errorf("Keeper page replayed event height %d at or below processed height %d", event.Height, processedHeight)
		}
		if event.Height > finalizedHeight {
			return fmt.Errorf("Keeper event height %d exceeds finalized height %d", event.Height, finalizedHeight)
		}
		if event.Height < page.RangeStartHeight || event.Height > page.RangeEndHeight {
			return fmt.Errorf("Keeper event height %d is outside scanned range %d-%d", event.Height, page.RangeStartHeight, page.RangeEndHeight)
		}
		if _, exists := blocks[event.Height]; !exists {
			heights = append(heights, event.Height)
		}
		blocks[event.Height] = append(blocks[event.Height], event)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })

	// Each block's manager callback must durably finish before its height is
	// committed. If a callback partially applies and returns an error, the height
	// remains unchanged and the complete block is replayed; taskHash-keyed manager
	// operations make that replay safe.
	for _, height := range heights {
		p.reconciler.opts.ChainHeight = page.ChainHeight
		effects, err := p.reconciler.ReconcileFromKeeperQuery(ctx, blocks[height])
		if err != nil {
			return err
		}
		if len(effects) > 0 {
			if p.cfg.EffectSink == nil {
				return fmt.Errorf("Keeper block %d produced %d effects without a manager sink", height, len(effects))
			}
			if err := p.cfg.EffectSink(ctx, effects); err != nil {
				return fmt.Errorf("apply Keeper block %d effects: %w", height, err)
			}
		}
		if _, err := p.store.AdvanceKeeperLastProcessedHeight(ctx, height); err != nil {
			return err
		}
		processedHeight = height
	}

	// Any remaining scanned blocks were empty or projection-only. The event
	// client read through finalizedHeight, so it is safe to commit the range.
	if processedHeight < finalizedHeight {
		if _, err := p.store.AdvanceKeeperLastProcessedHeight(ctx, finalizedHeight); err != nil {
			return err
		}
		processedHeight = finalizedHeight
	}
	p.observeProgress(ChainProgress{CursorHeight: processedHeight, ChainHeight: page.ChainHeight})
	return nil
}

func (p *KeeperPoller) observeProgress(progress ChainProgress) {
	if p.cfg.ObserveChainProgress != nil {
		p.cfg.ObserveChainProgress(progress)
	}
}

func validateKeeperEventsRange(page chainclient.KeeperEventsPage, processedHeight uint64) error {
	if page.FinalizedHeight <= processedHeight {
		return nil
	}
	if !page.RangeComplete || page.NextPageToken != "" {
		return fmt.Errorf("Keeper finalized event range is incomplete (range %d-%d, continuation %q)", page.RangeStartHeight, page.RangeEndHeight, page.NextPageToken)
	}
	if page.RangeStartHeight == 0 || page.RangeEndHeight != page.FinalizedHeight || page.RangeStartHeight > page.RangeEndHeight {
		return fmt.Errorf("Keeper finalized event range %d-%d does not completely cover finalized height %d", page.RangeStartHeight, page.RangeEndHeight, page.FinalizedHeight)
	}
	if page.RangeStartHeight != processedHeight+1 {
		return fmt.Errorf("Keeper finalized event range starts at %d after processed height %d", page.RangeStartHeight, processedHeight)
	}
	if page.LastPosition != chainclient.BlockEndPosition(page.RangeEndHeight) {
		return fmt.Errorf("Keeper finalized event range ends at %d but last position is %v", page.RangeEndHeight, page.LastPosition)
	}
	return nil
}

func keeperPosition(height uint64) chainclient.EventPosition {
	if height == 0 {
		return chainclient.EventPosition{}
	}
	return chainclient.BlockEndPosition(height)
}

func lagBehind(chainHeight, consumedHeight uint64) uint64 {
	if chainHeight == 0 || consumedHeight >= chainHeight {
		return 0
	}
	return chainHeight - consumedHeight
}

func (p *KeeperPoller) Run(ctx context.Context) error {
	consecutiveFailures := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		delay := p.cfg.Interval
		if err := p.RunOnce(ctx); err != nil {
			if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return nil
			}
			if !chainclient.IsRetryable(err) {
				return err
			}
			consecutiveFailures++
			if consecutiveFailures > p.cfg.MaxRetryAttempts {
				return fmt.Errorf("keeper poll failed %d consecutive times: %w", consecutiveFailures, err)
			}
			delay = p.retryDelay(consecutiveFailures)
			if p.cfg.OnRetryableFailure != nil {
				p.cfg.OnRetryableFailure(consecutiveFailures, delay, err)
			}
		} else {
			consecutiveFailures = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func (p *KeeperPoller) retryDelay(consecutiveFailures int) time.Duration {
	delay := p.cfg.RetryBackoff
	for i := 1; i < consecutiveFailures; i++ {
		if delay >= p.cfg.MaxRetryBackoff/2 {
			return p.cfg.MaxRetryBackoff
		}
		delay *= 2
	}
	if delay > p.cfg.MaxRetryBackoff {
		return p.cfg.MaxRetryBackoff
	}
	return delay
}
