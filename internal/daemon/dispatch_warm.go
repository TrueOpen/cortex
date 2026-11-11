package daemon

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// maxWarmLagBlocks is how far the held read-ahead height may trail the newest
// committed height the warm loop saw and still serve an offer. While the
// chain stalls the loop sees no newer height, so the held set keeps serving;
// when the chain moves on but the reads keep failing, offers go back to
// reading at the committed height.
const maxWarmLagBlocks = 2

// recentSessionTTL is how long RunWarm keeps reading ahead the Session of an
// offer; users send a Session's orders one after another, so all but the
// first are answered without a Session read. maxRecentSessions bounds it.
const (
	recentSessionTTL  = 10 * time.Minute
	maxRecentSessions = 256
)

// RunWarm reads, on every new committed height, the chain facts an offer
// evaluation needs that do not depend on the order, and holds the last
// complete set (dispatchFacts.Warm). An offer is then evaluated at that
// height and answered without waiting on the chain for them: the Builder's
// accept window is a few hundred ms, shorter than a chain stall (#107).
func (d *Dispatcher) RunWarm(ctx context.Context) error {
	tick := time.NewTicker(d.cfg.WarmEvery)
	defer tick.Stop()
	for {
		d.warmOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (d *Dispatcher) warmOnce(ctx context.Context) {
	height, err := d.cfg.Chain.CommittedHeight(ctx)
	if err != nil || height <= d.chain.WarmHeight() {
		return
	}
	if height > d.head.Load() {
		d.head.Store(height)
	}
	d.chain.Warm(height, d.warmReads(ctx, height))
}

// warmReads are the order-independent reads of evaluateOffer at height: this
// node's service key, node, bond and the liability params, the BuilderSet,
// every configured Builder's service and VRF keys, the support scope of
// every supported profile, and the epoch beacon of height's own epoch.
func (d *Dispatcher) warmReads(ctx context.Context, height uint64) []func(*dispatchFacts) error {
	op := d.cfg.Operator
	reads := []func(*dispatchFacts) error{
		func(c *dispatchFacts) error {
			_, err := c.CurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, op, height)
			return err
		},
		func(c *dispatchFacts) error { _, err := c.CortexNodeAt(ctx, op, height); return err },
		func(c *dispatchFacts) error { _, err := c.ServiceBondAt(ctx, op, height); return err },
		func(c *dispatchFacts) error { _, err := c.WorkerLiabilityParamsAt(ctx, height); return err },
		func(c *dispatchFacts) error { _, err := c.BuilderSetAt(ctx, height); return err },
		func(c *dispatchFacts) error { _, err := c.DispatchEpochAt(ctx, height, height); return err },
	}
	for b := range d.cfg.Builders {
		reads = append(reads,
			func(c *dispatchFacts) error {
				_, err := c.CurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, b, height)
				return err
			},
			func(c *dispatchFacts) error { _, err := c.BuilderVrfKeyAt(ctx, b, height); return err })
	}
	for _, sid := range d.recentSessions() {
		reads = append(reads, func(c *dispatchFacts) error { c.readSession(ctx, sid, height); return nil })
	}
	for _, p := range d.cfg.Profiles {
		model, version := strings.ToLower(strings.TrimPrefix(p.ModelID, "0x")), strconv.FormatUint(uint64(p.ProfileVersion), 10)
		reads = append(reads, func(c *dispatchFacts) error {
			_, err := c.ModelSupportScopeAt(ctx, op, model, version, height)
			return err
		})
	}
	return reads
}

// warmHeight is the held read-ahead height when it is fresh enough to
// evaluate an offer at, else zero.
func (d *Dispatcher) warmHeight() uint64 {
	h := d.chain.WarmHeight()
	if h == 0 || d.head.Load() > h+maxWarmLagBlocks {
		return 0
	}
	return h
}

// noteSession keeps an offer's Session in the read-ahead set for a while.
func (d *Dispatcher) noteSession(sessionID []byte) {
	if len(sessionID) != 32 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.recent == nil {
		d.recent = map[[32]byte]time.Time{}
	}
	if _, ok := d.recent[[32]byte(sessionID)]; !ok && len(d.recent) >= maxRecentSessions {
		return
	}
	d.recent[[32]byte(sessionID)] = d.cfg.Now()
}

// recentSessions are the Sessions of offers seen within recentSessionTTL.
func (d *Dispatcher) recentSessions() [][32]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := d.cfg.Now().Add(-recentSessionTTL)
	out := make([][32]byte, 0, len(d.recent))
	for sid, at := range d.recent {
		if at.Before(cutoff) {
			delete(d.recent, sid)
			continue
		}
		out = append(out, sid)
	}
	return out
}
