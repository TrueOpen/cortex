package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// An order of a Profile that requires the anchor commitment is refused at the
// offer when the longest sequence it allows (its prompt, taken as one token
// per anchor_input_bytes_per_token bytes, plus max_output_tokens) is above the
// local limit: an audit opening grows with the sequence, and one above the
// bound of the chain and the validators cannot be opened. An order at the
// limit is taken, the limit does not apply to a Profile without the anchor
// commitment, and without a limit nothing changes.
func TestAnchorOrderAboveTheSequenceLimitIsRefusedAtTheOffer(t *testing.T) {
	const out = 128 // the fixture order's max_output_tokens
	for _, c := range []struct {
		name     string
		anchor   bool
		limit    func(in uint64) uint64
		perToken uint64
		class    string // "" = accepted
	}{
		{"one above the limit", true, func(in uint64) uint64 { return in + out - 1 }, 0, classAnchorSequenceTooLong},
		{"at the limit", true, func(in uint64) uint64 { return in + out }, 0, ""},
		{"four bytes a token brings the same order under a lower limit", true, func(in uint64) uint64 { return (in+3)/4 + out }, 4, ""},
		{"and is still refused one below it", true, func(in uint64) uint64 { return (in+3)/4 + out - 1 }, 4, classAnchorSequenceTooLong},
		{"a Profile without the anchor commitment is not bounded", false, func(uint64) uint64 { return 1 }, 0, ""},
		{"no limit configured", true, func(uint64) uint64 { return 0 }, 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newDispatchHarness(t, 2, nil)
			if c.anchor {
				x.chain.with(func(f *fakeDispatchChain) {
					key := config.MinPriceBidKey(hrModelAB, 1)
					f.scopes[key] = requireAnchor(f.scopes[key])
				})
			}
			in := uint64(len(x.fx.input))
			x.reconfigure(func(cfg *DispatcherConfig) {
				cfg.Anchor = &fakeAnchorProbe{}
				cfg.AnchorMaxSequenceTokens, cfg.AnchorInputBytesPerToken = c.limit(in), c.perToken
			})
			if err := x.handle(context.Background()); err != nil {
				t.Fatal(err)
			}
			rec := x.record(t)
			if c.class == "" {
				if rec.State != layout.DispatchAccepted {
					t.Fatalf("ticket is %s (%s), want accepted", rec.State, rec.RejectClass)
				}
				return
			}
			if rec.State != layout.DispatchRejected || rec.RejectClass != c.class {
				t.Fatalf("ticket is %s, class %q; want rejected as %s", rec.State, rec.RejectClass, c.class)
			}
			if n := x.leaseCount(t); n != 0 {
				t.Fatalf("a refused offer holds %d leases", n)
			}
		})
	}
}
