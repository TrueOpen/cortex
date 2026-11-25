package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// The sidecar's max_rows is a sequence limit without any configuration; with
// both, the smaller one binds. With neither, a node wired as cortexd wires it
// refuses every order of a Profile that requires the anchor commitment (and
// only those) rather than serve it unprotected; a stale signal is no limit.
func TestAnchorSequenceLimitFromTheAdmissionSignalAndRefusalWithoutOne(t *testing.T) {
	const out = 128
	signal := func(rows string) string {
		return fmt.Sprintf(`{"accept":true,"slots":5,"seen":[]%s,"updated":%d}`, rows, admissionAt.Unix())
	}
	for _, c := range []struct {
		name    string
		anchor  bool
		body    func(in uint64) string
		config  func(in uint64) uint64
		require bool
		class   string
	}{
		{"max_rows one below the order", true, func(in uint64) string { return signal(fmt.Sprintf(`,"max_rows":%d`, in+out-1)) }, nil, true, classAnchorSequenceTooLong},
		{"max_rows at the order", true, func(in uint64) string { return signal(fmt.Sprintf(`,"max_rows":%d`, in+out)) }, nil, true, ""},
		{"the smaller of the two binds: configuration", true, func(in uint64) string { return signal(`,"max_rows":1000000`) }, func(in uint64) uint64 { return in + out - 1 }, true, classAnchorSequenceTooLong},
		{"the smaller of the two binds: signal", true, func(in uint64) string { return signal(fmt.Sprintf(`,"max_rows":%d`, in+out-1)) }, func(uint64) uint64 { return 1000000 }, true, classAnchorSequenceTooLong},
		{"neither known", true, func(uint64) string { return signal("") }, nil, true, classAnchorSequenceLimitUnknown},
		{"max_rows zero is not a limit", true, func(uint64) string { return signal(`,"max_rows":0`) }, nil, true, classAnchorSequenceLimitUnknown},
		{"a stale signal is not a limit", true, func(in uint64) string {
			return fmt.Sprintf(`{"accept":true,"max_rows":1000000,"updated":%d}`, admissionAt.Unix()-3600)
		}, nil, true, classAnchorSequenceLimitUnknown},
		{"neither known, not required (a harness without the rule)", true, func(uint64) string { return signal("") }, nil, false, ""},
		{"neither known, a Profile without the anchor commitment", false, func(uint64) string { return signal("") }, nil, true, ""},
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
			a, _, _ := newTestAdmission(t, c.body(in))
			x.reconfigure(func(cfg *DispatcherConfig) {
				cfg.Anchor, cfg.AnchorRequireSequenceLimit = &fakeAnchorProbe{}, c.require
				if c.class != classAnchorSequenceLimitUnknown || !strings.Contains(c.name, "stale") {
					cfg.AnchorAdmission = a
				}
				if strings.Contains(c.name, "stale") {
					// the gate itself would refuse a stale signal first; the
					// limit is asked directly below
					cfg.AnchorAdmission = nil
				}
				if c.config != nil {
					cfg.AnchorMaxSequenceTokens = c.config(in)
				}
			})
			if strings.Contains(c.name, "stale") {
				if rows, ok := a.MaxRows(); ok {
					t.Fatalf("a stale signal gave max_rows %d", rows)
				}
			}
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
		})
	}
}

// The start-up message: a warning when nothing bounds the sequence, none of
// that kind when the sidecar's max_rows or the configuration does, and the
// reject-rate note whenever a local limit is set.
func TestStartUpSaysWhatBoundsAnchorSequences(t *testing.T) {
	run := func(tokens, outTok, inBytes uint64, body string) string {
		var buf bytes.Buffer
		a, _, _ := newTestAdmission(t, body)
		warnAnchorSequenceLimit(slog.New(slog.NewTextHandler(&buf, nil)), tokens, outTok, inBytes, a)
		return buf.String()
	}
	plain := fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix())
	rows := fmt.Sprintf(`{"accept":true,"max_rows":1500,"updated":%d}`, admissionAt.Unix())
	if got := run(0, 0, 0, plain); !strings.Contains(got, "anchor_sequence_limit_unknown") || strings.Contains(got, "reject rate") {
		t.Fatalf("nothing set: %s", got)
	}
	if got := run(0, 0, 0, rows); strings.Contains(got, "anchor_sequence_limit_unknown") || !strings.Contains(got, "max_rows") {
		t.Fatalf("max_rows published: %s", got)
	}
	if got := run(1500, 2048, 0, plain); strings.Contains(got, "anchor_sequence_limit_unknown") || !strings.Contains(got, "reject rate") {
		t.Fatalf("configured: %s", got)
	}
}
