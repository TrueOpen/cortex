package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// admissionAt is the instant every admission test reads the signal at.
var admissionAt = time.Unix(1_800_000_000, 0)

// admissionAbsent as a body means the file does not exist.
const admissionAbsent = "\x00absent"

// admissionSignals are the states of the sidecar's file the gate must tell
// apart.
var admissionSignals = []struct {
	name   string
	body   string
	refuse string // "" admits; otherwise a fragment of the refusal
}{
	{"accept", fmt.Sprintf(`{"accept":true,"reason":"","updated":%d}`, admissionAt.Unix()-5), ""},
	{"accept with fields the gate does not know", fmt.Sprintf(`{"accept":true,"updated":%d.25,"backlog":3,"capacity":{"open":2}}`, admissionAt.Unix()-5), ""},
	{"drain", fmt.Sprintf(`{"accept":false,"reason":"7 openings queued, 4 fit before the deadline","updated":%d}`, admissionAt.Unix()-5), "7 openings queued"},
	{"drain without a reason", fmt.Sprintf(`{"accept":false,"updated":%d}`, admissionAt.Unix()-5), "draining"},
	{"missing", admissionAbsent, "unreadable"},
	{"stale", fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()-91), "91s old"},
	{"from the future", fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()+600), "old"},
	{"no timestamp", `{"accept":true}`, "old"},
	{"malformed", `{"accept":tru`, "malformed"},
	{"empty file", ``, "malformed"},
	{"no accept field", fmt.Sprintf(`{"updated":%d}`, admissionAt.Unix()), "malformed"},
	{"accept of the wrong type", fmt.Sprintf(`{"accept":"yes","updated":%d}`, admissionAt.Unix()), "malformed"},
}

// newTestAdmission is a gate over a file holding body (admissionAbsent: none),
// read at admissionAt, logging into the returned buffer.
func newTestAdmission(t *testing.T, body string) (*AnchorAdmission, string, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor_admission.json")
	if body != admissionAbsent {
		writeAdmission(t, path, body)
	}
	logs := &bytes.Buffer{}
	a := NewAnchorAdmission(config.AnchorAdmissionConfig{File: path}, func() time.Time { return admissionAt },
		slog.New(slog.NewTextHandler(logs, nil)))
	if a == nil {
		t.Fatal("a configured file must build a gate")
	}
	return a, path, logs
}

func writeAdmission(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnchorAdmissionReadsTheSignal(t *testing.T) {
	for _, c := range admissionSignals {
		t.Run(c.name, func(t *testing.T) {
			a, _, _ := newTestAdmission(t, c.body)
			err := a.Refusal()
			switch {
			case c.refuse == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.refuse != "" && (err == nil || !strings.Contains(err.Error(), c.refuse)):
				t.Fatalf("err = %v, want a refusal naming %q", err, c.refuse)
			}
			status, ok := a.Status()
			if !ok || status.Accepting != (c.refuse == "") {
				t.Fatalf("status %+v ok=%v", status, ok)
			}
		})
	}
}

func TestAnchorAdmissionMaxAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	writeAdmission(t, path, fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()-40))
	now := func() time.Time { return admissionAt }
	if err := NewAnchorAdmission(config.AnchorAdmissionConfig{File: path}, now, nil).Refusal(); err != nil {
		t.Fatalf("40 s is inside the default 90 s: %v", err)
	}
	if err := NewAnchorAdmission(config.AnchorAdmissionConfig{File: path, MaxAgeS: 30}, now, nil).Refusal(); err == nil {
		t.Fatal("40 s is past max_age_s 30")
	}
}

// Unset, there is no gate: nothing is read, nothing refuses, nothing is
// reported.
func TestAnchorAdmissionUnsetIsNoGate(t *testing.T) {
	a := NewAnchorAdmission(config.AnchorAdmissionConfig{MaxAgeS: 5}, nil, nil)
	if a != nil {
		t.Fatalf("no file must build no gate, got %+v", a)
	}
	if err := a.Refusal(); err != nil {
		t.Fatalf("the nil gate refused: %v", err)
	}
	a.noteRefusedOffer()
	if _, ok := a.Status(); ok {
		t.Fatal("the nil gate reported a status")
	}
	if got := (*Runtime)(nil).AnchorAdmission(); got != nil {
		t.Fatalf("nil runtime gate %+v", got)
	}
	if got := (&Runtime{}).AnchorAdmission(); got != nil {
		t.Fatalf("unconfigured runtime gate %+v", got)
	}
}

// The gate says once that it closed, stays quiet while it keeps refusing,
// repeats itself after anchorAdmissionLogEvery, and says once that it opened.
func TestAnchorAdmissionLogIsRateLimited(t *testing.T) {
	now := admissionAt
	path := filepath.Join(t.TempDir(), "a.json")
	logs := &bytes.Buffer{}
	a := NewAnchorAdmission(config.AnchorAdmissionConfig{File: path}, func() time.Time { return now }, slog.New(slog.NewTextHandler(logs, nil)))
	closed := func() int { return strings.Count(logs.String(), "anchor admission gate closed") }
	for range 50 {
		if a.Refusal() == nil {
			t.Fatal("a missing signal must refuse")
		}
	}
	if closed() != 1 {
		t.Fatalf("%d lines for 50 refusals, want 1:\n%s", closed(), logs)
	}
	now = now.Add(anchorAdmissionLogEvery)
	_ = a.Refusal()
	_ = a.Refusal()
	if closed() != 2 {
		t.Fatalf("%d lines after the log interval, want 2", closed())
	}
	writeAdmission(t, path, fmt.Sprintf(`{"accept":true,"updated":%d}`, now.Unix()))
	for range 3 {
		if err := a.Refusal(); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "anchor admission gate open again"); n != 1 || closed() != 2 {
		t.Fatalf("open lines %d, closed lines %d:\n%s", n, closed(), logs)
	}
	if _, ok := a.Status(); !ok || strings.Count(logs.String(), "\n") != 3 {
		t.Fatalf("Status must not log:\n%s", logs)
	}
}

// The standing handraise leaves a Profile requiring WORKER_ANCHOR_OPENING out
// while the gate is closed and offers it again when it opens; Profiles
// without kind 5 are offered throughout.
func TestHandraiseGatesApplyAnchorAdmission(t *testing.T) {
	ctx := context.Background()
	ab1, ab2, cd1 := hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)
	for _, c := range admissionSignals {
		t.Run(c.name, func(t *testing.T) {
			chain := newFakeHandraiseChain(t)
			key := config.MinPriceBidKey(hrModelCD, 1)
			chain.scopes[key] = requireAnchor(chain.scopes[key])
			g := newTestGates(t, chain, &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
			g.anchor = &fakeAnchorProbe{}
			a, path, _ := newTestAdmission(t, c.body)
			g.admission = a
			want := []HandraiseProfile{ab1, ab2, cd1}
			if c.refuse != "" {
				want = want[:2]
			}
			r := g.evaluate(ctx, 100, true)
			if r.state == nil || !slices.Equal(r.state.Profiles, want) {
				t.Fatalf("offer %+v (%s), want %v", r.state, r.why, want)
			}
			for _, v := range r.profiles {
				if v.HandraiseProfile != cd1 || c.refuse == "" {
					continue
				}
				if v.class != profileExcluded || !strings.HasPrefix(v.why, "anchor admission: ") {
					t.Fatalf("anchor profile verdict %+v, want excluded by the admission gate (a local fact, not a failed read)", v)
				}
			}
			// The chain facts are memoised by height; the signal is not.
			writeAdmission(t, path, fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()))
			if r := g.evaluate(ctx, 100, true); r.state == nil || !slices.Equal(r.state.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
				t.Fatalf("after the gate opened: offer %+v (%s)", r.state, r.why)
			}
			writeAdmission(t, path, fmt.Sprintf(`{"accept":false,"reason":"full","updated":%d}`, admissionAt.Unix()))
			if r := g.evaluate(ctx, 100, true); r.state == nil || !slices.Equal(r.state.Profiles, []HandraiseProfile{ab1, ab2}) {
				t.Fatalf("after the gate closed: offer %+v (%s)", r.state, r.why)
			}
		})
	}
	t.Run("only anchor profiles closes the offer on a fact", func(t *testing.T) {
		chain := newFakeHandraiseChain(t)
		for key, scope := range chain.scopes {
			chain.scopes[key] = requireAnchor(scope)
		}
		g := newTestGates(t, chain, &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
		g.anchor = &fakeAnchorProbe{}
		g.admission, _, _ = newTestAdmission(t, admissionAbsent)
		r := g.evaluate(ctx, 100, true)
		if r.state != nil || !r.factual {
			t.Fatalf("offer %+v factual=%v, want nothing offered and a withdrawal allowed", r.state, r.factual)
		}
	})
	t.Run("no anchor profile never reads the signal", func(t *testing.T) {
		g := newTestGates(t, newFakeHandraiseChain(t), &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
		a, _, logs := newTestAdmission(t, admissionAbsent)
		g.admission = a
		r := g.evaluate(ctx, 100, true)
		if r.state == nil || !slices.Equal(r.state.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
			t.Fatalf("offer %+v (%s)", r.state, r.why)
		}
		if logs.Len() != 0 {
			t.Fatalf("the gate was consulted for Profiles without kind 5:\n%s", logs)
		}
	})
	t.Run("unset changes nothing", func(t *testing.T) {
		chain := newFakeHandraiseChain(t)
		key := config.MinPriceBidKey(hrModelCD, 1)
		chain.scopes[key] = requireAnchor(chain.scopes[key])
		g := newTestGates(t, chain, &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
		g.anchor = &fakeAnchorProbe{}
		if r := g.evaluate(ctx, 100, true); r.state == nil || !slices.Equal(r.state.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
			t.Fatalf("offer %+v (%s)", r.state, r.why)
		}
	})
}

// An offer for a Profile requiring WORKER_ANCHOR_OPENING is refused
// NO_CAPACITY while the gate is closed: the Profile is fine, the node cannot
// take the audit obligation at this moment.
func TestDispatchOfferChecksAnchorAdmission(t *testing.T) {
	anchorOffer := func(t *testing.T, kind5 bool, a *AnchorAdmission) *dispatchHarness {
		x := newDispatchHarness(t, 2, nil)
		if kind5 {
			x.chain.with(func(f *fakeDispatchChain) {
				key := config.MinPriceBidKey(hrModelAB, 1)
				f.scopes[key] = requireAnchor(f.scopes[key])
			})
		}
		x.reconfigure(func(cfg *DispatcherConfig) { cfg.Anchor, cfg.AnchorAdmission = &fakeAnchorProbe{}, a })
		if err := x.handle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(x.a.messages()) == 0 {
			t.Fatal("no answer to the offer")
		}
		return x
	}
	accepted := func(t *testing.T, x *dispatchHarness) {
		t.Helper()
		if _, ok := x.a.messages()[0].(*taskv1.DispatchAcceptV1); !ok {
			t.Fatalf("answered %T, want an accept", x.a.messages()[0])
		}
	}
	for _, c := range admissionSignals {
		t.Run(c.name, func(t *testing.T) {
			a, _, _ := newTestAdmission(t, c.body)
			x := anchorOffer(t, true, a)
			status, _ := a.Status()
			if c.refuse == "" {
				accepted(t, x)
				if status.RefusedOffers != 0 {
					t.Fatalf("refused offers %d after an accept", status.RefusedOffers)
				}
				return
			}
			rj, ok := x.a.messages()[0].(*taskv1.DispatchRejectV1)
			if !ok || rj.GetRejectReason() != taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY {
				t.Fatalf("answered %v, want a NO_CAPACITY reject", x.a.messages()[0])
			}
			rec := x.record(t)
			if rec.RejectClass != classAnchorAdmission || rec.RejectBuilderSide {
				t.Fatalf("reject class %q builder_side=%v", rec.RejectClass, rec.RejectBuilderSide)
			}
			if x.leaseHeld(t) {
				t.Fatal("a refused offer holds a lease")
			}
			if status.RefusedOffers != 1 {
				t.Fatalf("refused offers %d, want 1", status.RefusedOffers)
			}
		})
	}
	t.Run("a Profile without kind 5 is not gated", func(t *testing.T) {
		a, _, logs := newTestAdmission(t, admissionAbsent)
		accepted(t, anchorOffer(t, false, a))
		if logs.Len() != 0 {
			t.Fatalf("the gate was consulted:\n%s", logs)
		}
	})
	t.Run("unset changes nothing", func(t *testing.T) {
		accepted(t, anchorOffer(t, true, nil))
	})
}

// Verifying creates no anchor obligation, so Verifier duty is decided without
// the gate: with a closed gate configured for the process, the Verifier
// eligibility answers exactly as it does without one.
func TestVerifierEligibilityIgnoresAnchorAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	t.Setenv("CORTEX_ANCHOR_ADMISSION_FILE", path)
	rt := &Runtime{cfg: config.Config{Dispatch: config.DispatchConfig{AnchorAdmission: config.AnchorAdmissionConfig{File: path}}}}
	if rt.AnchorAdmission().Refusal() == nil {
		t.Fatal("the gate under test must be closed")
	}
	want, err := rotationTestResolver(activeHandraiseKeeper()).Verifier(context.Background(), capacityTestVerifierCandidate())
	if err != nil {
		t.Fatalf("Verifier eligibility refused while the anchor admission gate is closed: %v", err)
	}
	if want.AvailableSlots <= 0 || !want.ChainSynced {
		t.Fatalf("Verifier precheck input %+v", want)
	}
}
