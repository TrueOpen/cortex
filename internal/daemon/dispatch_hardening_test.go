package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func (x *dispatchHarness) leaseHeld(t *testing.T) bool {
	t.Helper()
	held, err := hasWorkerLease(context.Background(), x.st, layout.StoredHash(x.fx.ticketHash()))
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// I1 / gap: a lease taken before a sign or persist failure is given back when
// the redelivered offer is rejected or dropped instead.
func TestDispatchLeaseIsReleasedWhenARedeliveryRejectsOrDrops(t *testing.T) {
	ctx := context.Background()
	failSign := func(x *dispatchHarness) { x.setSignErr(errors.New("signer down")) }
	failPersist := func(x *dispatchHarness) { x.signDuring = func(cancel context.CancelFunc) { cancel() } }
	for _, c := range []struct {
		name  string
		fail  func(*dispatchHarness)
		then  func(*dispatchHarness)
		wantE error
	}{
		{"sign failure, then a reject", failSign, func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { f.session.BoundChangeHeight = 106 })
		}, nil},
		{"sign failure, then a drop", failSign, func(x *dispatchHarness) { x.hr.forget(hrBuilderA) }, ErrOfferDropped},
		{"persist failure, then a reject", failPersist, func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { f.session.BoundChangeHeight = 106 })
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newDispatchHarness(t, 1, nil)
			c.fail(x)
			hctx, cancel := context.WithCancel(ctx)
			x.signCancel = cancel
			if err := x.d.HandleOffer(hctx, hrBuilderA, x.fx.offer()); err == nil {
				t.Fatal("the accept could not be signed or stored")
			}
			if !x.leaseHeld(t) {
				t.Fatal("the lease is kept for the redelivery")
			}
			x.setSignErr(nil)
			x.signDuring = nil
			c.then(x)
			if err := x.handle(ctx); !errors.Is(err, c.wantE) {
				t.Fatalf("redelivery: err = %v, want %v", err, c.wantE)
			}
			if x.leaseHeld(t) {
				t.Fatal("a ticket that is not accepted gives its lease back")
			}
			if free, _ := x.leases.FreeSlots(); free != 1 {
				t.Fatalf("free = %d, want 1", free)
			}
		})
	}
}

// I1: with no redelivery, the sweep gives back the lease of an offer left
// unanswered once its deadline passed.
func TestDispatchSweepReleasesALeaseLeftByAnInterruptedOffer(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 1, nil)
	x.setSignErr(errors.New("signer down"))
	if err := x.handle(ctx); !builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want retryable", err)
	}
	if err := x.d.Sweep(ctx); err != nil || !x.leaseHeld(t) {
		t.Fatalf("before the deadline the redelivery may still use it: %v", err)
	}
	x.now = x.now.Add(3 * time.Second)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if x.leaseHeld(t) {
		t.Fatal("past the deadline the lease of an unanswered offer goes back")
	}
}

// I2 / gap: release stops and frees before it writes the terminal state, so
// a failure leaves the ticket for the next sweep.
func TestDispatchReleaseFailureIsRetriedBySweep(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.a.markUnsent(1)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.infer.setErrs(nil, errors.New("runner busy"))
	x.now = x.now.Add(3 * time.Second)
	if err := x.d.Sweep(ctx); err == nil {
		t.Fatal("the stop failed")
	}
	if rec := x.record(t); rec.State != layout.DispatchAccepted || !x.leaseHeld(t) {
		t.Fatalf("record = %+v: nothing is written before the stop succeeds", rec)
	}
	x.infer.setErrs(nil, nil)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := x.record(t); rec.State != layout.DispatchAcceptUnsent || x.leaseHeld(t) {
		t.Fatalf("record = %+v: the next sweep completes the release", rec)
	}
}

// I6 / gap: a message the outbox refuses as invalid is a permanent failure.
func TestDispatchEnqueueValidationErrorIsPermanent(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.a.setFail(fmt.Errorf("%w: bad frame", dispatchstream.ErrInvalidOutgoing))
	err := x.handle(context.Background())
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
	if rec := x.record(t); rec.AcceptEnqueuing {
		t.Fatal("a refused enqueue left nothing in the outbox")
	}
}

// I3 / gap: a handler waiting for the work lock gives up with its context,
// as a retryable error, instead of blocking the stream past HandlerTimeout.
func TestDispatchHandlerGivesUpOnABusyLock(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.d.work <- struct{}{} // something else holds the lock
	defer func() { <-x.d.work }()
	for name, call := range map[string]func(context.Context) error{
		"offer":  func(ctx context.Context) error { return x.d.HandleOffer(ctx, hrBuilderA, x.fx.offer()) },
		"revoke": func(ctx context.Context) error { return x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, rbfReason)) },
		"input": func(ctx context.Context) error {
			return x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input))
		},
		"sweep": func(ctx context.Context) error { return x.d.Sweep(ctx) },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		err := call(ctx)
		cancel()
		if !builderclient.IsRetryable(err) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s: err = %v, want retryable DeadlineExceeded", name, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("%s waited %v", name, time.Since(start))
		}
	}
}

const rbfReason = nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF

// I3: facts that do not depend on the order are read once per height.
func TestDispatchFactsAreReadOncePerHeight(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 4, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.fx.ticket.DispatchRound = 7
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	for method, want := range map[string]int{
		"DispatchParamsAt": 1, "WorkerLiabilityParamsAt": 1, "BuilderSetAt": 1, "CortexNodeAt": 1, "ServiceBondAt": 1,
		"BuilderVrfKeyAt": 1, "DispatchEpochAt": 1, "CurrentServiceKey": 2, "ModelSupportScopeAt": 1, "SessionAt": 2,
	} {
		if got := x.chain.callCount(method); got != want {
			t.Errorf("%s read %d times over two offers at one height, want %d", method, got, want)
		}
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = 151 })
	x.fx.ticket.DispatchRound = 8
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := x.chain.callCount("DispatchParamsAt"); got != 2 {
		t.Fatalf("a new height reads again: %d", got)
	}
}

// M2: an older round is superseded only once the new round passed the
// checks; a rejected new round leaves it running.
func TestDispatchRejectedNewRoundSupersedesNothing(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	old := layout.StoredHash(x.fx.ticketHash())
	x.chain.with(func(f *fakeDispatchChain) { f.session.BoundChangeHeight = 106 })
	x.fx.ticket.DispatchRound = 2
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.a.messages()[2].(*taskv1.DispatchRejectV1); !ok {
		t.Fatal("the new round is rejected")
	}
	prev, err := layout.GetDispatchRecord(ctx, x.st, old)
	if err != nil || prev.State != layout.DispatchAccepted || x.infer.stopped(old) {
		t.Fatalf("old round = %+v, %v: a rejected round supersedes nothing", prev, err)
	}
	if held, _ := hasWorkerLease(ctx, x.st, old); !held {
		t.Fatal("the old round keeps its lease")
	}
}

// M1: accept_deadline_ms is the Builder's number; the local window is capped.
func TestDispatchAcceptDeadlineIsClampedLocally(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.fx.ticket.AcceptDeadlineMs = 1 << 40
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := x.record(t).AcceptDeadlineUnixMs, x.now.Add(maxAcceptWindow).UnixMilli(); got != want {
		t.Fatalf("deadline = %d, want %d", got, want)
	}
}

// M-1: no time left to answer is decided before any chain read.
func TestDispatchNoTimeLeftIsDroppedBeforeAnyChainRead(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.fx.ticket.AcceptDeadlineMs = 0
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(context.Background()); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("err = %v, want dropped", err)
	}
	if calls, heights := x.chain.reads(); calls != 0 || len(heights) != 0 {
		t.Fatalf("chain read %d/%v times for an offer with no time left", calls, heights)
	}
}

// C1 / gap: the staged total never passes input_size_bytes, and completeness
// comes from the count of distinct chunks.
func TestDispatchInputIsBoundedAndCounted(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	in := x.fx.input
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 2, in[:40])); err != nil {
		t.Fatal(err)
	}
	err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(1, 2, bytes.Repeat([]byte{'x'}, 10)))
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("40+10 bytes of a %d-byte input: err = %v, want permanent", len(in), err)
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("nothing starts")
	}

	y := newDispatchHarness(t, 2, nil)
	if err := y.handle(ctx); err != nil {
		t.Fatal(err)
	}
	n := uint32(len(in))
	if err := y.d.HandleInputResponse(ctx, hrBuilderA, y.fx.inputResponse(0, n+1, in[:1])); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("more chunks than bytes: err = %v, want permanent", err)
	}
	for i := int(n) - 1; i >= 0; i-- { // one-byte chunks, last first
		if err := y.d.HandleInputResponse(ctx, hrBuilderA, y.fx.inputResponse(uint32(i), n, in[i:i+1])); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if started := len(y.infer.starts()); (i == 0) != (started == 1) {
			t.Fatalf("after chunk %d: %d starts", i, started)
		}
	}
	if got, err := y.ev.ReadTaskKind(ctx, codec.Hash(y.fx.taskHash()), string(layout.ArtifactTaskInput)); err != nil || !bytes.Equal(got, in) {
		t.Fatalf("staged input = %q, %v", got, err)
	}
}

// I7: a revoke and a superseding round drop the ticket's staged input.
func TestDispatchRevokeAndSupersedeDropStagedInput(t *testing.T) {
	ctx := context.Background()
	chunks := func(x *dispatchHarness, ticket layout.StoredHash) int {
		c, err := dispatchInputChunks(ctx, x.st, ticket)
		if err != nil {
			t.Fatal(err)
		}
		return len(c)
	}
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	th := layout.StoredHash(x.fx.ticketHash())
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 2, x.fx.input[:10])); err != nil || chunks(x, th) != 1 {
		t.Fatalf("staged: %v", err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, rbfReason)); err != nil {
		t.Fatal(err)
	}
	if chunks(x, th) != 0 {
		t.Fatal("a revoke drops the staged input")
	}

	y := newDispatchHarness(t, 2, nil)
	if err := y.handle(ctx); err != nil {
		t.Fatal(err)
	}
	old := layout.StoredHash(y.fx.ticketHash())
	if err := y.d.HandleInputResponse(ctx, hrBuilderA, y.fx.inputResponse(0, 2, y.fx.input[:10])); err != nil {
		t.Fatal(err)
	}
	y.fx.ticket.DispatchRound = 2
	y.fx.signTicket(hrBuilderKey)
	if err := y.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if chunks(y, old) != 0 {
		t.Fatal("a superseded round drops its staged input")
	}
}

// I8: at the claim height the ticket is S6's; the sweep stops asking and
// settles it instead.
func TestDispatchSweepStopsAskingForInputAtTheClaimHeight(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	claim := x.record(t).ClaimFromHeight
	x.chain.with(func(f *fakeDispatchChain) { f.height = claim - 1 })
	x.now = x.now.Add(6 * time.Second)
	if err := x.d.Sweep(ctx); err != nil || len(x.a.messages()) != 3 {
		t.Fatalf("one block before the claim height it still asks: %v, %d", err, len(x.a.messages()))
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = claim })
	x.now = x.now.Add(6 * time.Second)
	if err := x.d.Sweep(ctx); err != nil || len(x.a.messages()) != 3 {
		t.Fatalf("no re-request at the claim height: %v, %d", err, len(x.a.messages()))
	}
	if got := x.record(t); got.State.HoldsDuty() {
		t.Fatalf("state %s: the ticket is settled at the claim height", got.State)
	}
}

// I6: a conflicting responsibility can never be started; that is permanent.
func TestDispatchInferConflictIsPermanent(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.infer.setErrs(fmt.Errorf("start: %w", layout.ErrConflict), nil)
	err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input))
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want permanent", err)
	}
}

// stopAfterStart runs the real start, then ends the caller's context: the
// process "stops" between StartDispatchedInfer and recording InputCommitted.
type stopAfterStart struct {
	DispatchInferStarter
	cancel context.CancelFunc
}

func (s *stopAfterStart) StartDispatchedInfer(ctx context.Context, e DispatchInferEntry) error {
	err := s.DispatchInferStarter.StartDispatchedInfer(ctx, e)
	if s.cancel != nil {
		s.cancel()
	}
	return err
}

// Gap: a restart between StartDispatchedInfer and InputCommitted, while the
// runner already moved the stage on, keeps the stage.
func TestDispatchRestartBetweenStartAndCommitKeepsTheStage(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	runner := NewTaskRunner(TaskRunnerConfig{Store: x.st})
	stopper := &stopAfterStart{DispatchInferStarter: runner}
	x.reconfigure(func(c *DispatcherConfig) { c.Infer = stopper })
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	hctx, cancel := context.WithCancel(ctx)
	stopper.cancel = cancel
	last := x.fx.inputResponse(0, 1, x.fx.input)
	if err := x.d.HandleInputResponse(hctx, hrBuilderA, last); err == nil {
		t.Fatal("recording InputCommitted failed")
	}
	if rec := x.record(t); rec.InputCommitted {
		t.Fatal("not committed yet")
	}
	task := layout.StoredHash(x.fx.taskHash())
	if err := layout.MergeInfer(ctx, x.st, task, layout.InferRecord{Stage: layout.StageSucceeded}); err != nil {
		t.Fatal(err)
	}
	x.reconfigure(func(c *DispatcherConfig) { c.Infer = runner }) // restart
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, last); err != nil {
		t.Fatal(err)
	}
	if rec := x.record(t); !rec.InputCommitted {
		t.Fatal("the redelivered chunk completes the commit")
	}
	if rec, err := layout.GetInferRecord(ctx, x.st, task); err != nil || rec.Stage != layout.StageSucceeded {
		t.Fatalf("infer record = %+v, %v: the stage reached is kept", rec, err)
	}
}

// N1: wire fixes no chunking rule, so an uneven split completes.
func TestDispatchInputAcceptsAnUnevenSplit(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	// 100 KiB, so half of it is far above any "even share plus slack" cap.
	in := bytes.Repeat([]byte("ledger line\n"), 100<<10/12)
	sum := sha256.Sum256(in)
	x.fx.input, x.fx.order.Order.InputHash, x.fx.order.Order.InputSizeBytes = in, sum[:], uint64(len(in))
	x.fx.seal()
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	half := len(in) / 2
	parts := [][]byte{in[:half]} // chunk 0 of 10 carries half the input
	rest := in[half:]
	for i := 0; i < 8; i++ {
		parts = append(parts, rest[i:i+1])
	}
	parts = append(parts, rest[8:])
	for i, p := range parts {
		if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(uint32(i), 10, p)); err != nil {
			t.Fatalf("chunk %d (%d bytes): %v", i, len(p), err)
		}
	}
	if len(x.infer.starts()) != 1 || !x.record(t).InputCommitted {
		t.Fatal("the uneven split completes")
	}
}

// N1: a refused chunk resets the staging, so a fresh re-send completes
// instead of the ticket stalling until D_ticket.
func TestDispatchRefusedChunkResetsTheStaging(t *testing.T) {
	ctx := context.Background()
	for name, bad := range map[string]func(x *dispatchHarness) *nexusv1.DispatchInputResponseV1{
		"over the room left": func(x *dispatchHarness) *nexusv1.DispatchInputResponseV1 {
			return x.fx.inputResponse(1, 2, bytes.Repeat([]byte{'x'}, 10))
		},
		"chunk_count changed": func(x *dispatchHarness) *nexusv1.DispatchInputResponseV1 {
			return x.fx.inputResponse(1, 3, []byte{'x'})
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newDispatchHarness(t, 2, nil)
			if err := x.handle(ctx); err != nil {
				t.Fatal(err)
			}
			in := x.fx.input
			if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 2, in[:40])); err != nil {
				t.Fatal(err)
			}
			if err := x.d.HandleInputResponse(ctx, hrBuilderA, bad(x)); err == nil || builderclient.IsRetryable(err) {
				t.Fatalf("err = %v, want permanent", err)
			}
			rec := x.record(t)
			if rec.InputChunkCount != 0 || rec.InputChunksReceived != 0 || rec.InputStagedBytes != 0 || rec.InputRequestedAtUnixMs != 0 {
				t.Fatalf("record = %+v: the staging is reset and input asked for again", rec)
			}
			if chunks, _ := dispatchInputChunks(ctx, x.st, rec.TicketHash); len(chunks) != 0 {
				t.Fatal("staged chunks are dropped")
			}
			for i, p := range [][]byte{in[:40], in[40:]} {
				if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(uint32(i), 2, p)); err != nil {
					t.Fatalf("fresh chunk %d: %v", i, err)
				}
			}
			if len(x.infer.starts()) != 1 {
				t.Fatal("the fresh re-send completes")
			}
		})
	}
}

// M-a: the C4 deadline carries no monotonic reading, so it compares against
// the session's wall clock.
func TestDispatchDeadlineIsWallClock(t *testing.T) {
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) { c.Now = time.Now })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.d.mu.Lock()
	at, ok := x.d.deadline[layout.StoredHash(x.fx.ticketHash())]
	x.d.mu.Unlock()
	if !ok || at != at.Round(0) {
		t.Fatalf("deadline %v carries a monotonic reading", at)
	}
}

// M-b: the session owner is compared as canonical account bytes.
func TestDispatchSessionOwnerIsComparedAsBytes(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	raw, err := nodewire.CanonicalOperatorAddressBytes("user", x.fx.order.Order.UserAddress)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := nodewire.CanonicalOperatorAddressString("other", raw)
	if err != nil {
		t.Fatal(err)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.session.OwnerUserAddress = owner })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.a.messages()[0].(*taskv1.DispatchAcceptV1); !ok {
		t.Fatalf("the same account under another prefix is the owner: %T", x.a.messages()[0])
	}
}

// M-c: local facts read before the lock are checked again under it, before
// the lease is taken.
func TestDispatchLocalFactsAreRecheckedUnderTheLock(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.d.work <- struct{}{} // hold the lock while the offer is evaluated
	done := make(chan error, 1)
	go func() { done <- x.handle(ctx) }()
	hrEventually(t, "the evaluation's last chain read", func() bool { return x.chain.callCount("WorkerLiabilityParamsAt") == 1 })
	x.local.with(func(l *fakeHandraiseLocal) { l.drain = true })
	<-x.d.work
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := x.a.messages()[0].(*taskv1.DispatchRejectV1); !ok {
		t.Fatal("a drain that began while waiting for the lock refuses the ticket")
	}
	if rec := x.record(t); rec.RejectClass != classNodeIneligible || x.leaseHeld(t) {
		t.Fatalf("record = %+v", rec)
	}
}

// M-d: the sweep reads the chain height before it waits for the lock.
func TestDispatchSweepReadsTheHeightBeforeTheLock(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.d.work <- struct{}{}
	defer func() { <-x.d.work }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := x.d.Sweep(ctx); !builderclient.IsRetryable(err) {
		t.Fatalf("err = %v", err)
	}
	if calls, _ := x.chain.reads(); calls != 1 {
		t.Fatalf("CommittedHeight calls = %d, want the read done before waiting", calls)
	}
}
