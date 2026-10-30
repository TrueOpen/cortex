package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/verifier"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

var _ verifier.FrameSender = (*StreamFanout)(nil)

// vsHandraise is a VerifierHandraiseV1 wire's strict decoder accepts: bech32
// operators, Hash32 fields and a raw64 signature.
func vsHandraise(t *testing.T, expiry uint64) *taskv1.VerifierHandraiseV1 {
	t.Helper()
	h := &taskv1.VerifierHandraiseV1{
		SchemaVersion: 1, ChainId: hrChainID, TaskId: bytes.Repeat([]byte{0x11}, 32), VerifyRound: 1,
		InferReceiptHash: bytes.Repeat([]byte{0x22}, 32), OutputHash: bytes.Repeat([]byte{0x33}, 32),
		ModelId: bytes.Repeat([]byte{0xab}, 32), ProfileVersion: 1,
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: bytes.Repeat([]byte{0x5a}, 32), Slot: 4, SlotVersion: 2, OperatorAddress: hrCortex,
		},
		Duty: sharedv1.Duty_DUTY_VERIFIER, ServiceAuthorizationNonce: 7, ExpiryHeight: expiry,
	}
	if err := dispatchwire.SignVerifierHandraise(context.Background(), h, hrSigner(hrCortexKey)); err != nil {
		t.Fatal(err)
	}
	return h
}

func newTestFanout(t *testing.T, a, b *fakeEnqueuer) *StreamFanout {
	t.Helper()
	f, err := NewStreamFanout(map[string]HandraiseEnqueuer{hrBuilderA: a, hrBuilderB: b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStreamFanoutQueuesTheHandraiseOnEveryBuilder(t *testing.T) {
	a, b := &fakeEnqueuer{}, &fakeEnqueuer{}
	h := vsHandraise(t, 140)
	if err := newTestFanout(t, a, b).SendVerifierHandraise(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]*fakeEnqueuer{"A": a, "B": b} {
		if len(e.sent) != 1 {
			t.Fatalf("Builder %s queued %d handraises, want 1", name, len(e.sent))
		}
		out := e.outgoing(0)
		if out.Message != h || out.ExpiryHeight != 140 || out.ExpiresAtUnixMilli != 0 {
			t.Fatalf("Builder %s outgoing = %+v, want the handraise bounded by its own expiry_height", name, out)
		}
	}
}

// CD §6.2 V6: any Task Builder that receives the handraise can put it in a
// proposal, so one durable enqueue is a delivered handraise.
func TestStreamFanoutSucceedsWhenAnyBuilderQueues(t *testing.T) {
	a, b := &fakeEnqueuer{}, &fakeEnqueuer{}
	b.setFail(errors.New("outbox write failed"))
	if err := newTestFanout(t, a, b).SendVerifierHandraise(context.Background(), vsHandraise(t, 140)); err != nil {
		t.Fatalf("one Builder queued it, error = %v", err)
	}
	if len(a.sent) != 1 || b.tries != 1 {
		t.Fatalf("A queued %d, B tried %d", len(a.sent), b.tries)
	}
}

func TestStreamFanoutFailsOnlyWhenNoBuilderQueues(t *testing.T) {
	a, b := &fakeEnqueuer{}, &fakeEnqueuer{}
	a.setFail(errors.New("store closed"))
	b.setFail(errors.New("store closed"))
	err := newTestFanout(t, a, b).SendVerifierHandraise(context.Background(), vsHandraise(t, 140))
	if !errors.Is(err, ErrNoStreamAccepted) || builderclient.IsPermanent(err) {
		t.Fatalf("error = %v, want ErrNoStreamAccepted left retryable", err)
	}
	if !strings.Contains(err.Error(), hrBuilderA) || !strings.Contains(err.Error(), hrBuilderB) {
		t.Fatalf("error = %v, want both Builders named", err)
	}
}

// A message every session refuses as invalid (dispatchstream.ErrInvalidOutgoing)
// can never be queued, so retrying it is pointless.
func TestStreamFanoutMarksAnInvalidMessagePermanent(t *testing.T) {
	a, b := &fakeEnqueuer{}, &fakeEnqueuer{}
	invalid := fmt.Errorf("%w: not strictly decodable", dispatchstream.ErrInvalidOutgoing)
	a.setFail(invalid)
	b.setFail(invalid)
	err := newTestFanout(t, a, b).SendVerifierHandraise(context.Background(), vsHandraise(t, 140))
	if !builderclient.IsPermanent(err) || !errors.Is(err, dispatchstream.ErrInvalidOutgoing) {
		t.Fatalf("error = %v, want a permanent invalid-message refusal", err)
	}
}

func TestStreamFanoutRefusesAMessageWithoutExpiry(t *testing.T) {
	a, b := &fakeEnqueuer{}, &fakeEnqueuer{}
	err := newTestFanout(t, a, b).SendVerifierHandraise(context.Background(), vsHandraise(t, 0))
	if !builderclient.IsPermanent(err) || a.tries != 0 || b.tries != 0 {
		t.Fatalf("error = %v, tries %d/%d: an unbounded message must never reach an outbox", err, a.tries, b.tries)
	}
}

func TestNewStreamFanoutNeedsEverySession(t *testing.T) {
	if _, err := NewStreamFanout(nil, nil); err == nil {
		t.Fatal("a fan-out with no Builder accepted")
	}
	if _, err := NewStreamFanout(map[string]HandraiseEnqueuer{hrBuilderA: nil}, nil); err == nil {
		t.Fatal("a Builder without a session accepted")
	}
}
