package dispatchstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Test-only keys; not credentials.
const (
	cortexKeyHex  = "1111111111111111111111111111111111111111111111111111111111111111"
	builderKeyHex = "2222222222222222222222222222222222222222222222222222222222222222"
	testOperator  = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	testChainID   = "trueopen-phase1-test-1"
)

func pub(t *testing.T, keyHex string) []byte {
	t.Helper()
	k, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return secp256k1.PrivKeyFromBytes(k).PubKey().SerializeCompressed()
}

func keySigner(keyHex string) dispatchwire.DigestSigner {
	return func(_ context.Context, d [32]byte) ([]byte, error) {
		return signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d))
	}
}

func h32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// revoke is a Builder-signed business message; tag makes it distinct.
func revoke(t *testing.T, tag byte, keyHex string) *nexusv1.DispatchRevokeV1 {
	t.Helper()
	m := &nexusv1.DispatchRevokeV1{
		TaskId: h32(tag), DispatchTicketHash: h32(tag + 1), RevokedHeight: uint64(tag),
		Reason: nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF,
	}
	d, err := dispatchwire.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d))
	if err != nil {
		t.Fatal(err)
	}
	m.BuilderServiceSignature = sig
	return m
}

// unsignedReject is a Cortex business message for the outbound path.
func unsignedReject(tag byte) *taskv1.DispatchRejectV1 {
	return &taskv1.DispatchRejectV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: h32(tag), TaskHash: h32(tag + 1),
		DispatchTicketHash: h32(tag + 2), ServiceAuthorizationNonce: 1,
		Member: &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: h32(tag + 3), Slot: 1, SlotVersion: 1, OperatorAddress: testOperator},
	}
}

func signReject(m *taskv1.DispatchRejectV1) *taskv1.DispatchRejectV1 {
	if err := dispatchwire.SignReject(context.Background(), m, keySigner(cortexKeyHex)); err != nil {
		panic(err)
	}
	return m
}

func reject(tag byte) *taskv1.DispatchRejectV1 { return signReject(unsignedReject(tag)) }

func revokeFrame(nonce []byte, cursor uint64, m *nexusv1.DispatchRevokeV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{StreamNonce: nonce, Cursor: cursor, Message: &nexusv1.DispatchStreamFrameV1_Revoke{Revoke: m}}
}

func ackFrame(nonce []byte, c uint64) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{StreamNonce: nonce, Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{AckedCursor: c}}}
}

func keepaliveFrame(nonce []byte, v uint64) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{StreamNonce: nonce, Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: v}}}
}

// recordingHandler records every delivered frame; fail, when set, decides
// the error for each call.
type recordingHandler struct {
	mu     sync.Mutex
	frames []*nexusv1.DispatchStreamFrameV1
	fail   func(ctx context.Context, call int) error
}

func (h *recordingHandler) HandleFrame(ctx context.Context, from string, f *nexusv1.DispatchStreamFrameV1) error {
	if from != testOperator {
		panic("handler called for the wrong builder: " + from)
	}
	h.mu.Lock()
	h.frames = append(h.frames, f)
	fail, call := h.fail, len(h.frames)
	h.mu.Unlock()
	if fail != nil {
		return fail(ctx, call)
	}
	return nil
}

func (h *recordingHandler) setFail(f func(ctx context.Context, call int) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fail = f
}

func (h *recordingHandler) calls() []*nexusv1.DispatchStreamFrameV1 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*nexusv1.DispatchStreamFrameV1(nil), h.frames...)
}

type harness struct {
	fake    *fakeNexus
	handler *recordingHandler
	cfg     Config
	prepare func(*Session) // test seams, applied before every Run

	mu      sync.Mutex
	session *Session
	cancel  context.CancelFunc
	done    chan struct{}
}

func startSession(t *testing.T, tweak func(*Config)) *harness {
	t.Helper()
	return startPrepared(t, tweak, nil)
}

func startPrepared(t *testing.T, tweak func(*Config), prepare func(*Session)) *harness {
	t.Helper()
	fake, srv := startFakeNexus(t)
	h := &harness{fake: fake, handler: &recordingHandler{}, prepare: prepare}
	h.cfg = Config{
		ChainID: testChainID, BuilderOperator: testOperator, CortexOperator: testOperator,
		HTTPClient: srv.Client(), BaseURL: srv.URL,
		Sign:           keySigner(cortexKeyHex),
		AuthNonce:      func(context.Context) (uint64, error) { return 7, nil },
		BuilderKey:     func(context.Context) ([]byte, error) { return pub(t, builderKeyHex), nil },
		Store:          newTestStore(t),
		Handler:        h.handler,
		KeepaliveEvery: time.Hour,
		PruneEvery:     time.Hour,
		MaxMissed:      3,
		Backoff:        func(int) time.Duration { return time.Millisecond },
		Now:            func() time.Time { return time.UnixMilli(1_000_000) },
		Height:         func() uint64 { return 100 },
	}
	if tweak != nil {
		tweak(&h.cfg)
	}
	h.run(t)
	return h
}

// run starts a Session over the harness config and store, as a restarted
// process would.
func (h *harness) run(t *testing.T) {
	t.Helper()
	s, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if h.prepare != nil {
		h.prepare(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	h.mu.Lock()
	h.session, h.cancel, h.done = s, cancel, done
	h.mu.Unlock()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("Run did not return after cancel")
		}
	})
}

// crash stops the current Session abruptly; safe to call from the Handler.
func (h *harness) crash() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cancel()
}

func (h *harness) waitStopped(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	done := h.done
	h.mu.Unlock()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("session did not stop")
	}
}

func (h *harness) current() *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.session
}

// bind accepts the next connection and returns it with its stream nonce.
func (h *harness) bind(t *testing.T) (*fakeConn, []byte) {
	t.Helper()
	c := h.fake.next(t)
	f := c.recv()
	if f.GetBinding() == nil {
		t.Fatalf("first frame must be the binding, got %v", f)
	}
	return c, f.GetStreamNonce()
}

func (h *harness) enqueue(t *testing.T, m proto.Message) {
	t.Helper()
	if _, err := h.current().Enqueue(context.Background(), Outgoing{Message: m, ExpiryHeight: 1_000}); err != nil {
		t.Fatal(err)
	}
}

func innerBytes(t *testing.T, f *nexusv1.DispatchStreamFrameV1) []byte {
	t.Helper()
	_, m, ok := inner(f)
	if !ok {
		t.Fatal("frame has no message")
	}
	raw, err := dispatchwire.Raw(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validFrame(t *testing.T, f *nexusv1.DispatchStreamFrameV1) {
	t.Helper()
	raw, err := proto.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.ValidateMessage("nexus.v1.DispatchStreamFrameV1", raw); err != nil {
		t.Fatalf("wire rejects the frame: %v", err)
	}
}

func TestSession(t *testing.T) {
	t.Run("binding is the first frame and is signed", func(t *testing.T) {
		h := startSession(t, nil)
		c := h.fake.next(t)
		f := c.recv()
		validFrame(t, f)
		b := f.GetBinding()
		if b == nil || f.GetCursor() != 0 {
			t.Fatalf("want binding at cursor 0, got %v", f)
		}
		if len(f.GetStreamNonce()) != dispatch.StreamNonceSize || !bytes.Equal(f.GetStreamNonce(), b.GetStreamNonce()) {
			t.Fatal("frame nonce must be the 32-byte binding nonce")
		}
		if b.GetSchemaVersion() != dispatch.StreamSchemaVersion || b.GetChainId() != testChainID ||
			b.GetBuilderOperator() != testOperator || b.GetCortexOperator() != testOperator || b.GetServiceAuthorizationNonce() != 7 {
			t.Fatalf("binding fields: %v", b)
		}
		d, err := dispatchwire.Digest(b)
		if err != nil {
			t.Fatal(err)
		}
		if err := dispatch.VerifyDigestSignature(pub(t, cortexKeyHex), d[:], b.GetServiceSignature()); err != nil {
			t.Fatalf("binding signature: %v", err)
		}
	})

	t.Run("enqueued messages go out on contiguous cursors", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		h.enqueue(t, reject(1))
		h.enqueue(t, reject(2))
		for want := uint64(1); want <= 2; want++ {
			f := c.recvSkippingKeepalive()
			validFrame(t, f)
			if f.GetCursor() != want || f.GetReject() == nil || !bytes.Equal(f.GetStreamNonce(), nonce) {
				t.Fatalf("want reject at cursor %d, got %v", want, f)
			}
			if !bytes.Equal(f.GetReject().GetTaskId(), h32(byte(want))) {
				t.Fatal("messages out of order")
			}
		}
	})

	t.Run("acked messages are not resent after reconnect", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		h.enqueue(t, reject(1))
		h.enqueue(t, reject(2))
		c.recvSkippingKeepalive()
		c.recvSkippingKeepalive()
		c.send(ackFrame(nonce, 2))
		c.disconnect()
		c2, nonce2 := h.bind(t)
		if bytes.Equal(nonce, nonce2) {
			t.Fatal("reconnect must use a fresh nonce")
		}
		h.enqueue(t, reject(3))
		f := c2.recvSkippingKeepalive()
		if f.GetCursor() != 1 || !bytes.Equal(f.GetReject().GetTaskId(), h32(3)) {
			t.Fatalf("first frame after reconnect must be the new message at cursor 1, got %v", f)
		}
	})

	t.Run("unacked message replays on cursor 1 with identical bytes", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		h.enqueue(t, reject(1))
		h.enqueue(t, reject(2))
		c.recvSkippingKeepalive()
		first := innerBytes(t, c.recvSkippingKeepalive())
		c.send(ackFrame(nonce, 1))
		c.disconnect()
		c2, nonce2 := h.bind(t)
		f := c2.recvSkippingKeepalive()
		validFrame(t, f)
		if f.GetCursor() != 1 || !bytes.Equal(f.GetStreamNonce(), nonce2) {
			t.Fatalf("replay must start at cursor 1 under the new nonce, got %v", f)
		}
		if !bytes.Equal(innerBytes(t, f), first) {
			t.Fatal("replayed message bytes differ from the original")
		}
	})

	t.Run("duplicate inbound cursor is delivered once", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		a, b := revoke(t, 1, builderKeyHex), revoke(t, 5, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		c.send(revokeFrame(nonce, 1, a))
		c.send(revokeFrame(nonce, 2, b))
		for {
			f := c.recvSkippingKeepalive()
			if f.GetAck() == nil {
				t.Fatalf("want acks, got %v", f)
			}
			if f.GetAck().GetAckedCursor() == 2 {
				break
			}
		}
		if got := h.handler.calls(); len(got) != 2 || !proto.Equal(got[0].GetRevoke(), a) || !proto.Equal(got[1].GetRevoke(), b) {
			t.Fatalf("handler must see a then b once each, got %d calls", len(got))
		}
	})

	t.Run("nonce mismatch drops the stream before the handler", func(t *testing.T) {
		h := startSession(t, nil)
		c, _ := h.bind(t)
		c.send(revokeFrame(h32(0xEE), 1, revoke(t, 1, builderKeyHex)))
		c.waitGone()
		h.bind(t)
		if n := len(h.handler.calls()); n != 0 {
			t.Fatalf("handler called %d times", n)
		}
	})

	t.Run("peer keepalive is echoed once", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		c.send(keepaliveFrame(nonce, 5))
		f := c.recv()
		if f.GetKeepalive().GetSentAtMs() != 5 || f.GetCursor() != 0 {
			t.Fatalf("want keepalive echo 5, got %v", f)
		}
		c.send(keepaliveFrame(nonce, 5))
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recv(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("a repeated probe must not be echoed; want ack 1 next, got %v", f)
		}
	})

	t.Run("missed keepalives force a reconnect", func(t *testing.T) {
		ticks := make(chan time.Time)
		h := startPrepared(t, func(c *Config) { c.MaxMissed = 2 }, func(s *Session) { s.keepaliveTicks = ticks })
		c, _ := h.bind(t)
		ticks <- time.Time{} // probe goes out
		if f := c.recv(); f.GetKeepalive() == nil {
			t.Fatalf("want a probe, got %v", f)
		}
		ticks <- time.Time{} // miss 1
		ticks <- time.Time{} // miss 2 == MaxMissed: drop
		c.waitGone()
		h.bind(t)
	})

	t.Run("replay across reconnect reaches the handler once", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		// The Builder lost the ack and replays the same signed message.
		c.disconnect()
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("a replayed message is still acked, got %v", f)
		}
		if n := len(h.handler.calls()); n != 1 {
			t.Fatalf("handler called %d times, want 1", n)
		}
	})

	t.Run("non-strict frame bytes drop the stream", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		f := revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex))
		// An unknown field on the frame: proto.Unmarshal would accept it and
		// the inner signature still verifies, so only wire's strict decoder
		// on the received bytes refuses it.
		f.ProtoReflect().SetUnknown([]byte{0xF8, 0x01, 0x01})
		c.send(f)
		c.waitGone()
		h.bind(t)
		if n := len(h.handler.calls()); n != 0 {
			t.Fatalf("handler called %d times", n)
		}
	})

	t.Run("bad builder signature drops the stream", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, cortexKeyHex)))
		c.waitGone()
		h.bind(t)
		if n := len(h.handler.calls()); n != 0 {
			t.Fatalf("handler called %d times", n)
		}
	})

	t.Run("retryable handler error leaves the frame unacked for redelivery", func(t *testing.T) {
		h := startSession(t, nil)
		h.handler.setFail(func(_ context.Context, call int) error {
			if call == 1 {
				return builderclient.Retryable(errors.New("busy"))
			}
			return nil
		})
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		c.waitGone() // dropped, never acked
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1 after the retry, got %v", f)
		}
		if n := len(h.handler.calls()); n != 2 {
			t.Fatalf("a retryable failure must allow exactly one redelivery, got %d calls", n)
		}
	})

	t.Run("permanent handler error is acked", func(t *testing.T) {
		h := startSession(t, nil)
		h.handler.setFail(func(context.Context, int) error { return builderclient.Permanent(errors.New("bad offer")) })
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
	})

	t.Run("expired outbound messages are never sent", func(t *testing.T) {
		h := startSession(t, nil)
		c, _ := h.bind(t)
		if _, err := h.current().Enqueue(context.Background(), Outgoing{Message: reject(1), ExpiryHeight: 99}); err != nil {
			t.Fatal(err)
		}
		h.enqueue(t, reject(2))
		if f := c.recvSkippingKeepalive(); f.GetCursor() != 1 || !bytes.Equal(f.GetReject().GetTaskId(), h32(2)) {
			t.Fatalf("the height-99 message is expired at height 100, got %v", f)
		}
	})
}

func TestEnqueueRefusesBuilderVariantsAndMissingExpiry(t *testing.T) {
	h := startSession(t, nil)
	ctx := context.Background()
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: revoke(t, 1, builderKeyHex), ExpiryHeight: 5}); err == nil {
		t.Fatal("a Builder variant cannot be sent by Cortex")
	}
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: reject(1)}); err == nil {
		t.Fatal("an outbound message needs an expiry")
	}
}

func countPrefix(t *testing.T, st interface {
	ScanPrefix(context.Context, []byte, func(k, v []byte) error) error
}, prefix string) int {
	t.Helper()
	n := 0
	if err := st.ScanPrefix(context.Background(), []byte(prefix), func(_, _ []byte) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

// eventually polls cond with 5ms pauses; used only where the observable is
// store state written by the session's own ticker.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSessionAtLeastOnce(t *testing.T) {
	t.Run("crash between received and done redelivers after restart", func(t *testing.T) {
		// Store writes here ignore cancellation, so only the session's own
		// "stopped during handler" check keeps the record from going done.
		h := startPrepared(t, nil, func(s *Session) { s.dedup = detached{s.dedup} })
		h.handler.setFail(func(_ context.Context, call int) error {
			if call == 1 {
				h.crash() // the process dies before the delivery is marked done
			}
			return nil
		})
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		h.waitStopped(t)
		c.waitGone()
		h.run(t)
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		if n := len(h.handler.calls()); n != 2 {
			t.Fatalf("a delivery never marked done must reach the handler again, got %d calls", n)
		}
	})

	t.Run("replay after done across restart is suppressed", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		h.crash()
		h.waitStopped(t)
		c.waitGone()
		h.run(t)
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		if n := len(h.handler.calls()); n != 1 {
			t.Fatalf("handler called %d times, want 1", n)
		}
	})

	t.Run("same cursor with different content is a protocol violation", func(t *testing.T) {
		h := startSession(t, nil)
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		c.send(revokeFrame(nonce, 1, revoke(t, 9, builderKeyHex)))
		c.waitGone()
		h.bind(t)
		if n := len(h.handler.calls()); n != 1 {
			t.Fatalf("handler called %d times, want 1", n)
		}
	})

	t.Run("oversized inbound frame is refused before the handler", func(t *testing.T) {
		logs := &syncBuffer{}
		h := startSession(t, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(logs, nil)) })
		c, nonce := h.bind(t)
		c.send(&nexusv1.DispatchStreamFrameV1{StreamNonce: nonce, Cursor: 1, Message: &nexusv1.DispatchStreamFrameV1_InputResponse{
			InputResponse: &nexusv1.DispatchInputResponseV1{TaskId: h32(1), Input: make([]byte, dispatch.MaxMessageBytes)},
		}})
		c.waitGone()
		h.bind(t)
		if n := len(h.handler.calls()); n != 0 {
			t.Fatalf("handler called %d times", n)
		}
		// Refused by the transport read bound, before strict decode.
		if !strings.Contains(logs.String(), "is larger than configured max") {
			t.Fatalf("frame was not refused by the read limit; log:\n%s", logs.String())
		}
	})

	t.Run("backoff grows while only retryable failures and control frames arrive", func(t *testing.T) {
		attempts := make(chan int, 16)
		h := startSession(t, func(c *Config) {
			c.Backoff = func(a int) time.Duration { attempts <- a; return time.Millisecond }
		})
		h.handler.setFail(func(context.Context, int) error { return builderclient.Retryable(errors.New("busy")) })
		a := revoke(t, 1, builderKeyHex)
		for want := 0; want < 3; want++ {
			c, nonce := h.bind(t)
			c.send(keepaliveFrame(nonce, uint64(want+1)))
			if f := c.recv(); f.GetKeepalive() == nil {
				t.Fatalf("want keepalive echo, got %v", f)
			}
			c.send(revokeFrame(nonce, 1, a))
			c.waitGone()
			select {
			case got := <-attempts:
				if got != want {
					t.Fatalf("reconnect %d used backoff attempt %d", want, got)
				}
			case <-time.After(waitFor):
				t.Fatal("no backoff")
			}
		}
	})

	t.Run("prune runs on a ticker while bound", func(t *testing.T) {
		var nowMs atomic.Int64
		nowMs.Store(1_000_000)
		h := startSession(t, func(c *Config) {
			c.PruneEvery = 2 * time.Millisecond
			c.DedupRetention = time.Hour
			c.Now = func() time.Time { return time.UnixMilli(nowMs.Load()) }
		})
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		if _, err := h.current().Enqueue(context.Background(), Outgoing{Message: reject(1), ExpiresAtUnixMilli: 1_000_000 + 60_000}); err != nil {
			t.Fatal(err)
		}
		c.recvSkippingKeepalive() // sent, never acked
		if countPrefix(t, h.cfg.Store, dedupPrefix) != 1 || countPrefix(t, h.cfg.Store, outboxPrefix) != 1 {
			t.Fatal("expected one dedup record and one outbox record")
		}
		nowMs.Add(2 * time.Hour.Milliseconds())
		eventually(t, "ticker prune", func() bool {
			return countPrefix(t, h.cfg.Store, dedupPrefix) == 0 && countPrefix(t, h.cfg.Store, outboxPrefix) == 0
		})
	})
}

func TestEnqueueBounds(t *testing.T) {
	h := startSession(t, nil)
	ctx := context.Background()
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: unsignedReject(1), ExpiryHeight: 500}); err == nil {
		t.Fatal("an unsigned Cortex message must be refused")
	}
	// Size the message to 10 bytes under the limit: valid alone, but the
	// worst-case frame around it (nonce, max cursor, tag, length) is not.
	big := unsignedReject(2)
	size := 0
	for n := dispatch.MaxMessageBytes - 1000; size != dispatch.MaxMessageBytes-10; {
		big.ChainId = string(bytes.Repeat([]byte{'x'}, n))
		size = proto.Size(signReject(big))
		n += dispatch.MaxMessageBytes - 10 - size
	}
	if raw, _ := proto.Marshal(big); dispatch.ValidateMessage(dispatchwire.Name(big), raw) != nil {
		t.Fatal("test setup: the message alone must be within the limit")
	}
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: big, ExpiryHeight: 500}); err == nil {
		t.Fatal("a message whose worst-case frame exceeds the limit must be refused")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// failingDone wraps the real dedup and fails the first "done" write.
type failingDone struct {
	deliveries
	failed atomic.Bool
}

func (f *failingDone) mark(ctx context.Context, key []byte, st deliveryState) error {
	if st == stateDone && f.failed.CompareAndSwap(false, true) {
		return errors.New("disk full")
	}
	return f.deliveries.mark(ctx, key, st)
}

func TestNewValidatesConfig(t *testing.T) {
	h := startSession(t, nil)
	cfg := h.cfg
	cfg.Height = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("Height is required")
	}
	cfg = h.cfg
	cfg.KeepaliveEvery, cfg.MaxMissed, cfg.HandlerTimeout = time.Second, 3, 3*time.Second
	if _, err := New(cfg); err == nil {
		t.Fatal("HandlerTimeout must be below the keepalive liveness window")
	}
	cfg.HandlerTimeout = 0
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.HandlerTimeout <= 0 || s.cfg.HandlerTimeout >= 3*time.Second {
		t.Fatalf("default HandlerTimeout %v must be within (0, KeepaliveEvery*MaxMissed)", s.cfg.HandlerTimeout)
	}
}

func TestSessionHandlerOutcomes(t *testing.T) {
	t.Run("handler past its timeout is not acked and is redelivered", func(t *testing.T) {
		h := startSession(t, func(c *Config) { c.HandlerTimeout = 20 * time.Millisecond })
		h.handler.setFail(func(ctx context.Context, call int) error {
			if call == 1 {
				<-ctx.Done() // blocks until the handler deadline
				return ctx.Err()
			}
			return nil
		})
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		c.waitGone()
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		if n := len(h.handler.calls()); n != 2 {
			t.Fatalf("handler called %d times, want 2", n)
		}
	})

	t.Run("handler that overruns its deadline but succeeds is acked once", func(t *testing.T) {
		h := startSession(t, func(c *Config) { c.HandlerTimeout = 20 * time.Millisecond })
		h.handler.setFail(func(ctx context.Context, _ int) error {
			<-ctx.Done() // runs past the deadline, then reports success
			return nil
		})
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1 on the same stream, got %v", f)
		}
		if n := len(h.handler.calls()); n != 1 {
			t.Fatalf("handler called %d times, want 1", n)
		}
	})

	t.Run("failed done write is not acked and is redelivered", func(t *testing.T) {
		h := startPrepared(t, nil, func(s *Session) { s.dedup = &failingDone{deliveries: s.dedup} })
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		c.waitGone()
		c2, nonce2 := h.bind(t)
		c2.send(revokeFrame(nonce2, 1, a))
		if f := c2.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		if n := len(h.handler.calls()); n != 2 {
			t.Fatalf("handler called %d times, want 2", n)
		}
	})

	t.Run("replay after dedup retention reaches the handler again", func(t *testing.T) {
		clk := &testClock{}
		clk.ms.Store(1_000_000)
		h := startSession(t, func(c *Config) { c.Now = clk.now; c.DedupRetention = time.Hour })
		c, nonce := h.bind(t)
		a := revoke(t, 1, builderKeyHex)
		c.send(revokeFrame(nonce, 1, a))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
		clk.advance(2 * time.Hour)
		c.send(revokeFrame(nonce, 2, a))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 2 {
			t.Fatalf("want ack 2, got %v", f)
		}
		if n := len(h.handler.calls()); n != 2 {
			t.Fatalf("handler called %d times, want 2", n)
		}
	})
}

// detached performs dedup writes even after the session context ends.
type detached struct{ deliveries }

func (d detached) mark(_ context.Context, key []byte, st deliveryState) error {
	return d.deliveries.mark(context.Background(), key, st)
}
