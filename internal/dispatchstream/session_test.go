package dispatchstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync"
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

// reject is a Cortex business message for the outbound path.
func reject(tag byte) *taskv1.DispatchRejectV1 {
	return &taskv1.DispatchRejectV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: h32(tag), TaskHash: h32(tag + 1),
		DispatchTicketHash: h32(tag + 2), ServiceAuthorizationNonce: 1,
	}
}

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
	fail   func(call int) error
}

func (h *recordingHandler) HandleFrame(_ context.Context, from string, f *nexusv1.DispatchStreamFrameV1) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if from != testOperator {
		panic("handler called for the wrong builder: " + from)
	}
	h.frames = append(h.frames, f)
	if h.fail != nil {
		return h.fail(len(h.frames))
	}
	return nil
}

func (h *recordingHandler) setFail(f func(call int) error) {
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
	session *Session
	handler *recordingHandler
}

func startSession(t *testing.T, tweak func(*Config)) *harness {
	t.Helper()
	fake, srv := startFakeNexus(t)
	h := &recordingHandler{}
	cfg := Config{
		ChainID: testChainID, BuilderOperator: testOperator, CortexOperator: testOperator,
		HTTPClient: srv.Client(), BaseURL: srv.URL,
		Sign:           keySigner(cortexKeyHex),
		AuthNonce:      func(context.Context) (uint64, error) { return 7, nil },
		BuilderKey:     func(context.Context) ([]byte, error) { return pub(t, builderKeyHex), nil },
		Store:          newTestStore(t),
		Handler:        h,
		KeepaliveEvery: time.Hour,
		MaxMissed:      3,
		Backoff:        func(int) time.Duration { return time.Millisecond },
		Now:            func() time.Time { return time.UnixMilli(1_000_000) },
		Height:         func() uint64 { return 100 },
	}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("Run did not return after cancel")
		}
	})
	return &harness{fake: fake, session: s, handler: h}
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
	if err := h.session.Enqueue(context.Background(), Outgoing{Message: m, ExpiryHeight: 1_000}); err != nil {
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
		h := startSession(t, func(c *Config) {
			c.KeepaliveEvery = 2 * time.Millisecond
			c.MaxMissed = 2
		})
		c, _ := h.bind(t)
		go func() {
			for {
				if _, err := c.tryRecv(); err != nil {
					return
				}
			}
		}()
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
		h.handler.setFail(func(call int) error {
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
		h.handler.setFail(func(int) error { return builderclient.Permanent(errors.New("bad offer")) })
		c, nonce := h.bind(t)
		c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
		if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
			t.Fatalf("want ack 1, got %v", f)
		}
	})

	t.Run("expired outbound messages are never sent", func(t *testing.T) {
		h := startSession(t, nil)
		c, _ := h.bind(t)
		if err := h.session.Enqueue(context.Background(), Outgoing{Message: reject(1), ExpiryHeight: 99}); err != nil {
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
	if err := h.session.Enqueue(ctx, Outgoing{Message: revoke(t, 1, builderKeyHex), ExpiryHeight: 5}); err == nil {
		t.Fatal("a Builder variant cannot be sent by Cortex")
	}
	if err := h.session.Enqueue(ctx, Outgoing{Message: reject(1)}); err == nil {
		t.Fatal("an outbound message needs an expiry")
	}
}
