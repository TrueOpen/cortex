package dispatchstream

import (
	"context"
	"testing"
)

// The Builder measures a Worker's RTT with its keepalive probe and refuses to
// admit a handraise above its threshold (ADMIT_REJECT_REASON_V1_RTT_OVER_THRESHOLD).
// The echo used to wait in the same loop as frame handling, so a probe that
// arrived while a Handler was reading the chain was answered only after it:
// on devnet, with cortex and nexus on one host, the Builder measured 300+ ms
// and dropped every Worker from the roster (TrueOpen/cortex#100). The echo
// must not wait for a Handler.
func TestBuilderProbeIsEchoedWhileAHandlerRuns(t *testing.T) {
	h := startSession(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	h.handler.setFail(func(ctx context.Context, call int) error {
		if call == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return nil
	})
	c, nonce := h.bind(t)
	c.send(revokeFrame(nonce, 1, revoke(t, 1, builderKeyHex)))
	<-entered

	c.send(keepaliveFrame(nonce, 7))
	f := c.recv()
	if f.GetKeepalive().GetSentAtMs() != 7 {
		t.Fatalf("want the probe echoed while the handler runs, got %v", f)
	}

	close(release)
	if f := c.recvSkippingKeepalive(); f.GetAck().GetAckedCursor() != 1 {
		t.Fatalf("want ack 1 after the handler, got %v", f)
	}
}

// A probe on another stream's nonce is not echoed: the fast path keeps the
// binding check the loop applies.
func TestBuilderProbeWithAForeignNonceIsNotEchoed(t *testing.T) {
	h := startSession(t, nil)
	c, nonce := h.bind(t)
	foreign := append([]byte(nil), nonce...)
	foreign[0] ^= 0xff
	c.send(keepaliveFrame(foreign, 9))
	c.waitGone()
}
