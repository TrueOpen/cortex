package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
)

// builderKeyCache is a Session's BuilderKey (S2): the Builder's current
// service key, read once per committed height. A rotation lands at a height,
// so a key is never trusted past the height it was read at (CD §4.2.1: no
// historical key); a new binding drops it too.
type builderKeyCache struct {
	builder string
	chain   builderServiceKeyReader
	height  func() uint64
	mu      sync.Mutex
	key     []byte
	at      uint64
}

// Key is dispatchstream.Config.BuilderKey.
func (c *builderKeyCache) Key(ctx context.Context) ([]byte, error) {
	h := c.height()
	c.mu.Lock()
	if c.key != nil && h != 0 && c.at == h {
		k := c.key
		c.mu.Unlock()
		return k, nil
	}
	c.mu.Unlock()
	snap, _, err := c.chain.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, c.builder)
	if err != nil {
		return nil, builderclient.Retryable(fmt.Errorf("Builder %s current service key: %w", c.builder, err))
	}
	if snap.Status != "ACTIVE" || snap.OperatorAddress != c.builder {
		return nil, fmt.Errorf("Builder %s current service key is %s for %s", c.builder, snap.Status, snap.OperatorAddress)
	}
	key, err := hex.DecodeString(snap.ServicePubkey)
	if err != nil || len(key) != 33 {
		return nil, fmt.Errorf("Builder %s service pubkey is not a compressed secp256k1 key", c.builder)
	}
	c.mu.Lock()
	c.key, c.at = key, h
	c.mu.Unlock()
	return key, nil
}

// Invalidate drops the cached key; the next frame re-reads it.
func (c *builderKeyCache) Invalidate() {
	c.mu.Lock()
	c.key = nil
	c.mu.Unlock()
}
