package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
)

// builderKeyCache is a Session's BuilderKeys (S2): the Builder's service-key
// binding, read once per committed height. A rotation lands at a height, so
// a binding is never trusted past the height it was read at; a new binding
// drops it too. Since wire b30fba8 the binding carries the one previous
// generation the chain retains, so a retained message signed before the
// Builder's cutover still verifies by its own nonce (no older history).
type builderKeyCache struct {
	builder string
	chain   builderServiceKeyReader
	height  func() uint64
	mu      sync.Mutex
	keys    *dispatchwire.BuilderKeys
	at      uint64
}

// Keys is dispatchstream.Config.BuilderKeys. A REVOKED current key is
// returned as such: the session refuses live messages for it.
func (c *builderKeyCache) Keys(ctx context.Context) (dispatchwire.BuilderKeys, error) {
	h := c.height()
	c.mu.Lock()
	if c.keys != nil && h != 0 && c.at == h {
		k := *c.keys
		c.mu.Unlock()
		return k, nil
	}
	c.mu.Unlock()
	snap, _, err := c.chain.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, c.builder)
	if err != nil {
		return dispatchwire.BuilderKeys{}, builderclient.Retryable(fmt.Errorf("Builder %s current service key: %w", c.builder, err))
	}
	keys, err := builderKeysOf(c.builder, snap)
	if err != nil {
		return dispatchwire.BuilderKeys{}, err
	}
	c.mu.Lock()
	c.keys, c.at = &keys, h
	c.mu.Unlock()
	return keys, nil
}

// Invalidate drops the cached binding; the next frame re-reads it.
func (c *builderKeyCache) Invalidate() {
	c.mu.Lock()
	c.keys = nil
	c.mu.Unlock()
}

// builderKeysOf converts builder's CurrentServiceKey snapshot into the
// generation resolver the dispatch proof checks use.
func builderKeysOf(builder string, snap chainclient.ServiceKeySnapshot) (dispatchwire.BuilderKeys, error) {
	if snap.OperatorAddress != builder {
		return dispatchwire.BuilderKeys{}, fmt.Errorf("Builder %s service key answered for %s", builder, snap.OperatorAddress)
	}
	if snap.Status != "ACTIVE" && snap.Status != "REVOKED" {
		return dispatchwire.BuilderKeys{}, fmt.Errorf("Builder %s service key status %q", builder, snap.Status)
	}
	cur, err := hex.DecodeString(snap.ServicePubkey)
	if err != nil || len(cur) != 33 {
		return dispatchwire.BuilderKeys{}, fmt.Errorf("Builder %s service pubkey is not a compressed secp256k1 key", builder)
	}
	keys := dispatchwire.BuilderKeys{Operator: builder, Current: cur, CurrentNonce: snap.AuthorizationNonce.Uint64(),
		CurrentActive: snap.Status == "ACTIVE", RevokedHeight: snap.RevokedHeight.Uint64()}
	if snap.HasPrevious {
		prev, err := hex.DecodeString(snap.Previous.ServicePubkey)
		if err != nil || len(prev) != 33 {
			return dispatchwire.BuilderKeys{}, fmt.Errorf("Builder %s previous service pubkey is not a compressed secp256k1 key", builder)
		}
		keys.Previous, keys.PreviousNonce, keys.PreviousRetiredHeight = prev, snap.Previous.AuthorizationNonce, snap.Previous.RetiredHeight
	}
	return keys, nil
}
