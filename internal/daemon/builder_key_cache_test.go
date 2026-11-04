package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

type countingKeys struct {
	snap  chainclient.ServiceKeySnapshot
	reads int
}

func (k *countingKeys) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	k.reads++
	return k.snap, 100, nil
}

func TestBuilderKeyCacheReadsOncePerHeight(t *testing.T) {
	keys := &countingKeys{snap: chainclient.ServiceKeySnapshot{ParticipantType: chainclient.ParticipantTypeBuilder, OperatorAddress: hrBuilderA,
		ServicePubkey: hex.EncodeToString(hrPub(t, hrBuilderKey)), AuthorizationNonce: 1, Status: "ACTIVE"}}
	height := uint64(100)
	c := &builderKeyCache{builder: hrBuilderA, chain: keys, height: func() uint64 { return height }}
	for i := 0; i < 3; i++ {
		k, err := c.Keys(context.Background())
		if err != nil || !bytes.Equal(k.Current, hrPub(t, hrBuilderKey)) || k.CurrentNonce != 1 || !k.CurrentActive {
			t.Fatalf("keys = %+v, %v", k, err)
		}
	}
	if keys.reads != 1 {
		t.Fatalf("reads = %d, want one per committed height", keys.reads)
	}
	height = 101
	_, _ = c.Keys(context.Background())
	c.Invalidate()
	_, _ = c.Keys(context.Background())
	if keys.reads != 3 {
		t.Fatalf("reads = %d: a new height and a rebind both re-read", keys.reads)
	}
	height = 0
	_, _ = c.Keys(context.Background())
	_, _ = c.Keys(context.Background())
	if keys.reads != 5 {
		t.Fatal("an unknown height never caches")
	}
	// A REVOKED current key is reported as such (the session refuses live
	// messages for it), with its explicit revoke cutoff.
	keys.snap.Status, keys.snap.RevokedHeight = "REVOKED", 90
	c.Invalidate()
	if k, err := c.Keys(context.Background()); err != nil || k.CurrentActive || k.RevokedHeight != 90 {
		t.Fatalf("revoked keys = %+v, %v", k, err)
	}
}

// The previous generation the chain retains is carried along, so a message
// retained across the Builder's cutover still verifies by its own nonce.
func TestBuilderKeysOfCarriesThePreviousGeneration(t *testing.T) {
	snap := chainclient.ServiceKeySnapshot{ParticipantType: chainclient.ParticipantTypeBuilder, OperatorAddress: hrBuilderA,
		ServicePubkey: hex.EncodeToString(hrPub(t, hrBuilderKey)), AuthorizationNonce: 2, Status: "ACTIVE",
		HasPrevious: true, Previous: chainclient.PreviousServiceKeySnapshot{ServicePubkey: hex.EncodeToString(hrPub(t, hrCortexKey)),
			AuthorizationNonce: 1, RetiredHeight: 120}}
	k, err := builderKeysOf(hrBuilderA, snap)
	if err != nil {
		t.Fatal(err)
	}
	if prev, err := k.Key(1); err != nil || !bytes.Equal(prev, hrPub(t, hrCortexKey)) || k.PreviousRetiredHeight != 120 {
		t.Fatalf("previous = %x, %v (%+v)", prev, err, k)
	}
	if cur, err := k.Key(2); err != nil || !bytes.Equal(cur, hrPub(t, hrBuilderKey)) {
		t.Fatalf("current = %x, %v", cur, err)
	}
	if _, err := builderKeysOf(hrBuilderB, snap); err == nil {
		t.Fatal("a binding for another operator was accepted")
	}
}
