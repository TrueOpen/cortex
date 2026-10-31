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
		k, err := c.Key(context.Background())
		if err != nil || !bytes.Equal(k, hrPub(t, hrBuilderKey)) {
			t.Fatalf("key = %x, %v", k, err)
		}
	}
	if keys.reads != 1 {
		t.Fatalf("reads = %d, want one per committed height", keys.reads)
	}
	height = 101
	_, _ = c.Key(context.Background())
	c.Invalidate()
	_, _ = c.Key(context.Background())
	if keys.reads != 3 {
		t.Fatalf("reads = %d: a new height and a rebind both re-read", keys.reads)
	}
	height = 0
	_, _ = c.Key(context.Background())
	_, _ = c.Key(context.Background())
	if keys.reads != 5 {
		t.Fatal("an unknown height never caches")
	}
	keys.snap.Status = "REVOKED"
	c.Invalidate()
	if _, err := c.Key(context.Background()); err == nil {
		t.Fatal("a revoked Builder key authorizes nothing")
	}
}
