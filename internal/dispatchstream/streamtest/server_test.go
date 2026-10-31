package streamtest_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchstream/streamtest"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	cortexKey  = "1111111111111111111111111111111111111111111111111111111111111111"
	builderKey = "2222222222222222222222222222222222222222222222222222222222222222"
	operator   = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	chainID    = "trueopen-phase1-test-1"
)

func h32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func sign(keyHex string) dispatchwire.DigestSigner {
	return func(_ context.Context, d [32]byte) ([]byte, error) {
		return signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d))
	}
}

type frames struct {
	mu  sync.Mutex
	got []*nexusv1.DispatchStreamFrameV1
}

func (f *frames) HandleFrame(_ context.Context, _ string, fr *nexusv1.DispatchStreamFrameV1) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, fr)
	return nil
}

func TestServerCarriesBothDirections(t *testing.T) {
	srv := streamtest.Start(t)
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	raw, _ := hex.DecodeString(builderKey)
	pub := secp256k1.PrivKeyFromBytes(raw).PubKey().SerializeCompressed()
	h := &frames{}
	s, err := dispatchstream.New(dispatchstream.Config{
		ChainID: chainID, BuilderOperator: operator, CortexOperator: operator,
		HTTPClient: builderclient.NewDispatchStreamHTTPClient(), BaseURL: srv.URL(),
		ClientOptions: nil, Sign: sign(cortexKey),
		AuthNonce:  func(context.Context) (uint64, error) { return 7, nil },
		BuilderKey: func(context.Context) ([]byte, error) { return pub, nil },
		Store:      st, Handler: h, KeepaliveEvery: time.Hour, MaxMissed: 3,
		Height: func() uint64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(builderclient.WithTLSPubkeyHash(context.Background(), srv.Pin()))
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	conn := srv.Next(t, operator)
	revoke := &nexusv1.DispatchRevokeV1{TaskId: h32(1), DispatchTicketHash: h32(2), RevokedHeight: 1,
		Reason: nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF}
	d, _ := dispatchwire.Digest(revoke)
	revoke.BuilderServiceSignature, _ = signer.SignDigestWithPrivateKeyHex(builderKey, codec.Hash(d))
	conn.WaitAcked(t, conn.Push(t, revoke))

	reject := &taskv1.DispatchRejectV1{SchemaVersion: 1, ChainId: chainID, TaskId: h32(3), TaskHash: h32(4),
		DispatchTicketHash: h32(5), ServiceAuthorizationNonce: 1,
		Member: &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: h32(6), Slot: 1, SlotVersion: 1, OperatorAddress: operator}}
	if err := dispatchwire.SignReject(context.Background(), reject, sign(cortexKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(context.Background(), dispatchstream.Outgoing{Message: reject, ExpiryHeight: 1_000}); err != nil {
		t.Fatal(err)
	}
	if f := conn.RecvUntil(t, "reject", func(f *nexusv1.DispatchStreamFrameV1) bool { return f.GetReject() != nil }); !bytes.Equal(f.GetReject().GetTaskId(), h32(3)) {
		t.Fatalf("reject = %v", f)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.got) != 1 || h.got[0].GetRevoke() == nil {
		t.Fatalf("handler saw %v", h.got)
	}
}
