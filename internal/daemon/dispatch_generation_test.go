package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// rotateBuilderA makes Builder A's current key hrCortexKey at nonce 2 and
// keeps hrBuilderKey as its previous generation 1, retired at retired.
func rotateBuilderA(t *testing.T, x *dispatchHarness, retired uint64) {
	t.Helper()
	x.chain.with(func(f *fakeDispatchChain) {
		k := f.builderKeys[hrBuilderA]
		k.ServicePubkey, k.AuthorizationNonce = hex.EncodeToString(hrPub(t, hrCortexKey)), 2
		k.HasPrevious, k.Previous = true, chainclient.PreviousServiceKeySnapshot{
			ServicePubkey: hex.EncodeToString(hrPub(t, hrBuilderKey)), AuthorizationNonce: 1, RetiredHeight: retired}
		f.builderKeys[hrBuilderA] = k
	})
}

// wire b30fba8: a ticket keeps the bytes its generation signed across the
// Builder's cutover, so a previous-generation ticket for an order before the
// retirement height is accepted, and one at or after it is not.
func TestDispatchOfferVerifiesTheTicketByItsGeneration(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	order := max(x.fx.order.Order.EarliestSubmitHeight, x.fx.ticket.BoundChangeHeight)
	rotateBuilderA(t, x, order+1)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if msgs := x.a.messages(); len(msgs) == 0 {
		t.Fatal("nothing enqueued, want an accept")
	} else if _, ok := msgs[0].(*taskv1.DispatchAcceptV1); !ok {
		t.Fatalf("enqueued %T first, want an accept", msgs[0])
	}

	y := newDispatchHarness(t, 2, nil)
	rotateBuilderA(t, y, order)
	if err := y.handle(ctx); !errors.Is(err, ErrOfferDropped) || !errors.Is(err, dispatchwire.ErrBuilderKeyGeneration) {
		t.Fatalf("a previous-generation ticket at its cutoff: err = %v, want a dropped generation", err)
	}
}

// A retained revoke may not be signed by a generation older than its ticket:
// rotation only advances the nonce, so that can only be a retired key.
func TestDispatchRevokeOlderThanItsTicketIsRefused(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rotateBuilderA(t, x, 10_000)
	x.fx.ticket.ServiceAuthorizationNonce = 2
	x.fx.signTicket(hrCortexKey)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	th := x.fx.ticketHash()
	rv := &nexusv1.DispatchRevokeV1{TaskId: x.fx.ticket.TaskId, DispatchTicketHash: th[:], RevokedHeight: 151,
		Reason: nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF, ServiceAuthorizationNonce: 1}
	d, err := dispatchwire.Digest(rv)
	if err != nil {
		t.Fatal(err)
	}
	if rv.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, rv); !errors.Is(err, dispatchwire.ErrBuilderKeyGeneration) {
		t.Fatalf("err = %v, want ErrBuilderKeyGeneration", err)
	}
	if rec := x.record(t); rec.State != layout.DispatchAccepted || len(rec.Revoke) != 0 {
		t.Fatalf("a refused revoke changed the record: %+v", rec)
	}
	// The same revoke under the ticket's own generation applies.
	rv.ServiceAuthorizationNonce, rv.BuilderServiceSignature = 2, nil
	if d, err = dispatchwire.Digest(rv); err != nil {
		t.Fatal(err)
	}
	if rv.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrCortexKey, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, rv); err != nil {
		t.Fatal(err)
	}
	if rec := x.record(t); rec.State != layout.DispatchRevoked {
		t.Fatalf("record = %+v", rec)
	}
}
