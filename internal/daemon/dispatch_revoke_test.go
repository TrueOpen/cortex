package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

func dpRevoke(t *testing.T, x *dispatchHarness, reason nexusv1.DispatchRevokeReasonV1) *nexusv1.DispatchRevokeV1 {
	t.Helper()
	th := x.fx.ticketHash()
	m := &nexusv1.DispatchRevokeV1{TaskId: bytes.Clone(x.fx.ticket.TaskId), DispatchTicketHash: th[:], RevokedHeight: 151, Reason: reason}
	d, err := dispatchwire.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	if m.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDispatchRevokeStopsReleasesAndKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	rbf := nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	notified := x.hr.notifications()
	rv := dpRevoke(t, x, rbf)
	if err := x.d.HandleRevoke(ctx, hrBuilderA, rv); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	raw, err := dispatchwire.Raw(rv)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != layout.DispatchRevoked || !bytes.Equal(rec.Revoke, raw) || len(rec.Accept) == 0 || len(rec.Ticket) == 0 {
		t.Fatalf("record = %+v: the ticket, the accept and the revoke are all kept", rec)
	}
	if held, _ := hasWorkerLease(ctx, x.st, rec.TicketHash); held {
		t.Fatal("a revoke releases the lease")
	}
	if !x.infer.stopped(rec.TicketHash) {
		t.Fatal("a revoke stops the ticket's inference")
	}
	if x.hr.notifications() <= notified {
		t.Fatal("a released slot re-evaluates the standing handraise")
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, rv); err != nil {
		t.Fatalf("a redelivered revoke is a no-op: %v", err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_UNSPECIFIED)); err == nil {
		t.Fatal("Phase 1 revokes are RBF only")
	}

	y := newDispatchHarness(t, 2, nil)
	if err := y.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, y, rbf)); err != nil {
		t.Fatal(err)
	}
	if err := y.handle(ctx); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("an offer revoked before it arrived: err = %v, want dropped", err)
	}
	if len(y.a.messages()) != 0 {
		t.Fatal("nothing is signed for a revoked ticket")
	}
}
