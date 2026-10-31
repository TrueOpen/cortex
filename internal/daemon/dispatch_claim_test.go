package daemon

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// dpServiceAddr stands in for the current service key's address (the Tx
// signer); it differs from the operator on purpose.
const dpServiceAddr = hrBuilderB

const (
	claimPending   = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL
	claimPaid      = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID
	claimDismissed = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_DISMISSED
)

// claimTx is a txclient.Client: rejects with reject when set, otherwise runs
// land (the chain gains the effect) and reports the Tx confirmed.
type claimTx struct {
	mu     sync.Mutex
	reqs   []txclient.Request
	reject string
	land   func(txclient.Request)
}

func (f *claimTx) Submit(_ context.Context, r txclient.Request) (txclient.Observation, error) {
	if err := txclient.ValidateRequest(r); err != nil {
		return txclient.Observation{}, err
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	reject, land := f.reject, f.land
	f.mu.Unlock()
	if reject != "" {
		return txclient.Observation{TaskID: r.TaskID, Kind: r.Kind, Rejected: true, RejectReason: reject, Status: txclient.LifecycleRejected}, nil
	}
	if land != nil {
		land(r)
	}
	return txclient.Observation{TaskID: r.TaskID, Kind: r.Kind, Accepted: true, TxHash: "C1A1", Status: txclient.LifecycleKeeperConfirmed}, nil
}

func (f *claimTx) requests() []txclient.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]txclient.Request(nil), f.reqs...)
}

func (f *claimTx) setReject(s string)                { f.mu.Lock(); f.reject = s; f.mu.Unlock() }
func (f *claimTx) setLand(fn func(txclient.Request)) { f.mu.Lock(); f.land = fn; f.mu.Unlock() }

func claimHarness(t *testing.T) (*dispatchHarness, *claimTx) {
	t.Helper()
	tx := &claimTx{}
	x := newDispatchHarness(t, 2, nil)
	x.reconfigure(func(c *DispatcherConfig) {
		c.Tx, c.ServiceAddress, c.ReceiptRescueMarginBlocks = tx, dpServiceAddr, 5
		c.ClaimRetryBlocks, c.ClaimRecheckBlocks, c.GCEveryBlocks, c.Evidence = 2, 3, 1, x.ev
	})
	x.chain.with(func(f *fakeDispatchChain) {
		f.params.CompensationClaimWindowBlocks, f.params.CompensationRebuttalBlocks = 20, 10
		f.params.ChallengeWindowBlocks, f.params.ChallengeResponseBlocks, f.params.EvidenceRetentionBlocks = 30, 5, 40
	})
	return x, tx
}

// atHeight commits height and runs one Run iteration (Sweep then SweepClaims).
func (x *dispatchHarness) atHeight(t *testing.T, height uint64) {
	t.Helper()
	x.chain.with(func(f *fakeDispatchChain) { f.height = height })
	if err := x.d.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := x.d.SweepClaims(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (x *dispatchHarness) chainClaim(rec layout.DispatchRecord, status taskv1.DispatchCompensationClaimStatusV1, claimed uint64) chainclient.DispatchClaimSnapshot {
	return chainclient.DispatchClaimSnapshot{TicketHash: bytes.Clone(rec.TicketHash[:]), TaskID: bytes.Clone(rec.TaskID[:]), SessionID: bytes.Clone(rec.SessionID[:]),
		OrderSequence: rec.OrderSequence, Builder: rec.Builder, Worker: hrCortex, Status: status, Amount: "40",
		ClaimedHeight: claimed, RebuttalDeadlineHeight: claimed + 10, ClaimWindowCloseHeight: rec.ClaimFromHeight + 20}
}

func (x *dispatchHarness) setClaim(c chainclient.DispatchClaimSnapshot) {
	x.chain.with(func(f *fakeDispatchChain) {
		if f.claims == nil {
			f.claims = map[[32]byte]chainclient.DispatchClaimSnapshot{}
		}
		f.claims[[32]byte(c.TicketHash)] = c
	})
}

// landClaims makes every accepted claim Tx put a PENDING_REBUTTAL claim on
// chain, included at the next block (a Tx broadcast at h lands at h+1).
func (x *dispatchHarness) landClaims(tx *claimTx) {
	tx.setLand(func(txclient.Request) {
		var h uint64
		x.chain.with(func(f *fakeDispatchChain) { h = f.height })
		x.setClaim(x.chainClaim(x.record(x.t), claimPending, h+1))
	})
}

func TestDeadlineWithoutARecordClaimsCompensation(t *testing.T) {
	x, tx := claimHarness(t)
	x.landClaims(tx)
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight-1)
	if got := x.record(t); got.State != layout.DispatchAccepted || len(tx.requests()) != 0 {
		t.Fatalf("state %s: nothing moves before D_ticket", got.State)
	}
	x.atHeight(t, rec.ClaimFromHeight)
	got := x.record(t)
	if !x.infer.stopped(rec.TicketHash) || x.leaseHeld(t) {
		t.Fatal("CLAIMABLE stops inference and releases the lease (CD §8.6)")
	}
	if got.ClaimWindowCloseHeight != rec.ClaimFromHeight+20 || len(got.Receipt) != 0 {
		t.Fatalf("record = %+v", got)
	}
	reqs := tx.requests()
	if len(reqs) != 1 || reqs[0].Kind != txclient.MsgClaimDispatchCompensation || reqs[0].DeadlineHeight != got.ClaimWindowCloseHeight {
		t.Fatalf("requests = %+v", reqs)
	}
	var msg taskv1.MsgClaimDispatchCompensation
	if err := protojson.Unmarshal(reqs[0].Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.GetSubmitterAddress() != dpServiceAddr {
		t.Fatal("the claim goes out under the current service address; rotation activates only after the window (Q10)")
	}
	accept, err := dispatchwire.Raw(msg.GetAccept())
	if err != nil || !bytes.Equal(accept, rec.Accept) || !proto.Equal(msg.GetTicket(), x.fx.ticket) || !proto.Equal(msg.GetOrder(), x.fx.order) {
		t.Fatal("the claim carries the stored ticket, accept and order exactly")
	}
	if got.State != layout.DispatchClaimPending || got.RebuttalDeadlineHeight == 0 || got.ClaimTxHash != "C1A1" {
		t.Fatalf("record = %+v", got)
	}
	x.atHeight(t, rec.ClaimFromHeight+1)
	if len(tx.requests()) != 1 {
		t.Fatal("one claim per ticket")
	}
}

func TestDeadlineWithAnotherWinnerClaims(t *testing.T) {
	x, tx := claimHarness(t)
	rec := x.committed(t)
	x.chainRecords(t, [32]byte{0xee}, hrBuilderB, 120, 150)
	x.atHeight(t, rec.ClaimFromHeight)
	got := x.record(t)
	if got.State != layout.DispatchClaimable || !strings.Contains(got.StateReason, "recorded with ticket") || len(tx.requests()) != 1 {
		t.Fatalf("record = %+v, %d claims", got, len(tx.requests()))
	}
}

func TestDeadlineWithThisTicketAsWinnerResumesAndFlagsTheNotice(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	rec := x.committed(t)
	if err := x.d.HandleRecordResult(ctx, hrBuilderA, dpNotice(t, x, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED)); err != nil {
		t.Fatal(err)
	}
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
	x.atHeight(t, rec.ClaimFromHeight)
	got := x.record(t)
	if got.State != layout.DispatchRecorded || !got.FalseNotice || len(got.RecordNotice) == 0 {
		t.Fatalf("record = %+v: winner, delivery resumes, the false notice is kept (CD §8.6a)", got)
	}
	if held, _ := hasWorkerTaskLease(ctx, x.st, rec.TaskID); !held || len(tx.requests()) != 0 || x.infer.stopped(rec.TicketHash) {
		t.Fatal("a winner keeps its lease and inference, and never claims")
	}
}

func TestIneligibleWinnerIsNeverClaimed(t *testing.T) {
	x, tx := claimHarness(t)
	rec := x.committed(t)
	x.chain.with(func(f *fakeDispatchChain) {
		f.ineligible = map[[32]byte]chainclient.DispatchWinnerIneligibleSnapshot{x.fx.ticketHash(): {
			Reason: taskv1.DispatchWinnerIneligibleReasonV1_DISPATCH_WINNER_INELIGIBLE_REASON_V1_BOND_INSUFFICIENT, RejectedHeight: 158}}
	})
	x.atHeight(t, rec.ClaimFromHeight)
	if got := x.record(t); got.State != layout.DispatchNotClaimable || !x.infer.stopped(rec.TicketHash) || x.leaseHeld(t) || len(tx.requests()) != 0 {
		t.Fatalf("record = %+v", got)
	}
}

func TestRevokedTicketIsNeverClaimed(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	x.atHeight(t, rec.ClaimFromHeight+1)
	queries := 0
	x.chain.with(func(f *fakeDispatchChain) { queries = f.recordQueries })
	if got := x.record(t); got.State != layout.DispatchRevoked || len(tx.requests()) != 0 || queries != 0 {
		t.Fatal("revoked (like rejected, accept-unsent, superseded) never reaches D_ticket settlement")
	}
}

func TestClaimRefusedByTheChainIsNotRetried(t *testing.T) {
	x, tx := claimHarness(t)
	tx.setReject("failed to execute message; message index: 0: ERR_COMPENSATION_NOT_CLAIMABLE")
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight)
	if got := x.record(t); got.State != layout.DispatchNotClaimable || !strings.Contains(got.StateReason, "ChainObservationConflict") {
		t.Fatalf("record = %+v", got)
	}
	x.atHeight(t, rec.ClaimFromHeight+5)
	if len(tx.requests()) != 1 {
		t.Fatal("a refused claim is not resubmitted")
	}
}

func TestClaimRetriesUntilTheWindowCloses(t *testing.T) {
	x, tx := claimHarness(t)
	tx.setReject("account sequence mismatch")
	rec := x.committed(t)
	d := rec.ClaimFromHeight
	x.atHeight(t, d)
	x.atHeight(t, d+1)
	if n := len(tx.requests()); n != 1 {
		t.Fatalf("%d claims: retries wait ClaimRetryBlocks", n)
	}
	x.atHeight(t, d+2)
	if n := len(tx.requests()); n != 2 {
		t.Fatalf("%d claims", n)
	}
	x.atHeight(t, d+20)
	if got := x.record(t); got.State != layout.DispatchNotClaimable || !strings.Contains(got.StateReason, "window closed") || len(tx.requests()) != 2 {
		t.Fatalf("record = %+v: the claim must land in (D, D+claim_window]", got)
	}
}

func TestPendingClaimSettlesFromTheChain(t *testing.T) {
	for _, status := range []taskv1.DispatchCompensationClaimStatusV1{claimPaid, claimDismissed} {
		x, tx := claimHarness(t)
		x.landClaims(tx)
		rec := x.committed(t)
		x.atHeight(t, rec.ClaimFromHeight)
		pending := x.record(t)
		final := x.chainClaim(pending, status, rec.ClaimFromHeight+1)
		final.PaidAmount, final.UnfilledAmount, final.ResolvedHeight = "30", "10", pending.RebuttalDeadlineHeight
		if status == claimDismissed {
			final.PaidAmount, final.UnfilledAmount, final.RebuttedBy = "0", "0", hrBuilderA
		}
		x.setClaim(final)
		x.atHeight(t, pending.RebuttalDeadlineHeight)
		if got := x.record(t); got.State != layout.DispatchClaimPending {
			t.Fatal("not re-read before the rebuttal deadline passes")
		}
		x.atHeight(t, pending.RebuttalDeadlineHeight+1)
		got := x.record(t)
		switch status {
		case claimPaid:
			if got.State != layout.DispatchClaimPaid || got.PaidAmount != "30" || got.UnfilledAmount != "10" {
				t.Fatalf("record = %+v", got)
			}
		default:
			if got.State != layout.DispatchClaimDismissed || got.RebuttedBy != hrBuilderA {
				t.Fatalf("record = %+v", got)
			}
		}
	}
}

func TestRecordedTicketKeepsRequestingInputPastDTicket(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 300)); err != nil {
		t.Fatal(err)
	}
	requests := func() int {
		n := 0
		for _, m := range x.a.messages() {
			if _, ok := m.(*nexusv1.DispatchInputRequestV1); ok {
				n++
			}
		}
		return n
	}
	before := requests()
	x.chain.with(func(f *fakeDispatchChain) { f.height = x.record(t).ClaimFromHeight + 1 })
	x.now = x.now.Add(10 * time.Second)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if requests() != before+1 {
		t.Fatal("a recorded ticket asks for input until infer_deadline_height, not D_ticket")
	}
}

// A record observation refused as a ChainObservationConflict leaves the
// ticket accepted; the D_ticket scan still settles it from the chain.
func TestDeadlineSettlesATicketLeftAcceptedByAConflict(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
	x.chain.with(func(f *fakeDispatchChain) { f.assignment.DispatchTicketHash = bytes.Repeat([]byte{0xee}, 32) })
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 300)); err == nil || !strings.Contains(err.Error(), "ChainObservationConflict") {
		t.Fatalf("observe: %v", err)
	}
	if got := x.record(t); got.State != layout.DispatchAccepted {
		t.Fatalf("state %s: the conflict changes nothing", got.State)
	}
	x.chainRecords(t, [32]byte{0xee}, hrBuilderB, 120, 300) // the order was re-dispatched and recorded for another ticket
	x.atHeight(t, rec.ClaimFromHeight)
	if got := x.record(t); got.State != layout.DispatchClaimable || x.leaseHeld(t) || len(tx.requests()) != 1 {
		t.Fatalf("record = %+v", got)
	}
}
