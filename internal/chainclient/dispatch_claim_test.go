package chainclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	tPending = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL
	tPaid    = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID
)

func claimState(ticket byte, status taskv1.DispatchCompensationClaimStatusV1) *taskv1.DispatchCompensationClaimState {
	return &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: bytes.Repeat([]byte{ticket}, 32), TaskId: bytes.Repeat([]byte{0x03}, 32), SessionId: bytes.Repeat([]byte{0x04}, 32),
		OrderSequence: 7, BuilderAddress: "trueopen1builder", BuilderSetId: "7", WorkerOperatorAddress: "trueopen1worker",
		Amount: &sharedv1.Amount{AtomicUnits: "40"}, Status: status, ClaimedHeight: 170, RebuttalDeadlineHeight: 190,
		PaidAmount: &sharedv1.Amount{AtomicUnits: "40"}, UnfilledAmount: &sharedv1.Amount{AtomicUnits: "0"}, ClaimWindowCloseHeight: 179,
	}
}

func TestDispatchCompensationClaimReadsTheClaim(t *testing.T) {
	ctx, ticket := context.Background(), bytes.Repeat([]byte{0x42}, 32)
	serve := func(s *taskv1.DispatchCompensationClaimState) *KeeperABCIClient {
		server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
			if path != taskQuery+"DispatchCompensationClaim" || height != "900" {
				t.Fatalf("ABCI %s at %s", path, height)
			}
			var req taskv1.QueryDispatchCompensationClaimRequest
			if err := unmarshalTestProto(data, &req); err != nil || !bytes.Equal(req.GetDispatchTicketHash(), ticket) {
				t.Fatalf("request: %v", err)
			}
			if s == nil {
				return nil, 5, "rpc error: code = NotFound desc = no claim"
			}
			return &taskv1.QueryDispatchCompensationClaimResponse{Claim: s}, 0, ""
		})
		t.Cleanup(server.Close)
		return NewKeeperABCIClient(server.URL)
	}
	got, err := serve(claimState(0x42, tPaid)).DispatchCompensationClaim(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if got.Height != 900 || got.Status != tPaid || got.Worker != "trueopen1worker" || got.Builder != "trueopen1builder" ||
		got.Amount != "40" || got.PaidAmount != "40" || got.RebuttalDeadlineHeight != 190 || got.OrderSequence != 7 || !bytes.Equal(got.TicketHash, ticket) {
		t.Fatalf("snapshot = %+v", got)
	}
	if _, err := serve(nil).DispatchCompensationClaim(ctx, ticket); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no claim: %v", err)
	}
	if _, err := serve(claimState(0x43, tPending)).DispatchCompensationClaim(ctx, ticket); err == nil {
		t.Fatal("a claim for another ticket is refused")
	}
	if _, err := serve(claimState(0x42, 0)).DispatchCompensationClaim(ctx, ticket); err == nil {
		t.Fatal("a status outside the closed set is refused")
	}
	if _, err := serve(nil).DispatchCompensationClaim(ctx, []byte{1}); err == nil {
		t.Fatal("a ticket hash that is not 32 bytes is refused")
	}
}

func TestDispatchCompensationClaimsByBuilderPagesAtOneHeight(t *testing.T) {
	pages := 0
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != taskQuery+"DispatchCompensationClaimsByBuilder" || height != "900" {
			t.Fatalf("ABCI %s at %s: every page is read at the first page's height", path, height)
		}
		var req taskv1.QueryDispatchCompensationClaimsByBuilderRequest
		if err := unmarshalTestProto(data, &req); err != nil || req.GetBuilderAddress() != "trueopen1builder" {
			t.Fatalf("request: %v", err)
		}
		pages++
		if len(req.GetPage().GetPageToken()) == 0 {
			return &taskv1.QueryDispatchCompensationClaimsByBuilderResponse{Claims: []*taskv1.DispatchCompensationClaimState{claimState(0x41, tPending)},
				Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p2")}}, 0, ""
		}
		return &taskv1.QueryDispatchCompensationClaimsByBuilderResponse{Claims: []*taskv1.DispatchCompensationClaimState{claimState(0x42, tPending)},
			Page: &sharedv1.QueryPageResponseV1{}}, 0, ""
	})
	t.Cleanup(server.Close)
	h, claims, err := NewKeeperABCIClient(server.URL).DispatchCompensationClaimsByBuilder(context.Background(), "trueopen1builder")
	if err != nil || h != 900 || pages != 2 || len(claims) != 2 || claims[1].TicketHash[0] != 0x42 {
		t.Fatalf("height %d, pages %d, claims %d, %v", h, pages, len(claims), err)
	}
	loop := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
		return &taskv1.QueryDispatchCompensationClaimsByBuilderResponse{Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("again")}}, 0, ""
	})
	t.Cleanup(loop.Close)
	if _, _, err := NewKeeperABCIClient(loop.URL).DispatchCompensationClaimsByBuilder(context.Background(), "trueopen1builder"); err == nil {
		t.Fatal("a repeated page token is refused")
	}
}

func TestDispatchWinnerIneligibleReadsTheMarker(t *testing.T) {
	ticket := bytes.Repeat([]byte{0x42}, 32)
	serve := func(found bool) *KeeperABCIClient {
		server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
			if path != taskQuery+"DispatchWinnerIneligible" {
				t.Fatalf("path %s", path)
			}
			if !found {
				return nil, 5, "rpc error: code = NotFound desc = none"
			}
			return &taskv1.QueryDispatchWinnerIneligibleResponse{Row: &taskv1.DispatchWinnerIneligibleState{DispatchTicketHash: ticket,
				TaskId: bytes.Repeat([]byte{3}, 32), WorkerOperatorAddress: "trueopen1worker",
				Reason: taskv1.DispatchWinnerIneligibleReasonV1_DISPATCH_WINNER_INELIGIBLE_REASON_V1_UNBONDING, RejectedHeight: 158}}, 0, ""
		})
		t.Cleanup(server.Close)
		return NewKeeperABCIClient(server.URL)
	}
	row, err := serve(true).DispatchWinnerIneligible(context.Background(), ticket)
	if err != nil || row.RejectedHeight != 158 || row.Worker != "trueopen1worker" {
		t.Fatalf("row = %+v, %v", row, err)
	}
	if _, err := serve(false).DispatchWinnerIneligible(context.Background(), ticket); !errors.Is(err, ErrNotFound) {
		t.Fatalf("none: %v", err)
	}
}
