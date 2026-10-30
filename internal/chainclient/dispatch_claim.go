package chainclient

import (
	"bytes"
	"context"
	"fmt"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// DispatchClaimSnapshot is task.v1 DispatchCompensationClaimState at one
// committed height: the authority for a claim (KC §10.2, CD §8.6).
type DispatchClaimSnapshot struct {
	Height                                                        uint64
	TicketHash, TaskID, SessionID                                 []byte
	OrderSequence                                                 uint64
	Builder, Worker                                               string
	Status                                                        taskv1.DispatchCompensationClaimStatusV1
	Amount, PaidAmount, UnfilledAmount                            string
	ClaimedHeight, RebuttalDeadlineHeight, ClaimWindowCloseHeight uint64
	RebuttedBy                                                    string
	ResolvedHeight                                                uint64
}

func claimSnapshot(height uint64, s *taskv1.DispatchCompensationClaimState) (DispatchClaimSnapshot, error) {
	for name, v := range map[string][]byte{"dispatch_ticket_hash": s.GetDispatchTicketHash(), "task_id": s.GetTaskId(), "session_id": s.GetSessionId()} {
		if len(v) != 32 {
			return DispatchClaimSnapshot{}, fmt.Errorf("Keeper compensation claim %s is %d bytes, want 32", name, len(v))
		}
	}
	switch s.GetStatus() {
	case taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL,
		taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID,
		taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_DISMISSED:
	default:
		return DispatchClaimSnapshot{}, fmt.Errorf("Keeper compensation claim status %v is outside the closed set", s.GetStatus())
	}
	if s.GetBuilderAddress() == "" || s.GetWorkerOperatorAddress() == "" || s.GetClaimedHeight() == 0 || s.GetClaimedHeight() > height {
		return DispatchClaimSnapshot{}, fmt.Errorf("Keeper compensation claim %x is incomplete", s.GetDispatchTicketHash())
	}
	return DispatchClaimSnapshot{
		Height: height, TicketHash: bytes.Clone(s.GetDispatchTicketHash()), TaskID: bytes.Clone(s.GetTaskId()), SessionID: bytes.Clone(s.GetSessionId()),
		OrderSequence: s.GetOrderSequence(), Builder: s.GetBuilderAddress(), Worker: s.GetWorkerOperatorAddress(), Status: s.GetStatus(),
		Amount: s.GetAmount().GetAtomicUnits(), PaidAmount: s.GetPaidAmount().GetAtomicUnits(), UnfilledAmount: s.GetUnfilledAmount().GetAtomicUnits(),
		ClaimedHeight: s.GetClaimedHeight(), RebuttalDeadlineHeight: s.GetRebuttalDeadlineHeight(), ClaimWindowCloseHeight: s.GetClaimWindowCloseHeight(),
		RebuttedBy: s.GetRebuttedByOrEmpty(), ResolvedHeight: s.GetResolvedHeight(),
	}, nil
}

// DispatchCompensationClaim reads the claim keyed by ticket. ErrNotFound: no
// claim was ever accepted for it (or it was pruned after its windows).
func (c *KeeperABCIClient) DispatchCompensationClaim(ctx context.Context, ticket []byte) (DispatchClaimSnapshot, error) {
	if len(ticket) != 32 {
		return DispatchClaimSnapshot{}, fmt.Errorf("dispatch_ticket_hash is %d bytes, want 32", len(ticket))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchClaimSnapshot{}, err
	}
	var response taskv1.QueryDispatchCompensationClaimResponse
	if err := c.query(ctx, taskQuery+"DispatchCompensationClaim", height, &taskv1.QueryDispatchCompensationClaimRequest{DispatchTicketHash: ticket}, &response); err != nil {
		return DispatchClaimSnapshot{}, err
	}
	snap, err := claimSnapshot(height, response.GetClaim())
	if err != nil {
		return DispatchClaimSnapshot{}, err
	}
	if !bytes.Equal(snap.TicketHash, ticket) {
		return DispatchClaimSnapshot{}, fmt.Errorf("Keeper answered the claim of ticket %x for %x", snap.TicketHash, ticket)
	}
	return snap, nil
}

// DispatchCompensationClaimsByBuilder reads every PENDING_REBUTTAL claim
// against builder, all pages pinned to one committed height
// (PHASE1_CONTRACT "Event routing and gap recovery").
func (c *KeeperABCIClient) DispatchCompensationClaimsByBuilder(ctx context.Context, builder string) (uint64, []DispatchClaimSnapshot, error) {
	if builder == "" {
		return 0, nil, fmt.Errorf("builder address is required")
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return 0, nil, err
	}
	var out []DispatchClaimSnapshot
	var token []byte
	seen := map[string]bool{}
	for {
		var response taskv1.QueryDispatchCompensationClaimsByBuilderResponse
		req := &taskv1.QueryDispatchCompensationClaimsByBuilderRequest{BuilderAddress: builder, Page: &sharedv1.QueryPageRequestV1{PageToken: token}}
		if err := c.query(ctx, taskQuery+"DispatchCompensationClaimsByBuilder", height, req, &response); err != nil {
			return 0, nil, err
		}
		for _, s := range response.GetClaims() {
			snap, err := claimSnapshot(height, s)
			if err != nil {
				return 0, nil, err
			}
			if snap.Builder != builder || snap.Status != taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL {
				return 0, nil, fmt.Errorf("Keeper listed claim %x outside builder %s's pending set", snap.TicketHash, builder)
			}
			out = append(out, snap)
		}
		next := response.GetPage().GetNextPageToken()
		if len(next) == 0 {
			return height, out, nil
		}
		if seen[string(next)] {
			return 0, nil, fmt.Errorf("Keeper repeated a claim page token")
		}
		seen[string(next)] = true
		token = bytes.Clone(next)
	}
}

// DispatchWinnerIneligibleSnapshot is task.v1 DispatchWinnerIneligibleState.
type DispatchWinnerIneligibleSnapshot struct {
	Height                                 uint64
	TicketHash, TaskID                     []byte
	Worker                                 string
	Reason                                 taskv1.DispatchWinnerIneligibleReasonV1
	RejectedHeight, ClaimWindowCloseHeight uint64
}

// DispatchWinnerIneligible reads the marker the Keeper writes when a record
// entry naming ticket as winner failed on the winner's own eligibility (KC
// §10.1.1 step 7). Present: the ticket is not claimable (KC §10.2 2c).
func (c *KeeperABCIClient) DispatchWinnerIneligible(ctx context.Context, ticket []byte) (DispatchWinnerIneligibleSnapshot, error) {
	if len(ticket) != 32 {
		return DispatchWinnerIneligibleSnapshot{}, fmt.Errorf("dispatch_ticket_hash is %d bytes, want 32", len(ticket))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchWinnerIneligibleSnapshot{}, err
	}
	var response taskv1.QueryDispatchWinnerIneligibleResponse
	if err := c.query(ctx, taskQuery+"DispatchWinnerIneligible", height, &taskv1.QueryDispatchWinnerIneligibleRequest{DispatchTicketHash: ticket}, &response); err != nil {
		return DispatchWinnerIneligibleSnapshot{}, err
	}
	r := response.GetRow()
	if !bytes.Equal(r.GetDispatchTicketHash(), ticket) || r.GetWorkerOperatorAddress() == "" {
		return DispatchWinnerIneligibleSnapshot{}, fmt.Errorf("Keeper winner-ineligible row does not match ticket %x", ticket)
	}
	return DispatchWinnerIneligibleSnapshot{Height: height, TicketHash: bytes.Clone(ticket), TaskID: bytes.Clone(r.GetTaskId()),
		Worker: r.GetWorkerOperatorAddress(), Reason: r.GetReason(), RejectedHeight: r.GetRejectedHeight(), ClaimWindowCloseHeight: r.GetClaimWindowCloseHeight()}, nil
}
