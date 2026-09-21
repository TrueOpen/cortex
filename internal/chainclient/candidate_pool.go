package chainclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	hubv1 "github.com/SingaXYZ/cortex/proto/hub/v1"
	sharedv1 "github.com/SingaXYZ/cortex/proto/shared/v1"
	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
)

// verifierCandidateWindowReady is VerifierCandidateWindowState.status = READY.
// The frozen subset carries the field as a bare int32, so the constant is named
// here rather than read from an enum this repository does not mirror.
const verifierCandidateWindowReady = taskv1.VerifierCandidateWindowStatusV1_VERIFIER_CANDIDATE_WINDOW_STATUS_V1_READY

// ErrVerifierWindowNotReady is the verifier candidate window for a task-round
// existing but not yet carrying its members: the chain is between the block
// that froze the source and the Beacon that materializes the draw. The contract
// for a caller that meets it is to wait (interface-and-topic-list.md §5.9), so it is a
// sentinel rather than a message -- a wait a node reports as a failure is a
// wait nobody can tell apart from a broken one.
var ErrVerifierWindowNotReady = errors.New("verifier candidate window is not READY yet")

// ErrVerifierWindowClosed is a READY verifier candidate window whose
// handraise_close_height is already behind the committed height. It is the other
// end of the same clock ErrVerifierWindowNotReady starts: between them a
// candidate has an interval to raise its hand in, and past this one no
// handraise for that round can ever be accepted again.
//
// It is a sentinel because a caller that waits has to be able to stop. A READY
// window keeps answering READY long after its close height passes -- the state
// is not pruned at close -- so without this the answer to "may I still raise a
// hand" was indistinguishable from a malformed window, and a node waiting for
// the draw had nothing to tell it the draw was over.
var ErrVerifierWindowClosed = errors.New("verifier candidate handraise window is closed")

type CandidateMemberRefSnapshot struct {
	CandidatePoolSnapshotID ProtoBytes32
	Slot                    uint32
	SlotVersion             uint64
	OperatorAddress         string
}

type VerifierCandidateMemberSnapshot struct {
	CandidateMemberRefSnapshot
	InferReceiptHash ProtoBytes32
	ExpiryHeight     uint64
}

func (c *KeeperABCIClient) CurrentCandidateMember(ctx context.Context, operatorAddress string) (CandidateMemberRefSnapshot, error) {
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return CandidateMemberRefSnapshot{}, err
	}
	var current hubv1.QueryCurrentCandidatePoolResponse
	if err := c.query(ctx, hubQuery+"CurrentCandidatePool", height, &hubv1.QueryCurrentCandidatePoolRequest{}, &current); err != nil {
		return CandidateMemberRefSnapshot{}, err
	}
	if len(current.Snapshot.SnapshotId) != 32 || current.Snapshot.Status != 2 || current.Snapshot.EffectiveHeight > height || current.Snapshot.ExpiresHeight < height {
		return CandidateMemberRefSnapshot{}, fmt.Errorf("current CandidatePool snapshot is not ACTIVE at committed height")
	}
	var token []byte
	for {
		var response hubv1.QueryCandidatePoolMembersResponse
		request := &hubv1.QueryCandidatePoolMembersRequest{SnapshotId: current.Snapshot.SnapshotId, Page: &sharedv1.QueryPageRequestV1{PageToken: token, Limit: 256}}
		if err := c.query(ctx, hubQuery+"CandidatePoolMembers", height, request, &response); err != nil {
			return CandidateMemberRefSnapshot{}, err
		}
		for _, member := range response.Members {
			if member.OperatorAddress == operatorAddress {
				if member.SlotVersion == 0 {
					return CandidateMemberRefSnapshot{}, fmt.Errorf("CandidatePool member slot_version is required")
				}
				return CandidateMemberRefSnapshot{CandidatePoolSnapshotID: ProtoBytes32(current.Snapshot.SnapshotId), Slot: member.CandidateSlot, SlotVersion: member.SlotVersion, OperatorAddress: member.OperatorAddress}, nil
			}
		}
		if len(response.Page.NextPageToken) == 0 {
			break
		}
		token = append(token[:0], response.Page.NextPageToken...)
	}
	return CandidateMemberRefSnapshot{}, fmt.Errorf("operator %s is not an ACTIVE CandidatePool member", operatorAddress)
}

// VerifierCandidateMember is the handraise-phase read: it answers "may this node
// still raise its hand for this task-round", so a window past its
// handraise_close_height is ErrVerifierWindowClosed.
func (c *KeeperABCIClient) VerifierCandidateMember(ctx context.Context, taskID string, verifyRound uint32, operatorAddress string) (VerifierCandidateMemberSnapshot, error) {
	return c.verifierWindowMember(ctx, taskID, verifyRound, operatorAddress, true)
}

// FrozenVerifierWindowMember is the verify-phase read of the same window: it
// answers "which frozen candidate slot did this node occupy", which stays true
// after the handraise interval ends.
//
// It exists because the two questions have opposite answers at verify time and
// only one query serves both. 06-challenge-and-evidence.md §5.1 orders the round
// handraise_close_height (the legal set frozen) -> Beacon B -> selection_height, so a
// selected Verifier begins work strictly after the close height: asking the
// handraise question there is structurally guaranteed to answer "no", and
// wrapping that as retryable produced a retry that could never succeed while
// re-downloading the output every round.
//
// Reading the window at all past close is sound because the chain keeps it:
// keeper-data-structure-contract.md requires a READY window to carry exactly window_size
// members and deletes only VerifierHandraiseCloseIndex at close, dropping the
// member bodies once the round is final and challenge/evidence are over. Every
// other field this returns is therefore the same value the strict read would
// have returned inside the interval.
//
// Nothing verify signs comes from here: keeper-interface-contract.md §4.1 puts
// CandidateMemberRefV1 in WorkerHandraiseV1/VerifierHandraiseV1 alone, and the
// §5.14 VerifyCommitV1 / ResultReceiptV1 / FullResultRevealV1 bodies carry no
// member. The values serve identity checks on a responsibility the Keeper
// snapshot already established.
func (c *KeeperABCIClient) FrozenVerifierWindowMember(ctx context.Context, taskID string, verifyRound uint32, operatorAddress string) (VerifierCandidateMemberSnapshot, error) {
	return c.verifierWindowMember(ctx, taskID, verifyRound, operatorAddress, false)
}

// verifierWindowMember serves both reads. requireOpenHandraise is the only
// difference between them, and it is a parameter rather than a second query so
// that the READY/schema/membership checks below cannot drift apart.
func (c *KeeperABCIClient) verifierWindowMember(ctx context.Context, taskID string, verifyRound uint32, operatorAddress string, requireOpenHandraise bool) (VerifierCandidateMemberSnapshot, error) {
	rawTaskID, err := hex.DecodeString(taskID)
	if err != nil || len(rawTaskID) != 32 || verifyRound == 0 {
		return VerifierCandidateMemberSnapshot{}, fmt.Errorf("verifier window task identity is invalid")
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return VerifierCandidateMemberSnapshot{}, err
	}
	var response taskv1.QueryVerifierCandidateWindowResponse
	request := &taskv1.QueryVerifierCandidateWindowRequest{TaskId: rawTaskID, VerifyRound: verifyRound}
	if err := c.query(ctx, taskQuery+"VerifierCandidateWindow", height, request, &response); err != nil {
		// FailedPrecondition here is the documented answer for a window still in
		// SOURCE_FROZEN, not a fault: keeper-interface-contract §4.4 writes the header in the
		// same transaction that accepts the infer receipt and turns it READY only
		// once the Beacon at h_window = h0 + delta_w lands, and §10.3 keeps the
		// build index pending across every block where that Beacon is missing.
		// The Builder is allowed to broadcast OPEN_VERIFY before then --
		// 04-task-execution-verification-and-settlement.md §6 requires only an accepted receipt and local
		// data -- so a candidate reaching this query early is the normal timeline,
		// and interface-and-topic-list.md §5.9 tells it to wait.
		if errors.Is(err, ErrFailedPrecondition) {
			return VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: %w", ErrVerifierWindowNotReady, err)
		}
		return VerifierCandidateMemberSnapshot{}, err
	}
	window := response.Window
	if window.Status != verifierCandidateWindowReady {
		return VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: status=%d", ErrVerifierWindowNotReady, window.Status)
	}
	// Everything below is a READY window contradicting its own contract, which no
	// amount of waiting repairs.
	if window.SchemaVersion != 1 || len(window.InferReceiptHash) != 32 ||
		len(window.CandidatePoolSnapshotId) != 32 || window.HandraiseCloseHeight == 0 {
		return VerifierCandidateMemberSnapshot{}, fmt.Errorf("READY verifier candidate window fields are invalid")
	}
	// A close height already behind the committed height is not a malformed
	// window, which is what it used to be reported as. The window is intact and
	// the chain is answering exactly what it recorded; what has passed is the
	// interval this node was allowed to act in. Every READY window on a devnet
	// answers this way once the task is a few blocks old, so calling it invalid
	// spent a caller's remaining attempts on a state that will never change.
	//
	// Only the handraise-phase read is bounded by it. The frozen-set read is
	// asking a question the close height does not answer -- see
	// FrozenVerifierWindowMember.
	if requireOpenHandraise && window.HandraiseCloseHeight < height {
		return VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: handraise_close_height=%d committed_height=%d",
			ErrVerifierWindowClosed, window.HandraiseCloseHeight, height)
	}
	for _, member := range response.Members {
		if member.OperatorAddress != operatorAddress {
			continue
		}
		if member.SchemaVersion != 1 || member.VerifyRound != verifyRound || member.SlotVersion == 0 {
			return VerifierCandidateMemberSnapshot{}, fmt.Errorf("verifier candidate member is invalid")
		}
		return VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: ProtoBytes32(window.CandidatePoolSnapshotId),
				Slot:                    member.Slot, SlotVersion: member.SlotVersion, OperatorAddress: member.OperatorAddress,
			},
			InferReceiptHash: ProtoBytes32(window.InferReceiptHash), ExpiryHeight: window.HandraiseCloseHeight,
		}, nil
	}
	return VerifierCandidateMemberSnapshot{}, fmt.Errorf("operator %s is not in the READY verifier window for verify_round %d", operatorAddress, verifyRound)
}
