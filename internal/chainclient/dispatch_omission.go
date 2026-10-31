package chainclient

import (
	"bytes"
	"context"
	"fmt"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// TaskProfileSnapshot is a Task's (model_id, profile_version).
type TaskProfileSnapshot struct {
	Height         uint64
	ModelID        []byte
	ProfileVersion uint32
}

// TaskProfile reads the profile from the active core or, once compacted,
// from the terminal summary.
func (c *KeeperABCIClient) TaskProfile(ctx context.Context, taskID []byte) (TaskProfileSnapshot, error) {
	if len(taskID) != 32 {
		return TaskProfileSnapshot{}, fmt.Errorf("task_id is %d bytes, want 32", len(taskID))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return TaskProfileSnapshot{}, err
	}
	var r taskv1.QueryTaskResponse
	if err := c.query(ctx, taskQuery+"Task", height, &taskv1.QueryTaskRequest{TaskId: taskID}, &r); err != nil {
		return TaskProfileSnapshot{}, err
	}
	var id, model []byte
	var version uint32
	if core := r.GetTask().GetActive().GetCore(); core != nil {
		id, model, version = core.GetTaskId(), core.GetModelId(), core.GetProfileVersion()
	} else if s := r.GetTask().GetTerminal(); s != nil {
		id, model, version = s.GetTaskId(), s.GetModelId(), s.GetProfileVersion()
	}
	if !bytes.Equal(id, taskID) || len(model) != 32 || version == 0 {
		return TaskProfileSnapshot{}, fmt.Errorf("Keeper task %x carries no profile", taskID)
	}
	return TaskProfileSnapshot{Height: height, ModelID: bytes.Clone(model), ProfileVersion: version}, nil
}

// CandidatePoolMember finds operator in candidate pool snapshot snapshotID
// (the pool a dispatch draw used). ErrNotFound: not a member, or the snapshot
// is gone.
func (c *KeeperABCIClient) CandidatePoolMember(ctx context.Context, snapshotID []byte, operator string) (CandidateMemberRefSnapshot, error) {
	if len(snapshotID) != 32 {
		return CandidateMemberRefSnapshot{}, fmt.Errorf("snapshot id is %d bytes, want 32", len(snapshotID))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return CandidateMemberRefSnapshot{}, err
	}
	var token []byte
	seen := map[string]bool{}
	for {
		var r hubv1.QueryCandidatePoolMembersResponse
		req := &hubv1.QueryCandidatePoolMembersRequest{SnapshotId: snapshotID, Page: &sharedv1.QueryPageRequestV1{PageToken: token, Limit: 256}}
		if err := c.query(ctx, hubQuery+"CandidatePoolMembers", height, req, &r); err != nil {
			return CandidateMemberRefSnapshot{}, err
		}
		for _, m := range r.GetMembers() {
			if m.GetOperatorAddress() == operator {
				if m.GetSlotVersion() == 0 {
					return CandidateMemberRefSnapshot{}, fmt.Errorf("CandidatePool member slot_version is required")
				}
				return CandidateMemberRefSnapshot{CandidatePoolSnapshotID: ProtoBytes32(bytes.Clone(snapshotID)), Slot: m.GetCandidateSlot(),
					SlotVersion: m.GetSlotVersion(), OperatorAddress: operator}, nil
			}
		}
		next := r.GetPage().GetNextPageToken()
		if len(next) == 0 {
			return CandidateMemberRefSnapshot{}, fmt.Errorf("operator %s in snapshot %x: %w", operator, snapshotID, ErrNotFound)
		}
		if seen[string(next)] {
			return CandidateMemberRefSnapshot{}, fmt.Errorf("Keeper repeated a pool page token")
		}
		seen[string(next)] = true
		token = bytes.Clone(next)
	}
}

// DispatchChallengeSnapshot is task.v1 DispatchChallengeState.
type DispatchChallengeSnapshot struct {
	Height                                            uint64
	ChallengeID, TaskID                               []byte
	Kind                                              sharedv1.DispatchChallengeKindV1
	Challenger, Builder, Victim                       string
	Round                                             uint32
	Status                                            taskv1.DispatchChallengeStatusV1
	OpenedHeight, ResolvedHeight, ProofDeadlineHeight uint64
}

// DispatchChallenge reads one challenge by challenge_id. ErrNotFound: the
// chain holds no such challenge.
func (c *KeeperABCIClient) DispatchChallenge(ctx context.Context, id []byte) (DispatchChallengeSnapshot, error) {
	if len(id) != 32 {
		return DispatchChallengeSnapshot{}, fmt.Errorf("challenge_id is %d bytes, want 32", len(id))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchChallengeSnapshot{}, err
	}
	var r taskv1.QueryDispatchChallengeResponse
	if err := c.query(ctx, taskQuery+"DispatchChallenge", height, &taskv1.QueryDispatchChallengeRequest{ChallengeId: id}, &r); err != nil {
		return DispatchChallengeSnapshot{}, err
	}
	s := r.GetRow()
	if !bytes.Equal(s.GetChallengeId(), id) || len(s.GetTaskId()) != 32 || s.GetStatus() == 0 || s.GetChallengerAddress() == "" {
		return DispatchChallengeSnapshot{}, fmt.Errorf("Keeper challenge %x is malformed", id)
	}
	return DispatchChallengeSnapshot{Height: height, ChallengeID: bytes.Clone(id), TaskID: bytes.Clone(s.GetTaskId()), Kind: s.GetKind(),
		Challenger: s.GetChallengerAddress(), Builder: s.GetBuilderAddress(), Victim: s.GetVictimOperatorAddress(), Round: s.GetDispatchRound(),
		Status: s.GetStatus(), OpenedHeight: s.GetOpenedHeight(), ResolvedHeight: s.GetResolvedHeight(), ProofDeadlineHeight: s.GetProofDeadlineHeight()}, nil
}
