package dispatchwire

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// ErrInRoster: the slot is a roster member; there is no absence to prove.
var ErrInRoster = errors.New("slot is in the roster")

func fixed32(b []byte) ([32]byte, bool) {
	var h [32]byte
	if len(b) != 32 {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

// RosterHash is roster_hash of r (wire dispatch.RosterDigest): the value a
// DispatchRecordState round commits.
func RosterHash(chainID string, r *taskv1.DispatchRosterV1) ([32]byte, error) {
	task, ok1 := fixed32(r.GetTaskId())
	snap, ok2 := fixed32(r.GetCandidatePoolSnapshotId())
	if !ok1 || !ok2 {
		return [32]byte{}, fmt.Errorf("roster task_id and candidate_pool_snapshot_id must be 32 bytes")
	}
	members := make([]dispatch.RosterMember, len(r.GetMembers()))
	for i, m := range r.GetMembers() {
		members[i] = dispatch.RosterMember{Slot: m.GetSlot(), SlotVersion: m.GetSlotVersion(), OperatorAddress: m.GetOperatorAddress(), CandidateWeight: m.GetCandidateWeight()}
	}
	return dispatch.RosterDigest(chainID, task, r.GetReferenceHeight(), snap, members)
}

// NonInclusion is the omission proof for slot: the roster members adjacent
// to it in strictly ascending slot order (KC §10.17, P06 §6.6.2).
func NonInclusion(r *taskv1.DispatchRosterV1, slot uint32) (*taskv1.DispatchRosterNonInclusionProofV1, error) {
	out := &taskv1.DispatchRosterNonInclusionProofV1{}
	ms := r.GetMembers()
	for i, m := range ms {
		if i > 0 && ms[i-1].GetSlot() >= m.GetSlot() {
			return nil, fmt.Errorf("roster slots are not strictly ascending")
		}
		switch {
		case m.GetSlot() == slot:
			return nil, fmt.Errorf("%w: slot %d", ErrInRoster, slot)
		case m.GetSlot() < slot:
			out.Predecessor = proto.Clone(m).(*taskv1.DispatchRosterMemberV1)
		case out.Successor == nil:
			out.Successor = proto.Clone(m).(*taskv1.DispatchRosterMemberV1)
		}
	}
	return out, nil
}

// OmissionChallengeID is challenge_id of MsgChallengeDispatchOmission (KC
// §10.17, C5): kind OMISSION, dispatch_round, victim, no Builder, zero record.
func OmissionChallengeID(chainID string, taskID [32]byte, round uint32, victim, challenger string) ([32]byte, error) {
	return dispatch.ChallengeID(chainID, dispatch.ChallengeScope{TaskID: taskID,
		Kind: uint32(sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION), DispatchRound: round,
		VictimOperator: victim, ChallengerAddress: challenger})
}

// RosterUnavailableChallengeID is challenge_id of MsgReportDispatchRosterUnavailable.
func RosterUnavailableChallengeID(chainID string, taskID [32]byte, round uint32, reporter string) ([32]byte, error) {
	return dispatch.ChallengeID(chainID, dispatch.ChallengeScope{TaskID: taskID,
		Kind: uint32(sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE), DispatchRound: round, ChallengerAddress: reporter})
}
