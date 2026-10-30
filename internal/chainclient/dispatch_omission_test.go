package chainclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cosmos/gogoproto/proto"
	gproto "google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func serveOne(t *testing.T, path string, answer func([]byte) (proto.Message, uint32, string)) *KeeperABCIClient {
	t.Helper()
	server := newABCITestServer(t, func(p, height string, data []byte) (proto.Message, uint32, string) {
		if p != path || height != "900" {
			t.Errorf("ABCI %s at %s", p, height)
		}
		return answer(data)
	})
	t.Cleanup(server.Close)
	return NewKeeperABCIClient(server.URL)
}

func TestDispatchRecordCarriesTheRounds(t *testing.T) {
	state := &taskv1.DispatchRecordState{
		TaskId: bytes.Repeat([]byte{3}, 32), DispatchRecordHash: bytes.Repeat([]byte{0x77}, 32), DispatchTicketHash: bytes.Repeat([]byte{0x42}, 32),
		BuilderAddress: "trueopen1builder", ReferenceHeight: 100, CandidatePoolSnapshotId: bytes.Repeat([]byte{0x66}, 32), EarliestSubmitHeight: 110,
		Rounds: []*taskv1.DispatchRoundV1{
			{DispatchRound: 0, HandraiseRootDigest: bytes.Repeat([]byte{0xa0}, 32), RosterHash: bytes.Repeat([]byte{0xb0}, 32)},
			{DispatchRound: 1, HandraiseRootDigest: bytes.Repeat([]byte{0xa1}, 32), RosterHash: bytes.Repeat([]byte{0xb1}, 32)}},
		Winner: &taskv1.CandidateMemberRefV1{OperatorAddress: "trueopen1worker"}, WinnerRound: 1, RecordedHeight: 120,
	}
	get := func(s *taskv1.DispatchRecordState) (DispatchRecordSnapshot, error) {
		return serveOne(t, taskQuery+"DispatchRecord", func([]byte) (proto.Message, uint32, string) {
			return &taskv1.QueryDispatchRecordResponse{Record: s}, 0, ""
		}).DispatchRecord(context.Background(), bytes.Repeat([]byte{4}, 32), 7)
	}
	got, err := get(state)
	if err != nil || got.EarliestSubmitHeight != 110 || got.ReferenceHeight != 100 || len(got.Rounds) != 2 ||
		got.Rounds[1].Round != 1 || got.Rounds[1].RosterHash[0] != 0xb1 || got.Rounds[0].HandraiseRootDigest[0] != 0xa0 || got.CandidatePoolSnapshotID[0] != 0x66 {
		t.Fatalf("snapshot = %+v, %v", got, err)
	}
	bad := gproto.Clone(state).(*taskv1.DispatchRecordState)
	bad.Rounds[0].RosterHash = []byte{1}
	if _, err := get(bad); err == nil {
		t.Fatal("a round with a short roster hash is refused")
	}
	none := gproto.Clone(state).(*taskv1.DispatchRecordState)
	none.Rounds = nil
	if _, err := get(none); err == nil {
		t.Fatal("a record has at least one round")
	}
	nosnap := gproto.Clone(state).(*taskv1.DispatchRecordState)
	nosnap.CandidatePoolSnapshotId = nil
	if _, err := get(nosnap); err == nil {
		t.Fatal("a record names its candidate pool snapshot")
	}
}

func TestTaskProfileReadsActiveOrTerminal(t *testing.T) {
	tid, model := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{0xab}, 32)
	for _, view := range []*taskv1.TaskViewV1{
		{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{Core: &taskv1.TaskCoreState{TaskId: tid, ModelId: model, ProfileVersion: 2}}}},
		{Value: &taskv1.TaskViewV1_Terminal{Terminal: &taskv1.TaskTerminalSummaryState{TaskId: tid, ModelId: model, ProfileVersion: 2}}},
	} {
		got, err := serveOne(t, taskQuery+"Task", func([]byte) (proto.Message, uint32, string) {
			return &taskv1.QueryTaskResponse{Task: view}, 0, ""
		}).TaskProfile(context.Background(), tid)
		if err != nil || !bytes.Equal(got.ModelID, model) || got.ProfileVersion != 2 || got.Height != 900 {
			t.Fatalf("profile = %+v, %v", got, err)
		}
	}
	other := &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{Core: &taskv1.TaskCoreState{TaskId: bytes.Repeat([]byte{9}, 32), ModelId: model, ProfileVersion: 2}}}}
	if _, err := serveOne(t, taskQuery+"Task", func([]byte) (proto.Message, uint32, string) {
		return &taskv1.QueryTaskResponse{Task: other}, 0, ""
	}).TaskProfile(context.Background(), tid); err == nil {
		t.Fatal("an answer for another task is refused")
	}
}

func TestCandidatePoolMemberPagesTheSnapshot(t *testing.T) {
	snap := bytes.Repeat([]byte{0x66}, 32)
	c := serveOne(t, hubQuery+"CandidatePoolMembers", func(data []byte) (proto.Message, uint32, string) {
		var req hubv1.QueryCandidatePoolMembersRequest
		_ = unmarshalTestProto(data, &req)
		if !bytes.Equal(req.GetSnapshotId(), snap) {
			t.Error("snapshot selector")
		}
		if len(req.GetPage().GetPageToken()) == 0 {
			return &hubv1.QueryCandidatePoolMembersResponse{Members: []*hubv1.CandidatePoolMemberViewV1{{CandidateSlot: 1, SlotVersion: 1, OperatorAddress: "a"}},
				Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p2")}}, 0, ""
		}
		return &hubv1.QueryCandidatePoolMembersResponse{Members: []*hubv1.CandidatePoolMemberViewV1{{CandidateSlot: 4, SlotVersion: 2, OperatorAddress: "trueopen1worker"}},
			Page: &sharedv1.QueryPageResponseV1{}}, 0, ""
	})
	m, err := c.CandidatePoolMember(context.Background(), snap, "trueopen1worker")
	if err != nil || m.Slot != 4 || m.SlotVersion != 2 || !bytes.Equal(m.CandidatePoolSnapshotID, snap) {
		t.Fatalf("member = %+v, %v", m, err)
	}
	if _, err := c.CandidatePoolMember(context.Background(), snap, "trueopen1nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent: %v", err)
	}
}

func TestDispatchChallengeReadsTheRow(t *testing.T) {
	id := bytes.Repeat([]byte{0xc1}, 32)
	got, err := serveOne(t, taskQuery+"DispatchChallenge", func(data []byte) (proto.Message, uint32, string) {
		var req taskv1.QueryDispatchChallengeRequest
		if err := unmarshalTestProto(data, &req); err != nil || !bytes.Equal(req.GetChallengeId(), id) {
			t.Errorf("selector %x, %v", req.GetChallengeId(), err)
		}
		return &taskv1.QueryDispatchChallengeResponse{Row: &taskv1.DispatchChallengeState{ChallengeId: id, TaskId: bytes.Repeat([]byte{3}, 32),
			Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION, ChallengerAddress: "trueopen1svc", BuilderAddress: "trueopen1builder",
			DispatchRound: testPointer(uint32(1)), VictimOperatorAddress: testPointer("trueopen1worker"),
			Status: taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD, OpenedHeight: 205, ResolvedHeight: testPointer(uint64(205))}}, 0, ""
	}).DispatchChallenge(context.Background(), id)
	if err != nil || got.Round != 1 || got.Victim != "trueopen1worker" || got.Challenger != "trueopen1svc" || got.Height != 900 ||
		got.Status != taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD || got.ResolvedHeight != 205 || got.OpenedHeight != 205 {
		t.Fatalf("challenge = %+v, %v", got, err)
	}
	missing := serveOne(t, taskQuery+"DispatchChallenge", func([]byte) (proto.Message, uint32, string) {
		return nil, 5, "rpc error: code = NotFound desc = no challenge"
	})
	if _, err := missing.DispatchChallenge(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent: %v", err)
	}
}
