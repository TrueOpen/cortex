package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"

	hubv1 "github.com/SingaXYZ/cortex/proto/hub/v1"
	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
	"github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

type settlementWireFixture []byte

func (m *settlementWireFixture) Reset()                   { *m = nil }
func (m *settlementWireFixture) String() string           { return "settlement wire fixture" }
func (*settlementWireFixture) ProtoMessage()              {}
func (m *settlementWireFixture) Marshal() ([]byte, error) { return *m, nil }

func settlementBytes(field protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, field, protowire.BytesType), value)
}

func settlementUint(field protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, field, protowire.VarintType), value)
}

// Generated responses follow the exact v0.4.0 descriptors.
func settlementFixtureResponse(path string, taskID []byte, phase, anchor, grace uint64, builders []string, count uint64) proto.Message {
	switch path {
	case taskQuery + "Task":
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core:                     &taskv1.TaskCoreState{TaskId: taskID, SessionId: bytes.Repeat([]byte{0x12}, 32), TaskPhase: taskv1.TaskPhase(phase), UpdatedHeight: abciTestCommittedHeight - 1, EffectiveVerifyRound: 1},
			RoundSummary:             &taskv1.TaskRoundSummaryState{RoundsClosedHeight: testPointer(uint64(abciTestCommittedHeight - 1))},
			Round1VerifierAssignment: &taskv1.VerifierAssignmentState{TaskId: taskID, VerifyRound: 1, RevealDeadlineHeight: anchor},
		}}}}
	case taskQuery + "TaskStage":
		return &taskv1.QueryTaskStageResponse{Stage: &taskv1.TaskStageViewV1{TaskId: taskID, NextDeadlineKind: taskv1.DeadlineKindV1_DEADLINE_KIND_V1_TASK_SETTLEMENT.Enum(), NextDeadlineHeight: testPointer(uint64(abciTestCommittedHeight + 100))}}
	case taskQuery + "TaskBuilders":
		return &taskv1.QueryTaskBuildersResponse{Selection: &taskv1.TaskBuilderSelectionViewV1{TaskId: taskID, SelectedTaskBuilders: builders, SelectedTaskBuilderCount: uint32(count), BodyStatus: 1}}
	case hubQuery + "Params":
		return &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Builder: &hubv1.BuilderParamsV1{SettlementBuilderGraceBlocks: grace}}}
	}
	return nil
}

func TestSettlementContextUsesRegisteredQueriesAtOneCommittedHeight(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	taskBytes, _ := hex.DecodeString(taskID)
	var queries []string
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		queries = append(queries, path)
		if height != strconv.FormatUint(abciTestCommittedHeight, 10) {
			t.Errorf("query %s height=%q, want the committed height", path, height)
		}
		if path != hubQuery+"Params" && !bytes.Equal(data, settlementBytes(1, taskBytes)) {
			t.Errorf("query %s request=%x, want only task_id", path, data)
		}
		return settlementFixtureResponse(path, taskBytes, 7, abciTestCommittedHeight-7, 2, []string{"builder-1", "builder-2", "builder-3"}, 3), 0, ""
	})
	defer server.Close()
	state, err := NewKeeperABCIClient(server.URL).SettlementContext(context.Background(), taskID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CanSubmit() || state.Terminal() || state.TaskID != taskID || state.SessionID != strings.Repeat("12", 32) || state.PermissionlessHeight != abciTestCommittedHeight {
		t.Fatalf("context=%#v, want permissionless settlement at this height", state)
	}
	if got := strings.Join(queries, ","); got != taskQuery+"Task,"+taskQuery+"TaskStage,"+taskQuery+"TaskBuilders,"+hubQuery+"Params" {
		t.Fatalf("queries=%s, want registered Task, TaskBuilders and Params only", got)
	}
}

func TestSettlementContextChecksGraceAndRejectsInvalidSchedules(t *testing.T) {
	for _, test := range []struct {
		name                 string
		anchor, grace, count uint64
		builders             []string
		wantError            bool
	}{
		{name: "last exclusive Builder block", anchor: abciTestCommittedHeight - 6, grace: 2, count: 3, builders: []string{"a", "b", "c"}},
		{name: "missing grace", anchor: 1, count: 1, builders: []string{"a"}, wantError: true},
		{name: "missing reveal deadline", grace: 2, count: 1, builders: []string{"a"}, wantError: true},
		{name: "missing Builders", anchor: 1, grace: 2, wantError: true},
		{name: "count mismatch", anchor: 1, grace: 2, count: 2, builders: []string{"a"}, wantError: true},
		{name: "duplicate Builders", anchor: 1, grace: 2, count: 2, builders: []string{"a", "a"}, wantError: true},
		{name: "overflow", anchor: 1, grace: math.MaxUint64, count: 2, builders: []string{"a", "b"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			taskBytes := bytes.Repeat([]byte{0xab}, 32)
			server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
				return settlementFixtureResponse(path, taskBytes, 7, test.anchor, test.grace, test.builders, test.count), 0, ""
			})
			defer server.Close()
			state, err := NewKeeperABCIClient(server.URL).SettlementContext(context.Background(), hex.EncodeToString(taskBytes))
			if (err != nil) != test.wantError {
				t.Fatalf("context=%#v error=%v, want error=%t", state, err, test.wantError)
			}
			if state.CanSubmit() {
				t.Fatal("unsafe settlement became eligible")
			}
		})
	}
}

func TestSettlementContextReadsTerminalTaskWithoutRetiredSettlementRPC(t *testing.T) {
	for _, compacted := range []bool{false, true} {
		for _, phase := range []uint64{8, 9} {
			taskBytes := bytes.Repeat([]byte{0xab}, 32)
			server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
				if path != taskQuery+"Task" {
					t.Errorf("unexpected query for terminal task: %s", path)
				}
				if !compacted {
					return settlementFixtureResponse(path, taskBytes, phase, 0, 0, nil, 0), 0, ""
				}
				terminal := settlementBytes(1, taskBytes)
				terminal = append(terminal, settlementBytes(2, bytes.Repeat([]byte{0x12}, 32))...)
				terminal = append(terminal, settlementUint(5, phase)...)
				if phase == 8 {
					terminal = append(terminal, settlementUint(31, abciTestCommittedHeight-10)...)
				} else {
					terminal = append(terminal, settlementUint(44, abciTestCommittedHeight-1)...)
				}
				fixture := settlementWireFixture(settlementBytes(1, settlementBytes(2, terminal)))
				return &fixture, 0, ""
			})
			state, err := NewKeeperABCIClient(server.URL).SettlementContext(context.Background(), hex.EncodeToString(taskBytes))
			server.Close()
			if err != nil || !state.Terminal() || state.CanSubmit() {
				t.Fatalf("compacted=%t context=%#v error=%v", compacted, state, err)
			}
		}
	}
}

func TestSettlementContextDoesNotSubmitAtCommittedDeadline(t *testing.T) {
	state := SettlementContext{Phase: 7, ObservedHeight: 200, PermissionlessHeight: 100, DeadlineHeight: 200}
	if state.CanSubmit() {
		t.Fatal("a transaction cannot enter the already committed deadline block")
	}
	state.ObservedHeight = 199
	if !state.CanSubmit() {
		t.Fatal("the block before the deadline should remain eligible")
	}
}
