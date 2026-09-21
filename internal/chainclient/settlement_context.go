package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	hubv1 "github.com/SingaXYZ/cortex/proto/hub/v1"
	sharedv1 "github.com/SingaXYZ/cortex/proto/shared/v1"
	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
)

// SettlementContext contains only committed Task facts and the permissionless
// submission window. It is not a locally constructed settlement plan.
type SettlementContext struct {
	TaskID               string
	SessionID            string
	Phase                uint32
	ObservedHeight       uint64
	UpdatedHeight        uint64
	PermissionlessHeight uint64
	DeadlineHeight       uint64
}

type SettlementContextReader interface {
	SettlementContext(context.Context, string) (SettlementContext, error)
}

func (s SettlementContext) Terminal() bool {
	return (s.Phase == 8 || s.Phase == 9) && s.UpdatedHeight > 0 && s.UpdatedHeight <= s.ObservedHeight
}

func (s SettlementContext) CanSubmit() bool {
	return s.Phase == 7 && s.PermissionlessHeight > 0 && s.ObservedHeight >= s.PermissionlessHeight &&
		s.DeadlineHeight >= s.PermissionlessHeight && s.ObservedHeight < s.DeadlineHeight
}

// SettlementContext uses the same TaskBuilders order and Hub grace parameter
// as Nexus's settlement submitter. Every read is pinned to one committed height.
// A closed round summary gates settlement, while the effective verifier round's
// reveal deadline anchors Builder duty. TaskStage supplies the final deadline.
func (c *KeeperABCIClient) SettlementContext(ctx context.Context, taskID string) (SettlementContext, error) {
	taskIDBytes, err := decodeTaskIDHash32(taskID)
	if err != nil || hex.EncodeToString(taskIDBytes) != taskID || bytes.Equal(taskIDBytes, make([]byte, 32)) {
		return SettlementContext{}, fmt.Errorf("settlement task_id must be canonical non-zero Hash32 hex")
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return SettlementContext{}, err
	}
	request := &taskv1.QueryTaskRequest{TaskId: taskIDBytes}
	var task taskv1.QueryTaskResponse
	if err := c.query(ctx, taskQuery+"Task", height, request, &task); err != nil {
		return SettlementContext{}, err
	}
	state := SettlementContext{TaskID: taskID, ObservedHeight: height}
	var returnedTaskID, session []byte
	switch {
	case task.GetTask().GetActive() != nil && task.GetTask().GetTerminal() == nil:
		core := task.GetTask().GetActive().Core
		if core == nil {
			return SettlementContext{}, fmt.Errorf("settlement task query has no active core")
		}
		returnedTaskID, session = core.TaskId, core.SessionId
		state.Phase, state.UpdatedHeight = uint32(core.TaskPhase), core.UpdatedHeight
	case task.GetTask().GetTerminal() != nil && task.GetTask().GetActive() == nil:
		terminal := task.GetTask().GetTerminal()
		returnedTaskID, session = terminal.TaskId, terminal.SessionId
		state.Phase, state.UpdatedHeight = uint32(terminal.TerminalPhase), terminal.SettlementHeight
		if state.UpdatedHeight == 0 {
			state.UpdatedHeight = terminal.CompactedHeight
		}
	default:
		return SettlementContext{}, fmt.Errorf("settlement task query requires exactly one active or terminal view")
	}
	if !bytes.Equal(returnedTaskID, taskIDBytes) || len(session) != 32 || bytes.Equal(session, make([]byte, 32)) {
		return SettlementContext{}, fmt.Errorf("settlement task query returned invalid task/session identity")
	}
	state.SessionID = hex.EncodeToString(session)
	if state.Phase < 1 || state.Phase > 9 || state.UpdatedHeight == 0 || state.UpdatedHeight > height {
		return SettlementContext{}, fmt.Errorf("settlement task phase or update height is invalid")
	}
	if task.GetTask().GetTerminal() != nil && !state.Terminal() {
		return SettlementContext{}, fmt.Errorf("compacted task has no terminal phase")
	}
	if state.Terminal() || state.Phase != 7 {
		return state, nil
	}
	summary := task.GetTask().GetActive().GetRoundSummary()
	if summary == nil || summary.OpenRoundCount != 0 || summary.RoundsClosedHeight == nil || *summary.RoundsClosedHeight == 0 || *summary.RoundsClosedHeight > height {
		return SettlementContext{}, fmt.Errorf("settlement requires a committed closed round summary")
	}
	var effective *taskv1.VerifierAssignmentState
	switch task.GetTask().GetActive().GetCore().GetEffectiveVerifyRound() {
	case 1:
		effective = task.GetTask().GetActive().GetRound1VerifierAssignment()
	case 2:
		effective = task.GetTask().GetActive().GetRound2VerifierAssignment()
	}
	if effective == nil || !bytes.Equal(effective.TaskId, taskIDBytes) || effective.VerifyRound != task.GetTask().GetActive().GetCore().GetEffectiveVerifyRound() || effective.RevealDeadlineHeight == 0 {
		return SettlementContext{}, fmt.Errorf("settlement requires the effective round reveal deadline")
	}
	var stage taskv1.QueryTaskStageResponse
	if err := c.query(ctx, taskQuery+"TaskStage", height, &taskv1.QueryTaskStageRequest{TaskId: taskIDBytes}, &stage); err != nil {
		return SettlementContext{}, err
	}
	if stage.Stage == nil || !bytes.Equal(stage.Stage.TaskId, taskIDBytes) || stage.Stage.GetNextDeadlineKind() != taskv1.DeadlineKindV1_DEADLINE_KIND_V1_TASK_SETTLEMENT || stage.Stage.NextDeadlineHeight == nil {
		return SettlementContext{}, fmt.Errorf("settlement deadline is unavailable from task stage")
	}
	state.DeadlineHeight = stage.Stage.GetNextDeadlineHeight()
	var builders taskv1.QueryTaskBuildersResponse
	if err := c.query(ctx, taskQuery+"TaskBuilders", height, &taskv1.QueryTaskBuildersRequest{TaskId: taskIDBytes}, &builders); err != nil {
		return SettlementContext{}, err
	}
	selection := builders.Selection
	if selection == nil || !bytes.Equal(selection.TaskId, taskIDBytes) || selection.BodyStatus != sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE || selection.SelectedTaskBuilderCount == 0 || uint64(len(selection.SelectedTaskBuilders)) != uint64(selection.SelectedTaskBuilderCount) {
		return SettlementContext{}, fmt.Errorf("settlement TaskBuilders identity, active body or selected count is invalid")
	}
	seen := make(map[string]bool, len(selection.SelectedTaskBuilders))
	for _, builder := range selection.SelectedTaskBuilders {
		if builder == "" || strings.TrimSpace(builder) != builder || seen[builder] {
			return SettlementContext{}, fmt.Errorf("settlement TaskBuilders contains an empty, non-canonical or duplicate member")
		}
		seen[builder] = true
	}
	var params hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", height, &hubv1.QueryHubParamsRequest{}, &params); err != nil {
		return SettlementContext{}, err
	}
	grace, count, anchor := params.GetParams().GetBuilder().GetSettlementBuilderGraceBlocks(), uint64(selection.SelectedTaskBuilderCount), effective.RevealDeadlineHeight
	if params.GetParams().GetSchemaVersion() != 2 || grace == 0 || anchor == math.MaxUint64 || grace > (math.MaxUint64-anchor-1)/count {
		return SettlementContext{}, fmt.Errorf("settlement grace parameter is missing or its window overflows")
	}
	state.PermissionlessHeight = anchor + count*grace + 1
	if state.PermissionlessHeight > state.DeadlineHeight {
		return SettlementContext{}, fmt.Errorf("settlement deadline does not cover the permissionless window")
	}
	return state, nil
}
