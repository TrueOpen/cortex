package chainclient

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func decodeTaskIDHash32(taskID string) ([]byte, error) {
	_, key, err := canonicalTaskKey(taskID)
	return key, err
}

func hexHashFromBytes(raw []byte, field string) (HexHash, error) {
	if len(raw) != 32 {
		return HexHash{}, fmt.Errorf("Keeper %s must be 32 bytes", field)
	}
	var hash HexHash
	copy(hash[:], raw)
	return hash, nil
}

func snapshotFromWireTask(sessionID string, requestedTaskID []byte, response *taskv1.QueryTaskResponse) (TaskSnapshot, error) {
	view := response.GetTask()
	if terminal := view.GetTerminal(); terminal != nil {
		return snapshotFromTerminalTask(sessionID, requestedTaskID, terminal)
	}
	active := view.GetActive()
	if active == nil || active.Core == nil {
		return TaskSnapshot{}, fmt.Errorf("Keeper QueryTask response has no active core or terminal task")
	}
	core := active.Core
	if !bytes.Equal(core.TaskId, requestedTaskID) {
		return TaskSnapshot{}, fmt.Errorf("Keeper QueryTask task_id does not match the request")
	}
	acceptedTaskHash, err := hexHashFromBytes(core.AcceptedTaskHash, "accepted_task_hash")
	if err != nil {
		return TaskSnapshot{}, err
	}
	inputHash, err := hexHashFromBytes(core.AcceptedInputHash, "accepted_input_hash")
	if err != nil {
		return TaskSnapshot{}, err
	}
	gotSession := sessionIDFromCore(core.SessionId)
	if gotSession == "" || sessionID != "" && gotSession != sessionID {
		return TaskSnapshot{}, fmt.Errorf("Keeper QueryTask session_id does not match the request")
	}
	assignment := AssignmentSnapshot{
		SessionID: gotSession, TaskID: hex.EncodeToString(core.TaskId), OrderSequence: NewUint64String(core.OrderSequence),
		AcceptedOrderPayloadHash: inputHash, ModelID: core.ModelId, ProfileVersion: NewProfileVersion(core.ProfileVersion),
		TaskReceiptFactsSnapshot: TaskReceiptFactsSnapshot{AcceptedTaskHash: ProtoBytes32(acceptedTaskHash[:])},
	}
	if view := active.Assignment; view != nil {
		assignment.SelectedWorker = view.GetWinnerWorker()
		assignment.WinnerConfirmHeight = NewUint64String(view.GetWinnerConfirmHeight())
		assignment.InferDeadlineHeight = NewUint64String(view.GetInferDeadlineHeight())
		assignment.GenerationParamsDigest = ProtoBytes32(view.GenerationParamsDigest)
		assignment.ProfileExecutionSnapshotHash = ProtoBytes32(view.ProfileExecutionSnapshotHash)
	}
	status := "ACTIVE"
	if assignment.SelectedWorker != "" {
		status = "ASSIGNED"
	}
	if core.EffectiveVerifyRound > 2 {
		return TaskSnapshot{}, fmt.Errorf("Keeper effective verification round %d is unsupported", core.EffectiveVerifyRound)
	}
	// EffectiveVerifyRound is a settlement outcome and stays zero while rounds
	// are open. The latest finalized assignment identifies the execution round.
	verifier, verifyRound := active.Round1VerifierAssignment, uint32(1)
	if active.Round2VerifierAssignment != nil {
		verifier, verifyRound = active.Round2VerifierAssignment, 2
	}
	if verifier != nil && (!bytes.Equal(verifier.TaskId, requestedTaskID) || verifier.VerifyRound != verifyRound) {
		return TaskSnapshot{}, fmt.Errorf("Keeper verifier assignment does not match task round")
	}
	return TaskSnapshot{Status: status, UpdatedHeight: NewUint64String(core.UpdatedHeight), Assignment: assignment, VerifierAssignment: verifierAssignmentSnapshot(gotSession, verifier), CurrentContract: true}, nil
}

func snapshotFromTerminalTask(sessionID string, requestedTaskID []byte, terminal *taskv1.TaskTerminalSummaryState) (TaskSnapshot, error) {
	if !bytes.Equal(terminal.TaskId, requestedTaskID) || len(terminal.TaskHash) != 32 {
		return TaskSnapshot{}, fmt.Errorf("Keeper terminal task identity does not match request")
	}
	gotSession := sessionIDFromCore(terminal.SessionId)
	if gotSession == "" || sessionID != "" && gotSession != sessionID {
		return TaskSnapshot{}, fmt.Errorf("Keeper terminal task session_id does not match request")
	}
	return TaskSnapshot{
		Status: TaskStatusTerminal, UpdatedHeight: NewUint64String(terminal.CompactedHeight), CurrentContract: true,
		Assignment: AssignmentSnapshot{SessionID: gotSession, TaskID: hex.EncodeToString(terminal.TaskId), OrderSequence: NewUint64String(terminal.OrderSequence), ModelID: terminal.ModelId, ProfileVersion: NewProfileVersion(terminal.ProfileVersion), SelectedWorker: terminal.GetWinnerWorker(), TaskReceiptFactsSnapshot: TaskReceiptFactsSnapshot{AcceptedTaskHash: ProtoBytes32(terminal.TaskHash), GenerationParamsDigest: ProtoBytes32(terminal.GenerationParamsDigest), ProfileExecutionSnapshotHash: ProtoBytes32(terminal.ProfileExecutionSnapshotHash)}},
		Settlement: SettlementSnapshot{TaskVerdict: strings.TrimPrefix(terminal.Verdict.String(), "TASK_VERDICT_"), SettlementHeight: NewUint64String(terminal.SettlementHeight)},
	}, nil
}

func verifierAssignmentSnapshot(sessionID string, state *taskv1.VerifierAssignmentState) VerifierAssignmentSnapshot {
	if state == nil {
		return VerifierAssignmentSnapshot{}
	}
	verifiers := make([]string, len(state.SelectedVerifiers))
	indexes := make(map[string]uint32, len(verifiers))
	for index, verifier := range state.SelectedVerifiers {
		verifiers[index] = verifier.GetOperatorAddress()
		indexes[verifier.GetOperatorAddress()] = uint32(index)
	}
	var windowHash, seed HexHash
	copy(windowHash[:], state.VerifierCandidateWindowHash)
	copy(seed[:], state.SelectionRandomnessBeacon)
	return VerifierAssignmentSnapshot{SessionID: sessionID, TaskID: hex.EncodeToString(state.TaskId), VerifyRound: NewUint64String(uint64(state.VerifyRound)), SelectedVerifierIndexes: indexes, OpenVerifyHeight: NewUint64String(state.OpenVerifyHeight), FormalVerifierSet: CSVStrings(verifiers), SampleSeedReadyHeight: NewUint64String(state.SelectionRandomnessHeight), VerificationSampleSeed: seed, CommitDeadlineHeight: NewUint64String(state.CommitDeadlineHeight), RevealDeadlineHeight: NewUint64String(state.RevealDeadlineHeight), VerifyDeadlineHeight: NewUint64String(state.VerifyDeadlineHeight), SampleSeedStatus: "READY", VerifierCandidateWindowHash: windowHash}
}

func sessionIDFromCore(raw []byte) string {
	if len(raw) != 32 {
		return ""
	}
	return hex.EncodeToString(raw)
}
