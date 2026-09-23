package chainclient

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	gogoproto "github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/proto"
)

func TestWireV040TaskSelectsAuthoritativeRound(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 32)
	session := bytes.Repeat([]byte{2}, 32)
	for _, tc := range []struct {
		name      string
		effective uint32
		round1    bool
		round2    bool
		wantRound uint64
	}{
		{"not assigned", 0, false, false, 0},
		{"round 1 open", 0, true, false, 1},
		{"round 2 open", 0, true, true, 2},
		{"round 1 effective", 1, true, false, 1},
		{"round 2 present with round 1 effective", 1, true, true, 2},
		{"round 2 effective", 2, true, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := &taskv1.TaskActiveBundleV1{Core: &taskv1.TaskCoreState{
				TaskId: id, SessionId: session, AcceptedTaskHash: id, AcceptedInputHash: id, EffectiveVerifyRound: tc.effective, UpdatedHeight: 90,
			}}
			if tc.round1 {
				active.Round1VerifierAssignment = &taskv1.VerifierAssignmentState{TaskId: id, VerifyRound: 1,
					SelectedVerifiers: []*taskv1.SelectedVerifierV1{{OperatorAddress: "round1-first", Slot: 3}, {OperatorAddress: "verifier", Slot: 5}}}
			}
			if tc.round2 {
				active.Round2VerifierAssignment = &taskv1.VerifierAssignmentState{TaskId: id, VerifyRound: 2,
					SelectedVerifiers: []*taskv1.SelectedVerifierV1{{OperatorAddress: "round2-first", Slot: 7}, {OperatorAddress: "verifier", Slot: 12}}}
			}
			response := &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: active}}}
			got, err := snapshotFromWireTask("", id, response)
			if err != nil {
				t.Fatal(err)
			}
			if got.VerifierAssignment.VerifyRound.Uint64() != tc.wantRound {
				t.Fatalf("wrong verifier round: %+v", got.VerifierAssignment)
			}
			if tc.wantRound == 0 {
				if len(got.VerifierAssignment.FormalVerifierSet) != 0 {
					t.Fatal("fabricated an unassigned verifier set")
				}
			} else if len(got.VerifierAssignment.FormalVerifierSet) != 2 ||
				got.VerifierAssignment.FormalVerifierSet[0] != "round"+strconv.FormatUint(tc.wantRound, 10)+"-first" ||
				got.VerifierAssignment.SelectedVerifierIndexes["verifier"] != 1 {
				t.Fatalf("wrong verifier set or selected index: %+v", got.VerifierAssignment)
			}
			if got.UpdatedHeight.Uint64() != 90 {
				t.Fatalf("updated height = %d", got.UpdatedHeight.Uint64())
			}
		})
	}
}

func TestWireTaskRejectsMismatchedVerifierAssignment(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 32)
	for _, round := range []uint32{1, 2} {
		for _, mismatch := range []string{"task", "round"} {
			t.Run(strconv.Itoa(int(round))+"/"+mismatch, func(t *testing.T) {
				assignment := &taskv1.VerifierAssignmentState{TaskId: id, VerifyRound: round}
				if mismatch == "task" {
					assignment.TaskId = bytes.Repeat([]byte{3}, 32)
				} else {
					assignment.VerifyRound = 3 - round
				}
				active := &taskv1.TaskActiveBundleV1{Core: &taskv1.TaskCoreState{
					TaskId: id, SessionId: id, AcceptedTaskHash: id, AcceptedInputHash: id,
				}}
				if round == 1 {
					active.Round1VerifierAssignment = assignment
				} else {
					active.Round1VerifierAssignment = &taskv1.VerifierAssignmentState{TaskId: id, VerifyRound: 1}
					active.Round2VerifierAssignment = assignment
				}
				response := &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: active}}}
				if _, err := snapshotFromWireTask("", id, response); err == nil {
					t.Fatal("accepted mismatched current assignment or fell back to an older round")
				}
			})
		}
	}
}

func marshalTestProto(message gogoproto.Message) ([]byte, error) {
	if current, ok := message.(proto.Message); ok {
		return proto.Marshal(current)
	}
	return gogoproto.Marshal(message)
}

func unmarshalTestProto(data []byte, message gogoproto.Message) error {
	if current, ok := message.(proto.Message); ok {
		return proto.Unmarshal(data, current)
	}
	return gogoproto.Unmarshal(data, message)
}

func testPointer[T any](value T) *T { return &value }

func TestWireV041BuilderKeyStatusIsAuthoritative(t *testing.T) {
	for _, keyStatus := range []hubv1.ServiceKeyStatus{hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE, hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED} {
		t.Run(keyStatus.String(), func(t *testing.T) {
			server := newABCITestServer(t, func(path, height string, _ []byte) (gogoproto.Message, uint32, string) {
				if height != strconv.FormatUint(abciTestCommittedHeight, 10) {
					t.Errorf("query %s height=%q", path, height)
				}
				switch path {
				case hubQuery + "CurrentServiceKey":
					return &hubv1.QueryCurrentServiceKeyResponse{Binding: &hubv1.CurrentServiceKeyViewV1{
						ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, OperatorAddress: "builder", ServiceAddress: "service", ServicePubkey: append([]byte{2}, bytes.Repeat([]byte{1}, 32)...), ServiceAuthorizationNonce: 9, CurrentDescriptorVersion: 7, ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{BuilderServiceKeyStatus: keyStatus},
					}}, 0, ""
				default:
					t.Fatalf("unexpected path %s", path)
					return nil, 0, ""
				}
			})
			defer server.Close()
			key, err := NewKeeperABCIClient(server.URL).CurrentServiceKey(context.Background(), ParticipantTypeBuilder, "builder", 0)
			if err != nil {
				t.Fatal(err)
			}
			wantKey := "ACTIVE"
			if keyStatus == hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED {
				wantKey = "REVOKED"
			}
			if key.Status != wantKey || key.AuthorizationNonce.Uint64() != 9 || key.CurrentDescriptorVersion.Uint64() != 7 {
				t.Fatalf("key = %+v", key)
			}
		})
	}
}
