package chainclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/cosmos/gogoproto/proto"
)

// The frozen §16.2 Task views, at TrueOpen/node contract/proto-v1-all-domains
// (d8792e6). Every number below is a field number read off that tree, and both
// the golden responses and the expected request bodies in this file are
// hand-encoded from them rather than produced by the vendored Go structs, so a
// wrong tag in proto/task/v1/query_task_frozen.pb.go cannot make these
// tests pass.
const (
	// QueryTaskResponse.task (query_task.proto:244).
	frozenFieldQueryTaskResponseTask = 1
	// TaskViewV1.active (query_task.proto:181).
	frozenFieldTaskViewActive = 1
	// TaskActiveBundleV1.core (query_task.proto:163).
	frozenFieldActiveBundleCore = 1
	// TaskCoreState.task_id (assignment.proto:198).
	frozenFieldTaskCoreTaskID = 1
	// TaskCoreState.user_address (assignment.proto:199) - not vendored by the
	// subset, present here so the golden response is a full keeper message.
	frozenFieldTaskCoreUserAddress = 2
	// TaskCoreState.accepted_task_hash (assignment.proto:202).
	frozenFieldTaskCoreAcceptedTaskHash = 5
	// QueryTaskAssignmentResponse.assignment (query_task.proto:264).
	frozenFieldQueryTaskAssignmentResponseAssignment = 1
	// TaskAssignmentViewV1.task_id (query_task.proto:89).
	frozenFieldAssignmentViewTaskID = 1
	// TaskAssignmentViewV1.judgment_function_version (query_task.proto:103) -
	// not vendored by the subset.
	frozenFieldAssignmentViewJudgmentFunctionVersion = 13
	// TaskAssignmentViewV1.generation_params_digest (query_task.proto:106).
	frozenFieldAssignmentViewGenerationParamsDigest = 16
	// QueryTaskRequest.task_id (query_task.proto:238-240).
	frozenFieldQueryTaskRequestTaskID = 1
	// QueryTaskAssignmentRequest.task_id (query_task.proto:258-260).
	frozenFieldQueryTaskAssignmentRequestTaskID = 1
)

// rawProtoMessage carries pre-encoded protobuf bytes through the ABCI test
// server, which marshals whatever proto.Message the handler returns. gogo's
// proto.Marshal prefers the Marshaler interface, so these bytes reach the client
// untouched.
type rawProtoMessage []byte

func (rawProtoMessage) Reset()                     {}
func (rawProtoMessage) String() string             { return "rawProtoMessage" }
func (rawProtoMessage) ProtoMessage()              {}
func (m rawProtoMessage) Marshal() ([]byte, error) { return append([]byte(nil), m...), nil }

// protoLenField encodes one length-delimited protobuf field.
func protoLenField(number int, payload []byte) []byte {
	var out []byte
	out = binary.AppendUvarint(out, uint64(number)<<3|2)
	out = binary.AppendUvarint(out, uint64(len(payload)))
	return append(out, payload...)
}

func frozenTaskResponseBytes(taskID, acceptedTaskHash []byte) rawProtoMessage {
	core := protoLenField(frozenFieldTaskCoreTaskID, taskID)
	core = append(core, protoLenField(frozenFieldTaskCoreUserAddress, []byte("trueopen1user"))...)
	if acceptedTaskHash != nil {
		core = append(core, protoLenField(frozenFieldTaskCoreAcceptedTaskHash, acceptedTaskHash)...)
	}
	bundle := protoLenField(frozenFieldActiveBundleCore, core)
	view := protoLenField(frozenFieldTaskViewActive, bundle)
	return rawProtoMessage(protoLenField(frozenFieldQueryTaskResponseTask, view))
}

func frozenAssignmentResponseBytes(taskID, generationParamsDigest []byte, profileHashes ...[]byte) rawProtoMessage {
	view := protoLenField(frozenFieldAssignmentViewTaskID, taskID)
	view = append(view, protoLenField(frozenFieldAssignmentViewJudgmentFunctionVersion, []byte("PREFILL_JUDGMENT_V1"))...)
	if generationParamsDigest != nil {
		view = append(view, protoLenField(frozenFieldAssignmentViewGenerationParamsDigest, generationParamsDigest)...)
	}
	profileHash := bytes.Repeat([]byte{0x44}, 32)
	if len(profileHashes) > 0 {
		profileHash = profileHashes[0]
	}
	if profileHash != nil {
		view = append(view, protoLenField(12, profileHash)...)
	}
	return rawProtoMessage(protoLenField(frozenFieldQueryTaskAssignmentResponseAssignment, view))
}

// frozenTaskFactsServer answers the two frozen queries with the supplied golden
// bytes and records the raw request bodies for the frozen-request assertions.
func frozenTaskFactsServer(t testing.TB, taskResponse, assignmentResponse rawProtoMessage, requests map[string][]byte) *KeeperABCIClient {
	t.Helper()
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if height != strconv.FormatUint(abciTestCommittedHeight, 10) {
			t.Errorf("query %s height=%s, want committed height", path, height)
		}
		if requests != nil {
			requests[path] = append([]byte(nil), data...)
		}
		switch path {
		case taskQuery + "Task":
			return taskResponse, 0, ""
		case taskQuery + "TaskAssignment":
			return assignmentResponse, 0, ""
		default:
			t.Fatalf("unexpected ABCI path %q", path)
			return nil, 0, ""
		}
	})
	t.Cleanup(server.Close)
	return NewKeeperABCIClient(server.URL)
}

func TestTaskReceiptFactsReadsFrozenTaskAndAssignmentViews(t *testing.T) {
	taskID := bytes.Repeat([]byte{0x11}, 32)
	acceptedTaskHash := bytes.Repeat([]byte{0x22}, 32)
	generationParamsDigest := bytes.Repeat([]byte{0x33}, 32)
	requests := map[string][]byte{}
	client := frozenTaskFactsServer(t,
		frozenTaskResponseBytes(taskID, acceptedTaskHash),
		frozenAssignmentResponseBytes(taskID, generationParamsDigest),
		requests,
	)

	facts, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32))
	if err != nil {
		t.Fatalf("TaskReceiptFacts() error = %v", err)
	}
	if facts.AcceptedTaskHash.Hex() != strings.Repeat("22", 32) {
		t.Fatalf("accepted_task_hash = %q", facts.AcceptedTaskHash.Hex())
	}
	if facts.GenerationParamsDigest.Hex() != strings.Repeat("33", 32) {
		t.Fatalf("generation_params_digest = %q", facts.GenerationParamsDigest.Hex())
	}
	if facts.ProfileExecutionSnapshotHash.Hex() != strings.Repeat("44", 32) {
		t.Fatalf("profile execution hash = %q", facts.ProfileExecutionSnapshotHash.Hex())
	}

	// Both queries carry the frozen request shape: a single bytes task_id, not the
	// pre-freeze {session_id, task_id} string pair. The expectation is
	// hand-encoded from the frozen field number rather than decoded with the same
	// struct that produced the request, so moving TaskId off field 1 breaks this
	// instead of cancelling out.
	wantTaskRequest := protoLenField(frozenFieldQueryTaskRequestTaskID, taskID)
	if !bytes.Equal(requests[taskQuery+"Task"], wantTaskRequest) {
		t.Fatalf("Query/Task request = %x, want %x", requests[taskQuery+"Task"], wantTaskRequest)
	}
	wantAssignmentRequest := protoLenField(frozenFieldQueryTaskAssignmentRequestTaskID, taskID)
	if !bytes.Equal(requests[taskQuery+"TaskAssignment"], wantAssignmentRequest) {
		t.Fatalf("Query/TaskAssignment request = %x, want %x",
			requests[taskQuery+"TaskAssignment"], wantAssignmentRequest)
	}
}

// A short hash must not become a zero Hash32: 32 zero bytes are a positive claim
// about consensus state, and the receipt path refuses zeros precisely because of
// that, so a silent zero-fill here would be signed as if it were read.
func TestTaskReceiptFactsRefusesWrongLengthHashes(t *testing.T) {
	taskID := bytes.Repeat([]byte{0x11}, 32)
	good := bytes.Repeat([]byte{0x22}, 32)
	for name, tc := range map[string]struct {
		task, assignment rawProtoMessage
		wantIn           string
	}{
		"short accepted_task_hash": {
			task:       frozenTaskResponseBytes(taskID, bytes.Repeat([]byte{0x22}, 31)),
			assignment: frozenAssignmentResponseBytes(taskID, good),
			wantIn:     "accepted_task_hash",
		},
		"long accepted_task_hash": {
			task:       frozenTaskResponseBytes(taskID, bytes.Repeat([]byte{0x22}, 33)),
			assignment: frozenAssignmentResponseBytes(taskID, good),
			wantIn:     "accepted_task_hash",
		},
		"short generation_params_digest": {
			task:       frozenTaskResponseBytes(taskID, good),
			assignment: frozenAssignmentResponseBytes(taskID, bytes.Repeat([]byte{0x33}, 16)),
			wantIn:     "generation_params_digest",
		},
		"short profile_execution_snapshot_hash": {
			task:       frozenTaskResponseBytes(taskID, good),
			assignment: frozenAssignmentResponseBytes(taskID, good, good[:31]),
			wantIn:     "profile_execution_snapshot_hash",
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := frozenTaskFactsServer(t, tc.task, tc.assignment, nil)
			facts, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32))
			if err == nil {
				t.Fatalf("TaskReceiptFacts() error = nil, want refusal; facts = %#v", facts)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("TaskReceiptFacts() error = %v, want it to name %s", err, tc.wantIn)
			}
			if !strings.Contains(err.Error(), "exactly 32 bytes") {
				t.Fatalf("TaskReceiptFacts() error = %v, want the bytes32 length refusal", err)
			}
			if facts.AcceptedTaskHash.IsSet() || facts.GenerationParamsDigest.IsSet() {
				t.Fatalf("a refused read returned facts: %#v", facts)
			}
		})
	}
}

// Absent and all-zero are different answers. Absent means Cortex has no value
// and reports IsSet() == false; all-zero means consensus holds those bytes and
// must survive the read so the receipt path can refuse it on its own terms.
func TestTaskReceiptFactsSeparatesAbsentFromZero(t *testing.T) {
	taskID := bytes.Repeat([]byte{0x11}, 32)
	zero := make([]byte, 32)
	good := bytes.Repeat([]byte{0x22}, 32)

	t.Run("absent accepted_task_hash", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(taskID, nil), frozenAssignmentResponseBytes(taskID, good), nil)
		_, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32))
		if err == nil || !strings.Contains(err.Error(), "accepted_task_hash is required") {
			t.Fatalf("TaskReceiptFacts() error = %v, want the absent-value refusal", err)
		}
	})
	t.Run("absent generation_params_digest", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(taskID, good), frozenAssignmentResponseBytes(taskID, nil), nil)
		_, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32))
		if err == nil || !strings.Contains(err.Error(), "generation_params_digest is required") {
			t.Fatalf("TaskReceiptFacts() error = %v, want the absent-value refusal", err)
		}
	})
	t.Run("absent profile_execution_snapshot_hash", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(taskID, good), frozenAssignmentResponseBytes(taskID, good, nil), nil)
		if _, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32)); err == nil || !strings.Contains(err.Error(), "profile_execution_snapshot_hash is required") {
			t.Fatalf("TaskReceiptFacts error = %v", err)
		}
	})
	t.Run("zero is read, not treated as absent", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(taskID, zero), frozenAssignmentResponseBytes(taskID, zero), nil)
		facts, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32))
		if err != nil {
			t.Fatalf("TaskReceiptFacts() error = %v", err)
		}
		if !facts.AcceptedTaskHash.IsSet() || !facts.GenerationParamsDigest.IsSet() {
			t.Fatalf("an all-zero consensus value must report IsSet(): %#v", facts)
		}
		if facts.AcceptedTaskHash.Hex() != strings.Repeat("00", 32) {
			t.Fatalf("accepted_task_hash = %q", facts.AcceptedTaskHash.Hex())
		}
	})
}

func TestTaskReceiptFactsRefusesMismatchedIdentityAndCompactedTask(t *testing.T) {
	taskID := bytes.Repeat([]byte{0x11}, 32)
	other := bytes.Repeat([]byte{0x99}, 32)
	good := bytes.Repeat([]byte{0x22}, 32)

	t.Run("task core answers for another task", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(other, good), frozenAssignmentResponseBytes(taskID, good), nil)
		if _, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32)); err == nil ||
			!strings.Contains(err.Error(), "core identity") {
			t.Fatalf("TaskReceiptFacts() error = %v, want the core identity refusal", err)
		}
	})
	t.Run("assignment answers for another task", func(t *testing.T) {
		client := frozenTaskFactsServer(t, frozenTaskResponseBytes(taskID, good), frozenAssignmentResponseBytes(other, good), nil)
		if _, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32)); err == nil ||
			!strings.Contains(err.Error(), "assignment identity") {
			t.Fatalf("TaskReceiptFacts() error = %v, want the assignment identity refusal", err)
		}
	})
	t.Run("no active bundle", func(t *testing.T) {
		client := frozenTaskFactsServer(t, rawProtoMessage(nil), frozenAssignmentResponseBytes(taskID, good), nil)
		if _, err := client.TaskReceiptFacts(context.Background(), strings.Repeat("11", 32)); err == nil ||
			!strings.Contains(err.Error(), "no active bundle") {
			t.Fatalf("TaskReceiptFacts() error = %v, want the missing-bundle refusal", err)
		}
	})
	t.Run("non-canonical task id never reaches the chain", func(t *testing.T) {
		client := frozenTaskFactsServer(t, rawProtoMessage(nil), rawProtoMessage(nil), nil)
		for _, id := range []string{"", "task-1", strings.Repeat("AB", 32), strings.Repeat("ab", 31)} {
			if _, err := client.TaskReceiptFacts(context.Background(), id); err == nil ||
				!strings.Contains(err.Error(), "canonical lowercase 64-hex") {
				t.Fatalf("TaskReceiptFacts(%q) error = %v, want the task id refusal", id, err)
			}
		}
	})
}

// The two facts are promoted onto AssignmentSnapshot because that is the
// snapshot the receipt path consumes. An unpopulated snapshot must still encode
// to exactly the bytes it did before the fields existed: the reconciler hashes
// json.Marshal of this struct as the authoritative task material.
func TestAssignmentSnapshotCarriesTaskReceiptFactsWithoutChangingLegacyJSON(t *testing.T) {
	var snapshot AssignmentSnapshot
	if err := json.Unmarshal([]byte(`{"session_id":"s","task_id":"t","selected_worker":"w","profile_version":1}`), &snapshot); err != nil {
		t.Fatalf("Unmarshal legacy assignment: %v", err)
	}
	if snapshot.AcceptedTaskHash.IsSet() || snapshot.GenerationParamsDigest.IsSet() {
		t.Fatalf("a pre-freeze Query/Task response must leave both facts absent: %#v", snapshot)
	}
	absent, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal unpopulated assignment: %v", err)
	}
	if bytes.Contains(absent, []byte("accepted_task_hash")) || bytes.Contains(absent, []byte("generation_params_digest")) {
		t.Fatalf("absent facts must not appear in assignment JSON: %s", absent)
	}

	snapshot.TaskReceiptFactsSnapshot = TaskReceiptFactsSnapshot{
		AcceptedTaskHash:       bytes.Repeat([]byte{0x22}, 32),
		GenerationParamsDigest: bytes.Repeat([]byte{0x33}, 32),
	}
	populated, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal populated assignment: %v", err)
	}
	var round AssignmentSnapshot
	if err := json.Unmarshal(populated, &round); err != nil {
		t.Fatalf("Unmarshal populated assignment: %v", err)
	}
	if round.AcceptedTaskHash.Hex() != strings.Repeat("22", 32) || round.GenerationParamsDigest.Hex() != strings.Repeat("33", 32) {
		t.Fatalf("round trip lost the facts: %#v", round)
	}
}
