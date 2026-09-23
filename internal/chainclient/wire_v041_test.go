package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	gogoproto "github.com/cosmos/gogoproto/proto"
)

func TestOutputStreamLimitsRequireCommittedCurrentParams(t *testing.T) {
	for _, test := range []struct {
		name      string
		params    *taskv1.TaskParamsV1
		wantError bool
	}{
		{"current", &taskv1.TaskParamsV1{SchemaVersion: 1, Evidence: &taskv1.EvidenceLimitParamsV1{MaxOutputMmrLeaves: 1000, MinOutputStreamFrameBytes: 256}}, false},
		{"missing params", nil, true},
		{"wrong schema", &taskv1.TaskParamsV1{SchemaVersion: 2, Evidence: &taskv1.EvidenceLimitParamsV1{MaxOutputMmrLeaves: 1000, MinOutputStreamFrameBytes: 256}}, true},
		{"missing evidence", &taskv1.TaskParamsV1{SchemaVersion: 1}, true},
		{"missing leaf cap", &taskv1.TaskParamsV1{SchemaVersion: 1, Evidence: &taskv1.EvidenceLimitParamsV1{MinOutputStreamFrameBytes: 256}}, true},
		{"missing frame minimum", &taskv1.TaskParamsV1{SchemaVersion: 1, Evidence: &taskv1.EvidenceLimitParamsV1{MaxOutputMmrLeaves: 1000}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newABCITestServer(t, func(path, height string, data []byte) (gogoproto.Message, uint32, string) {
				if path != taskQuery+"Params" || height != strconv.FormatUint(abciTestCommittedHeight, 10) {
					t.Errorf("unpinned params query: path=%s height=%s", path, height)
				}
				var request taskv1.QueryTaskParamsRequest
				mustUnmarshalProto(t, data, &request)
				return &taskv1.QueryTaskParamsResponse{Params: test.params}, 0, ""
			})
			defer server.Close()
			got, err := NewKeeperABCIClient(server.URL).OutputStreamLimits(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("limits=%+v error=%v", got, err)
			}
			if !test.wantError && (got.MaxOutputMMRLeaves != 1000 || got.MinOutputStreamFrameBytes != 256 || got.SnapshotHeight != abciTestCommittedHeight) {
				t.Fatalf("limits=%+v", got)
			}
		})
	}
}

func TestWireV041CurrentKeyRejectsWrongStatusArmAndUnknownEnum(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*hubv1.CurrentServiceKeyViewV1)
	}{
		{"missing arm", func(b *hubv1.CurrentServiceKeyViewV1) { b.ParticipantStatus = nil }},
		{"wrong arm", func(b *hubv1.CurrentServiceKeyViewV1) {
			b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE}
		}},
		{"zero enum", func(b *hubv1.CurrentServiceKeyViewV1) {
			b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{}
		}},
		{"unknown enum", func(b *hubv1.CurrentServiceKeyViewV1) {
			b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{BuilderServiceKeyStatus: 99}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := &hubv1.CurrentServiceKeyViewV1{ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER}
			test.mutate(binding)
			if _, err := serviceKeySnapshotFromWire(binding); err == nil {
				t.Fatal("accepted invalid binding status")
			}
		})
	}
}

func TestWireV041TaskReadsReceiptLeafCountAtCommittedHeight(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*taskv1.InferReceiptState)
	}{
		{"current", nil},
		{"wrong task", func(r *taskv1.InferReceiptState) { r.TaskId = bytes.Repeat([]byte{9}, 32) }},
		{"wrong worker", func(r *taskv1.InferReceiptState) { r.WinnerWorker = "another" }},
		{"future receipt", func(r *taskv1.InferReceiptState) { r.ReceiptHeight = abciTestCommittedHeight + 1 }},
		{"missing leaf count", func(r *taskv1.InferReceiptState) { r.OutputLeafCount = 0 }},
		{"empty output with multiple leaves", func(r *taskv1.InferReceiptState) { r.OutputSizeBytes = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := bytes.Repeat([]byte{1}, 32)
			session := bytes.Repeat([]byte{2}, 32)
			receipt := &taskv1.InferReceiptState{TaskId: id, WinnerWorker: "worker", InferReceiptHash: id, OutputHash: id, OutputSizeBytes: 1024, GeneratedTokenCount: 37, OutputLeafCount: 4, ReceiptHeight: abciTestCommittedHeight}
			if test.mutate != nil {
				test.mutate(receipt)
			}
			server := newABCITestServer(t, func(path, height string, _ []byte) (gogoproto.Message, uint32, string) {
				if height != strconv.FormatUint(abciTestCommittedHeight, 10) {
					t.Errorf("query height=%s", height)
				}
				switch path {
				case taskQuery + "Task":
					return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
						Core:       &taskv1.TaskCoreState{TaskId: id, SessionId: session, AcceptedTaskHash: id, AcceptedInputHash: id, ModelId: "model", ProfileVersion: 1, ReceiptStatus: taskv1.ReceiptStatus_RECEIPT_STATUS_RECEIPT_ACCEPTED, UpdatedHeight: abciTestCommittedHeight},
						Assignment: &taskv1.TaskAssignmentViewV1{TaskId: id, WinnerWorker: testPointer("worker")},
					}}}}, 0, ""
				case taskQuery + "InferReceipt":
					return &taskv1.QueryInferReceiptResponse{Receipt: receipt}, 0, ""
				default:
					t.Fatalf("unexpected query %s", path)
					return nil, 1, "unexpected"
				}
			})
			defer server.Close()
			got, err := NewKeeperABCIClient(server.URL).Task(context.Background(), hex.EncodeToString(session), hex.EncodeToString(id))
			if test.mutate != nil {
				if err == nil {
					t.Fatal("accepted malformed receipt")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.InferReceipt.OutputLeafCount.Uint64() != 4 || got.InferReceipt.GeneratedTokenCount.Uint64() != 37 || got.InferReceipt.OutputSizeBytes.Uint64() != 1024 {
				t.Fatalf("receipt=%+v", got.InferReceipt)
			}
		})
	}
}

func TestWireV041ModelSupportPreservesP30SourcePresence(t *testing.T) {
	for _, test := range []struct {
		name      string
		setSource func(*hubv1.ModelSupportState)
		wantError bool
		wantField string
	}{
		{"epoch zero", func(s *hubv1.ModelSupportState) {
			s.P30Source = &hubv1.ModelSupportState_P30CutoffEpoch{P30CutoffEpoch: 0}
		}, false, "p30_cutoff_epoch"},
		{"bootstrap", func(s *hubv1.ModelSupportState) {
			s.P30Source = &hubv1.ModelSupportState_P30Bootstrap{P30Bootstrap: true}
		}, false, "p30_bootstrap"},
		{"missing source", func(s *hubv1.ModelSupportState) {}, true, ""},
		{"false bootstrap", func(s *hubv1.ModelSupportState) { s.P30Source = &hubv1.ModelSupportState_P30Bootstrap{} }, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &hubv1.ModelSupportState{OperatorAddress: "worker", ModelId: "model", ProfileVersion: 1, DeclaredSupport: true, SupportActive: true, ActivationKind: hubv1.ModelSupportActivationKind_MODEL_SUPPORT_ACTIVATION_KIND_WORKER_P30_ORDER_VALUE, FirstActivationDuty: sharedv1.Duty_DUTY_WORKER, SupportVersion: 1}
			state.FirstSupportTaskId = bytes.Repeat([]byte{1}, 32)
			state.LastRefreshTaskId = bytes.Repeat([]byte{2}, 32)
			test.setSource(state)
			server := newABCITestServer(t, func(path, _ string, data []byte) (gogoproto.Message, uint32, string) {
				if path != hubQuery+"ModelSupport" {
					t.Fatalf("unexpected path %s", path)
				}
				return &hubv1.QueryModelSupportResponse{Support: state}, 0, ""
			})
			defer server.Close()
			got, err := NewKeeperABCIClient(server.URL).ModelSupport(context.Background(), "worker", "model", "1")
			if (err != nil) != test.wantError {
				t.Fatalf("support=%+v error=%v", got, err)
			}
			if test.wantError {
				return
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			_, epoch := fields["p30_cutoff_epoch"]
			_, bootstrap := fields["p30_bootstrap"]
			if epoch == bootstrap || fields[test.wantField] == nil {
				t.Fatalf("P30 presence lost: %s", data)
			}
			if epoch && (got.P30CutoffEpoch == nil || got.P30CutoffEpoch.Uint64() != 0) {
				t.Fatalf("epoch zero lost: %+v", got)
			}
		})
	}
}

func TestWireV041IdentityReadsRejectMissingState(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, _ []byte) (gogoproto.Message, uint32, string) {
		switch path {
		case hubQuery + "Params":
			return &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2}}, 0, ""
		case hubQuery + "CortexNode":
			return &hubv1.QueryCortexNodeResponse{}, 0, ""
		case hubQuery + "ServiceBond":
			return &hubv1.QueryServiceBondResponse{}, 0, ""
		case hubQuery + "ModelSupport":
			return &hubv1.QueryModelSupportResponse{}, 0, ""
		default:
			t.Fatalf("unexpected path %s", path)
			return nil, 1, "unexpected"
		}
	})
	defer server.Close()
	client := NewKeeperABCIClient(server.URL)
	if _, err := client.Params(context.Background()); err == nil {
		t.Fatal("accepted missing nested params")
	}
	if _, err := client.CortexNode(context.Background(), "worker"); err == nil {
		t.Fatal("accepted missing node")
	}
	if _, err := client.ServiceBond(context.Background(), "worker"); err == nil {
		t.Fatal("accepted missing bond")
	}
	if _, err := client.ModelSupport(context.Background(), "worker", "model", "1"); err == nil {
		t.Fatal("accepted missing support")
	}
}
