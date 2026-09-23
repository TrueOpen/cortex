package chainclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	"github.com/cosmos/gogoproto/proto"
)

// nodeCurrentServiceKey* mirror the Node V1 Query/CurrentServiceKey wire. They
// deliberately live in the test package so this regression test fails unless
// the production client uses the same enum request and current response view.
type nodeCurrentServiceKeyRequest struct {
	ParticipantType int32  `protobuf:"varint,1,opt,name=participant_type,json=participantType,proto3"`
	OperatorAddress string `protobuf:"bytes,2,opt,name=operator_address,json=operatorAddress,proto3"`
}

func (m *nodeCurrentServiceKeyRequest) Reset()         { *m = nodeCurrentServiceKeyRequest{} }
func (m *nodeCurrentServiceKeyRequest) String() string { return proto.CompactTextString(m) }
func (*nodeCurrentServiceKeyRequest) ProtoMessage()    {}

type nodeCurrentServiceKeyView struct {
	ParticipantType           int32  `protobuf:"varint,1,opt,name=participant_type,json=participantType,proto3"`
	OperatorAddress           string `protobuf:"bytes,2,opt,name=operator_address,json=operatorAddress,proto3"`
	ServiceAddress            string `protobuf:"bytes,3,opt,name=service_address,json=serviceAddress,proto3"`
	ServicePubkey             []byte `protobuf:"bytes,4,opt,name=service_pubkey,json=servicePubkey,proto3"`
	ServiceAuthorizationNonce uint64 `protobuf:"varint,5,opt,name=service_authorization_nonce,json=serviceAuthorizationNonce,proto3"`
	CortexServiceKeyStatus    int32  `protobuf:"varint,6,opt,name=cortex_service_key_status,json=cortexServiceKeyStatus,proto3"`
	CurrentDescriptorVersion  uint64 `protobuf:"varint,8,opt,name=current_descriptor_version,json=currentDescriptorVersion,proto3"`
}

func (m *nodeCurrentServiceKeyView) Reset()         { *m = nodeCurrentServiceKeyView{} }
func (m *nodeCurrentServiceKeyView) String() string { return proto.CompactTextString(m) }
func (*nodeCurrentServiceKeyView) ProtoMessage()    {}

type nodeCurrentServiceKeyResponse struct {
	Binding nodeCurrentServiceKeyView `protobuf:"bytes,1,opt,name=binding,proto3"`
}

func (m *nodeCurrentServiceKeyResponse) Reset()         { *m = nodeCurrentServiceKeyResponse{} }
func (m *nodeCurrentServiceKeyResponse) String() string { return proto.CompactTextString(m) }
func (*nodeCurrentServiceKeyResponse) ProtoMessage()    {}

type nodeAmount struct {
	AtomicUnits string `protobuf:"bytes,1,opt,name=atomic_units,json=atomicUnits,proto3"`
}

func (m *nodeAmount) Reset()         { *m = nodeAmount{} }
func (m *nodeAmount) String() string { return proto.CompactTextString(m) }
func (*nodeAmount) ProtoMessage()    {}

type nodeEpochParams struct {
	EpochLengthBlocks uint64 `protobuf:"varint,1,opt,name=epoch_length_blocks,json=epochLengthBlocks,proto3"`
}

func (m *nodeEpochParams) Reset()         { *m = nodeEpochParams{} }
func (m *nodeEpochParams) String() string { return proto.CompactTextString(m) }
func (*nodeEpochParams) ProtoMessage()    {}

type nodeSupportParams struct {
	SupportWindowEpochs uint32 `protobuf:"varint,1,opt,name=support_window_epochs,json=supportWindowEpochs,proto3"`
}

func (m *nodeSupportParams) Reset()         { *m = nodeSupportParams{} }
func (m *nodeSupportParams) String() string { return proto.CompactTextString(m) }
func (*nodeSupportParams) ProtoMessage()    {}

type nodeServiceParams struct {
	ServiceUnbondingPeriodBlocks uint64 `protobuf:"varint,1,opt,name=service_unbonding_period_blocks,json=serviceUnbondingPeriodBlocks,proto3"`
}

func (m *nodeServiceParams) Reset()         { *m = nodeServiceParams{} }
func (m *nodeServiceParams) String() string { return proto.CompactTextString(m) }
func (*nodeServiceParams) ProtoMessage()    {}

type nodeBuilderParams struct {
	BuilderBond nodeAmount `protobuf:"bytes,3,opt,name=builder_bond,json=builderBond,proto3"`
}

func (m *nodeBuilderParams) Reset()         { *m = nodeBuilderParams{} }
func (m *nodeBuilderParams) String() string { return proto.CompactTextString(m) }
func (*nodeBuilderParams) ProtoMessage()    {}

type nodeHubParams struct {
	SchemaVersion uint32            `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3"`
	Epoch         nodeEpochParams   `protobuf:"bytes,2,opt,name=epoch,proto3"`
	Support       nodeSupportParams `protobuf:"bytes,3,opt,name=support,proto3"`
	Service       nodeServiceParams `protobuf:"bytes,5,opt,name=service,proto3"`
	Builder       nodeBuilderParams `protobuf:"bytes,6,opt,name=builder,proto3"`
}

func (m *nodeHubParams) Reset()         { *m = nodeHubParams{} }
func (m *nodeHubParams) String() string { return proto.CompactTextString(m) }
func (*nodeHubParams) ProtoMessage()    {}

type nodeHubParamsResponse struct {
	Params nodeHubParams `protobuf:"bytes,1,opt,name=params,proto3"`
}

func (m *nodeHubParamsResponse) Reset()         { *m = nodeHubParamsResponse{} }
func (m *nodeHubParamsResponse) String() string { return proto.CompactTextString(m) }
func (*nodeHubParamsResponse) ProtoMessage()    {}

type nodeCortexNodeState struct {
	SchemaVersion                  uint32 `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3"`
	OperatorAddress                string `protobuf:"bytes,2,opt,name=operator_address,json=operatorAddress,proto3"`
	CurrentServiceAddress          string `protobuf:"bytes,3,opt,name=current_service_address,json=currentServiceAddress,proto3"`
	CurrentServicePubkey           []byte `protobuf:"bytes,4,opt,name=current_service_pubkey,json=currentServicePubkey,proto3"`
	ServiceAuthorizationNonce      uint64 `protobuf:"varint,5,opt,name=service_authorization_nonce,json=serviceAuthorizationNonce,proto3"`
	ServiceKeyStatus               int32  `protobuf:"varint,6,opt,name=service_key_status,json=serviceKeyStatus,proto3"`
	CurrentDescriptorVersion       uint64 `protobuf:"varint,7,opt,name=current_descriptor_version,json=currentDescriptorVersion,proto3"`
	RegisteredHeight               uint64 `protobuf:"varint,8,opt,name=registered_height,json=registeredHeight,proto3"`
	UpdatedHeight                  uint64 `protobuf:"varint,9,opt,name=updated_height,json=updatedHeight,proto3"`
	ActiveTaskLiabilityCount       uint32 `protobuf:"varint,10,opt,name=active_task_liability_count,json=activeTaskLiabilityCount,proto3"`
	PendingStageDutyCount          uint32 `protobuf:"varint,11,opt,name=pending_stage_duty_count,json=pendingStageDutyCount,proto3"`
	PendingEvidenceSubmissionCount uint32 `protobuf:"varint,12,opt,name=pending_evidence_submission_count,json=pendingEvidenceSubmissionCount,proto3"`
}

func (m *nodeCortexNodeState) Reset()         { *m = nodeCortexNodeState{} }
func (m *nodeCortexNodeState) String() string { return proto.CompactTextString(m) }
func (*nodeCortexNodeState) ProtoMessage()    {}

type nodeCortexNodeResponse struct {
	Node nodeCortexNodeState `protobuf:"bytes,1,opt,name=node,proto3"`
}

func (m *nodeCortexNodeResponse) Reset()         { *m = nodeCortexNodeResponse{} }
func (m *nodeCortexNodeResponse) String() string { return proto.CompactTextString(m) }
func (*nodeCortexNodeResponse) ProtoMessage()    {}

type nodeServiceBondState struct {
	OperatorAddress            string `protobuf:"bytes,1,opt,name=operator_address,json=operatorAddress,proto3"`
	ActiveBond                 uint64 `protobuf:"varint,2,opt,name=active_bond,json=activeBond,proto3"`
	EffectiveActiveBond        uint64 `protobuf:"varint,3,opt,name=effective_active_bond,json=effectiveActiveBond,proto3"`
	ReservedLiability          uint64 `protobuf:"varint,4,opt,name=reserved_liability,json=reservedLiability,proto3"`
	PendingUnbondingTotal      uint64 `protobuf:"varint,5,opt,name=pending_unbonding_total,json=pendingUnbondingTotal,proto3"`
	BondVersion                uint64 `protobuf:"varint,6,opt,name=bond_version,json=bondVersion,proto3"`
	EffectiveBondEpoch         uint64 `protobuf:"varint,7,opt,name=effective_bond_epoch,json=effectiveBondEpoch,proto3"`
	Status                     int32  `protobuf:"varint,8,opt,name=status,proto3"`
	JailCount                  uint32 `protobuf:"varint,9,opt,name=jail_count,json=jailCount,proto3"`
	NormalActionCountSinceJail uint32 `protobuf:"varint,10,opt,name=normal_action_count_since_jail,json=normalActionCountSinceJail,proto3"`
	LastStakeHeight            uint64 `protobuf:"varint,11,opt,name=last_stake_height,json=lastStakeHeight,proto3"`
	LastUnstakeHeight          uint64 `protobuf:"varint,12,opt,name=last_unstake_height,json=lastUnstakeHeight,proto3"`
}

func (m *nodeServiceBondState) Reset()         { *m = nodeServiceBondState{} }
func (m *nodeServiceBondState) String() string { return proto.CompactTextString(m) }
func (*nodeServiceBondState) ProtoMessage()    {}

type nodeServiceBondResponse struct {
	Bond nodeServiceBondState `protobuf:"bytes,1,opt,name=bond,proto3"`
}

func (m *nodeServiceBondResponse) Reset()         { *m = nodeServiceBondResponse{} }
func (m *nodeServiceBondResponse) String() string { return proto.CompactTextString(m) }
func (*nodeServiceBondResponse) ProtoMessage()    {}

func TestKeeperABCIClientQueriesModelIDContainingSlash(t *testing.T) {
	const modelID = "MODEL_PROFILE_STATUS_hf/ad410/dream-7b"
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"Model" {
			t.Fatalf("ABCI path = %q", path)
		}
		if height != "" {
			t.Fatalf("ABCI height = %q, want latest", height)
		}
		var request hubv1.QueryModelRequest
		if err := unmarshalTestProto(data, &request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.ModelId != modelID {
			t.Fatalf("model_id = %q", request.ModelId)
		}
		return &hubv1.QueryModelResponse{Model: &hubv1.ModelState{
			ModelId: modelID, ProposerAddress: "trueopen1proposer",
			Status:             hubv1.ModelProfileStatus_MODEL_PROFILE_STATUS_ACTIVE,
			ActiveProfileCount: 1, LatestProfileVersion: 2,
			StatusSource:        hubv1.ModelStatusSource_MODEL_STATUS_SOURCE_AUTO_PROFILE,
			RegistrationFeePaid: 100, CreatedHeight: 40, UpdatedHeight: 41,
		}}, 0, ""
	})
	defer server.Close()

	model, err := NewKeeperABCIClient(server.URL).CurrentModel(context.Background(), modelID)
	if err != nil {
		t.Fatalf("CurrentModel() error = %v", err)
	}
	if model.ModelID != modelID || model.LatestProfileVersion.Uint32() != 2 || model.Status != "ACTIVE" {
		t.Fatalf("CurrentModel() = %#v", model)
	}
}

func TestKeeperABCIClientReadsCurrentProfileTypedEvidenceSchema(t *testing.T) {
	manifestHash := bytes.Repeat([]byte{0xa1}, 32)
	tokenizerHash := bytes.Repeat([]byte{0xb2}, 32)
	schemaHash := bytes.Repeat([]byte{0xc3}, 32)
	registrationDigest := bytes.Repeat([]byte{0xd4}, 32)
	evidenceSchemaHash := bytes.Repeat([]byte{0xe5}, 32)
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if height != strconv.FormatUint(abciTestCommittedHeight, 10) {
			t.Fatalf("ABCI height for %s = %q, want one pinned committed height", path, height)
		}
		switch path {
		case hubQuery + "Model":
			var request hubv1.QueryModelRequest
			mustUnmarshalProto(t, data, &request)
			return &hubv1.QueryModelResponse{Model: &hubv1.ModelState{
				ModelId: request.ModelId, ProposerAddress: "trueopen1proposer",
				Status: hubv1.ModelProfileStatus_MODEL_PROFILE_STATUS_ACTIVE, ActiveProfileCount: 1,
				LatestProfileVersion: 7, StatusSource: hubv1.ModelStatusSource_MODEL_STATUS_SOURCE_AUTO_PROFILE,
				CreatedHeight: 40, UpdatedHeight: 41,
			}}, 0, ""
		case hubQuery + "Profile":
			var request hubv1.QueryProfileRequest
			mustUnmarshalProto(t, data, &request)
			return &hubv1.QueryProfileResponse{Profile: &hubv1.ProfileState{
				ModelId: request.ModelId, ProfileVersion: request.ProfileVersion,
				ManifestHash: manifestHash, TokenizerHash: tokenizerHash, RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1",
				RequiredTopK: 20, TaskTypes: []sharedv1.TaskType{1}, GenerationType: 1,
				ResourceTier: 1, MinStake: 100, ChallengeOpenWindowBlocks: 120,
				VerificationProfile: &sharedv1.VerificationProfile{
					VerificationProfileId: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1",
					VerificationMode: 1, TokenScope: 1,
					Metrics:                  &sharedv1.MetricSpec{ComparedTopK: 20},
					CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: evidenceSchemaHash,
					MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1",
					EvidenceSchema: &sharedv1.EvidenceSchemaV1{
						SchemaVersion: 1,
						RequiredInferEvidence: []*sharedv1.InferEvidenceRequirementV1{{
							EvidenceKind: 1, CommitmentSchemaVersion: 1, MaxEncodedSizeBytes: 1 << 30,
						}},
					},
				},
				VerificationThresholds: &sharedv1.VerificationThresholds{
					PassMinFiniteCount: 9, PassMeanAbsLogprobDiffMax: 18_000,
					PassAbsLogprobDiffP95Max: 100_000, PassAbsLogprobDiffP99Max: 150_000,
					PassRankDeltaNonzeroRateMax: 200_000, PassTopkJaccardMeanMin: 800_000,
					PassUnionJsP99Max: 50_000, RejectMeanAbsLogprobDiffMin: 500_000,
					RejectAbsLogprobDiffP95Min: 800_000, RejectAbsLogprobDiffP99Min: 1_000_000,
					RejectRankDeltaNonzeroRateMin: 600_000, RejectTopkJaccardMeanMax: 200_000,
					RejectUnionJsP99Min: 500_000,
				},
				PricingProfile: &sharedv1.PricingProfile{
					InitialOutputPrice: 10, VerifyRatioBps: 1_000, MinOrderValue: 1_000,
				},
				TimeoutBootstrapProfile: &sharedv1.TimeoutBootstrapProfile{
					InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50,
					CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000,
				},
				SchemaHash: schemaHash, Status: 2, StatusSource: 1,
				ProposerAddress: "trueopen1proposer", RegistrationDigest: registrationDigest, CreatedHeight: 40, UpdatedHeight: 41,
			}}, 0, ""
		default:
			t.Fatalf("path = %q", path)
			return nil, 1, "unexpected path"
		}
	})
	defer server.Close()

	state, err := NewKeeperABCIClient(server.URL).CurrentModelProfile(context.Background(), "hf/org/model", "7")
	if err != nil {
		t.Fatalf("CurrentModelProfile() error = %v", err)
	}
	schema := state.Profile.VerificationProfile.EvidenceSchema
	if state.Profile.ModelID != "hf/org/model" || state.Profile.ProfileVersion.Uint32() != 7 ||
		state.Profile.ManifestHash.Hex() != hex.EncodeToString(manifestHash) ||
		state.Profile.TokenizerHash.Hex() != hex.EncodeToString(tokenizerHash) ||
		state.Profile.SchemaHash.Hex() != hex.EncodeToString(schemaHash) ||
		state.Profile.RegistrationDigest.Hex() != hex.EncodeToString(registrationDigest) ||
		state.Profile.VerificationProfile.EvidenceSchemaHash.Hex() != hex.EncodeToString(evidenceSchemaHash) ||
		state.Profile.VerificationProfile.Metrics.ComparedTopK != 20 ||
		schema.SchemaVersion != 1 || len(schema.RequiredInferEvidence) != 1 ||
		schema.RequiredInferEvidence[0].EvidenceKind != 1 ||
		schema.RequiredInferEvidence[0].CommitmentSchemaVersion != 1 ||
		schema.RequiredInferEvidence[0].MaxEncodedSizeBytes != 1<<30 ||
		state.Profile.VerificationThresholds.PassMinFiniteCount != 9 ||
		state.Profile.VerificationThresholds.RejectUnionJSP99Min != 500_000 ||
		state.Profile.PricingProfile.InitialOutputPrice.Uint64() != 10 ||
		state.Profile.TimeoutBootstrapProfile.BootstrapValidUntilEpoch.Uint64() != 1_000 {
		t.Fatalf("CurrentModelProfile() = %#v", state)
	}
	if state.Model.Status != "ACTIVE" || state.Profile.Status != "ACTIVE" ||
		state.Profile.StatusSource != "AUTO_SUPPORT" || state.Model.StatusSource != "AUTO_PROFILE" {

		t.Fatalf("status = model/profile %q/%q source %q/%q", state.Model.Status, state.Profile.Status, state.Model.StatusSource, state.Profile.StatusSource)
	}
}
func TestKeeperABCIClientReadsCurrentCapabilityAndSupportShapes(t *testing.T) {
	hashA := bytes.Repeat([]byte{0xa1}, 32)
	hashB := bytes.Repeat([]byte{0xb2}, 32)
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		switch path {
		case hubQuery + "ProfileCapability":
			var request hubv1.QueryProfileCapabilityRequest
			mustUnmarshalProto(t, data, &request)
			return &hubv1.QueryProfileCapabilityResponse{Capability: &hubv1.ProfileCapabilityState{
				OperatorAddress: request.OperatorAddress, ModelId: request.ModelId, ProfileVersion: request.ProfileVersion,
				InferenceCapability: true, VerificationCapability: false, CapabilityVersion: 7,
			}}, 0, ""
		case hubQuery + "ModelSupport":
			var request hubv1.QueryModelSupportRequest
			mustUnmarshalProto(t, data, &request)
			return &hubv1.QueryModelSupportResponse{Support: &hubv1.ModelSupportState{
				OperatorAddress: request.OperatorAddress, ModelId: request.ModelId, ProfileVersion: request.ProfileVersion,
				DeclaredSupport: true, SupportActive: true, ActivationKind: 2, FirstActivationDuty: 1,
				FirstSupportTaskId: hashA, FirstSupportOrderValue: 30, P30Source: &hubv1.ModelSupportState_P30CutoffEpoch{P30CutoffEpoch: 9},
				SupportFreshUntilEpoch: 12, LastRefreshTaskId: hashB, LastRefreshHeight: 800,
				ActiveSupportStakeSnapshot: 100, EligibleSupportStakeSnapshot: 120, SupportVersion: 4,
			}}, 0, ""
		default:
			t.Fatalf("path = %q", path)
			return nil, 1, "unexpected path"
		}
	})
	defer server.Close()
	client := NewKeeperABCIClient(server.URL)
	capability, err := client.ModelCapability(context.Background(), "trueopen1operator", "model-a", "3")
	if err != nil {
		t.Fatalf("ModelCapability() error = %v", err)
	}
	if !capability.InferenceCapability || capability.VerificationCapability || capability.CapabilityVersion.Uint64() != 7 {
		t.Fatalf("capability = %#v", capability)
	}
	support, err := client.ModelSupport(context.Background(), "trueopen1operator", "model-a", "3")
	if err != nil {
		t.Fatalf("ModelSupport() error = %v", err)
	}
	if !support.DeclaredSupport || !support.SupportActive || support.SupportFreshUntilEpoch.Uint64() != 12 ||
		support.FirstSupportTaskID.Hex() != hex.EncodeToString(hashA) || support.LastRefreshTaskID.Hex() != hex.EncodeToString(hashB) ||
		support.EligibleSupportStakeSnapshot.Uint64() != 120 || support.SupportVersion.Uint64() != 4 {
		t.Fatalf("support = %#v", support)
	}
}

func TestKeeperABCIClientReadsCortexNodeProjection(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		if path == hubQuery+"CortexNode" {
			var request hubv1.QueryCortexNodeRequest
			mustUnmarshalProto(t, data, &request)
			return &nodeCortexNodeResponse{Node: nodeCortexNodeState{
				SchemaVersion: 1, OperatorAddress: request.OperatorAddress,
				CurrentServiceAddress:     "trueopen1service",
				CurrentServicePubkey:      append([]byte{0x02}, bytes.Repeat([]byte{0xaa}, 32)...),
				ServiceAuthorizationNonce: 3, ServiceKeyStatus: 1,
				CurrentDescriptorVersion: 1, RegisteredHeight: 10, UpdatedHeight: 20,
			}}, 0, ""
		}
		t.Fatalf("unexpected ABCI path %q", path)
		return nil, 1, "unexpected"
	})
	defer server.Close()

	node, err := NewKeeperABCIClient(server.URL).CortexNode(context.Background(), "trueopen1operator")
	if err != nil {
		t.Fatalf("CortexNode() error = %v", err)
	}
	if node.OperatorAddress != "trueopen1operator" || node.CurrentServiceAddress != "trueopen1service" ||
		node.CurrentServicePubkey != "02"+strings.Repeat("aa", 32) ||
		node.AuthorizationNonce.Uint64() != 3 || node.Status != "ACTIVE" {
		t.Fatalf("CortexNode() = %#v", node)
	}
}

func TestKeeperABCIClientReadsNodeV1ServiceBond(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"ServiceBond" {
			t.Fatalf("unexpected ABCI path %q", path)
		}
		var request hubv1.QueryServiceBondRequest
		mustUnmarshalProto(t, data, &request)
		return &nodeServiceBondResponse{Bond: nodeServiceBondState{
			OperatorAddress: request.OperatorAddress, ActiveBond: 2_000_000,
			EffectiveActiveBond: 1_500_000, ReservedLiability: 400_000,
			PendingUnbondingTotal: 100_000, BondVersion: 3, EffectiveBondEpoch: 7,
			Status: 2, JailCount: 1, LastStakeHeight: 20,
		}}, 0, ""
	})
	defer server.Close()

	bond, err := NewKeeperABCIClient(server.URL).ServiceBond(context.Background(), "trueopen1operator")
	if err != nil {
		t.Fatalf("ServiceBond() error = %v", err)
	}
	if bond.OperatorAddress != "trueopen1operator" || bond.ActiveBond.Uint64() != 2_000_000 ||
		bond.ReservedLiability.Uint64() != 400_000 || bond.BondVersion.Uint64() != 3 ||
		bond.EffectiveBondEpoch.Uint64() != 7 || bond.Status != "ACTIVE" ||
		bond.NodeJailCount.Uint64() != 1 {
		t.Fatalf("ServiceBond() = %#v", bond)
	}
}

func TestKeeperABCIClientAcceptsPostSlashReservedLiabilityAboveActiveBond(t *testing.T) {
	server := newABCITestServer(t, func(_ string, _ string, _ []byte) (proto.Message, uint32, string) {
		return &nodeServiceBondResponse{Bond: nodeServiceBondState{
			OperatorAddress: "trueopen1operator", ActiveBond: 1_000_000,
			EffectiveActiveBond: 1_000_000, ReservedLiability: 1_500_000,
			BondVersion: 4, EffectiveBondEpoch: 8, Status: 2,
		}}, 0, ""
	})
	defer server.Close()

	bond, err := NewKeeperABCIClient(server.URL).ServiceBond(context.Background(), "trueopen1operator")
	if err != nil {
		t.Fatalf("ServiceBond() rejected legal post-slash state: %v", err)
	}
	if bond.ReservedLiability.Uint64() != 1_500_000 {
		t.Fatalf("ServiceBond() = %#v", bond)
	}
}

func TestKeeperABCIClientReadsFrozenTaskView(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	sessionID := strings.Repeat("12", 32)
	sessionBytes, _ := hex.DecodeString(sessionID)
	hashBytes := bytes.Repeat([]byte{0xab}, 32)
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		if path != taskQuery+"Task" {
			t.Fatalf("path = %q", path)
		}
		var request taskv1.QueryTaskRequest
		mustUnmarshalProto(t, data, &request)
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core: &taskv1.TaskCoreState{
				TaskId: request.TaskId, SessionId: sessionBytes, OrderSequence: 1,
				AcceptedTaskHash: hashBytes, AcceptedInputHash: hashBytes,
				ModelId: "hf-model", ProfileVersion: 1,
			},
			Assignment: &taskv1.TaskAssignmentViewV1{
				WinnerWorker: testPointer("trueopen1worker"), WinnerConfirmHeight: testPointer(uint64(20)), InferDeadlineHeight: testPointer(uint64(30)),
				GenerationParamsDigest: bytes.Repeat([]byte{0x33}, 32),
			},
		}}}}, 0, ""
	})
	defer server.Close()

	task, err := NewKeeperABCIClient(server.URL).Task(context.Background(), sessionID, taskID)
	if err != nil {
		t.Fatalf("Task() error = %v", err)
	}
	if task.Assignment.SelectedWorker != "trueopen1worker" || task.Assignment.AcceptedTaskHash.Hex() != strings.Repeat("ab", 32) {
		t.Fatalf("Task() = %#v", task)
	}
}

func TestKeeperABCIClientReadsFrozenTerminalTask(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	sessionID := strings.Repeat("12", 32)
	taskBytes, _ := hex.DecodeString(taskID)
	sessionBytes, _ := hex.DecodeString(sessionID)
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		var request taskv1.QueryTaskRequest
		mustUnmarshalProto(t, data, &request)
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Terminal{Terminal: &taskv1.TaskTerminalSummaryState{
			TaskId: request.TaskId, SessionId: sessionBytes, OrderSequence: 1, TaskHash: taskBytes,
			TerminalPhase: 8, Verdict: 1, ModelId: "hf-model", ProfileVersion: 1,
			WinnerWorker: testPointer("trueopen1worker"), SettlementHeight: 40, CompactedHeight: 50,
		}}}}, 0, ""
	})
	defer server.Close()
	task, err := NewKeeperABCIClient(server.URL).Task(context.Background(), sessionID, taskID)
	if err != nil {
		t.Fatalf("Task() error = %v", err)
	}
	if task.Status != "TERMINAL" || task.Settlement.TaskVerdict != "PASS" || task.Assignment.OrderSequence.Uint64() != 1 {
		t.Fatalf("terminal task = %#v", task)
	}
}

// TestKeeperABCIClientDoesNotConflateOrderDigestWithAcceptedTaskHash asserts
// that Query/Task adapters expose accepted_task_hash under
// Assignment.AcceptedTaskHash and leave Assignment.OrderDigest unset. Using the
// order-envelope digest as the task key was the conflation that issue #218
// removes.
func TestKeeperABCIClientDoesNotConflateOrderDigestWithAcceptedTaskHash(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	sessionID := strings.Repeat("12", 32)
	sessionBytes, _ := hex.DecodeString(sessionID)
	acceptedHash := bytes.Repeat([]byte{0xab}, 32)
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		var request taskv1.QueryTaskRequest
		mustUnmarshalProto(t, data, &request)
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{
			Core: &taskv1.TaskCoreState{
				TaskId: request.TaskId, SessionId: sessionBytes, OrderSequence: 1,
				AcceptedTaskHash: acceptedHash, AcceptedInputHash: bytes.Repeat([]byte{0x22}, 32),
				ModelId: "hf-model", ProfileVersion: 1,
			},
			Assignment: &taskv1.TaskAssignmentViewV1{
				WinnerWorker: testPointer("trueopen1worker"), WinnerConfirmHeight: testPointer(uint64(20)), InferDeadlineHeight: testPointer(uint64(30)),
				GenerationParamsDigest: bytes.Repeat([]byte{0x33}, 32),
			},
		}}}}, 0, ""
	})
	defer server.Close()
	task, err := NewKeeperABCIClient(server.URL).Task(context.Background(), sessionID, taskID)
	if err != nil {
		t.Fatalf("Task() error = %v", err)
	}
	if !task.Assignment.OrderDigest.IsZero() {
		t.Fatalf("Assignment.OrderDigest = %x, want zero (order-envelope digest is not available from Query/Task)", task.Assignment.OrderDigest)
	}
	if !task.Assignment.AcceptedTaskHash.IsSet() || task.Assignment.AcceptedTaskHash.Hex() != strings.Repeat("ab", 32) {
		t.Fatalf("Assignment.AcceptedTaskHash = %#v, want %s", task.Assignment.AcceptedTaskHash, strings.Repeat("ab", 32))
	}
}

// TestKeeperABCIClientTerminalTaskDoesNotConflateOrderDigestWithAcceptedTaskHash
// is the terminal-task twin of the active-task assertion above.
func TestKeeperABCIClientTerminalTaskDoesNotConflateOrderDigestWithAcceptedTaskHash(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	sessionID := strings.Repeat("12", 32)
	taskBytes, _ := hex.DecodeString(taskID)
	sessionBytes, _ := hex.DecodeString(sessionID)
	server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
		var request taskv1.QueryTaskRequest
		mustUnmarshalProto(t, data, &request)
		return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Terminal{Terminal: &taskv1.TaskTerminalSummaryState{
			TaskId: request.TaskId, SessionId: sessionBytes, OrderSequence: 1, TaskHash: taskBytes,
			TerminalPhase: 8, Verdict: 1, ModelId: "hf-model", ProfileVersion: 1,
			WinnerWorker: testPointer("trueopen1worker"), SettlementHeight: 40, CompactedHeight: 50,
		}}}}, 0, ""
	})
	defer server.Close()
	task, err := NewKeeperABCIClient(server.URL).Task(context.Background(), sessionID, taskID)
	if err != nil {
		t.Fatalf("Task() error = %v", err)
	}
	if !task.Assignment.OrderDigest.IsZero() {
		t.Fatalf("terminal Assignment.OrderDigest = %x, want zero", task.Assignment.OrderDigest)
	}
	if !task.Assignment.AcceptedTaskHash.IsSet() || task.Assignment.AcceptedTaskHash.Hex() != taskID {
		t.Fatalf("terminal Assignment.AcceptedTaskHash = %#v, want %s", task.Assignment.AcceptedTaskHash, taskID)
	}
}
func TestKeeperABCIClientReadsNodeV1HubParams(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"Params" {
			t.Fatalf("unexpected ABCI path %q", path)
		}
		return &nodeHubParamsResponse{Params: nodeHubParams{
			SchemaVersion: 2,
			Epoch:         nodeEpochParams{EpochLengthBlocks: 720},
			Support:       nodeSupportParams{SupportWindowEpochs: 20},
			Service:       nodeServiceParams{ServiceUnbondingPeriodBlocks: 302_400},
		}}, 0, ""
	})
	defer server.Close()

	params, err := NewKeeperABCIClient(server.URL).Params(context.Background())
	if err != nil {
		t.Fatalf("Params() error = %v", err)
	}
	if params.ServiceUnbondingPeriodBlocks.Uint64() != 302_400 ||
		params.DailySupportWindowBlocks.Uint64() != 14_400 {
		t.Fatalf("Params() = %#v", params)
	}
}

// query() must send the caller's height verbatim. It is asserted through the
// current BuilderSet wire rather than the pre-cutover generated pair, whose
// term_id selector no longer exists upstream.
func TestKeeperABCIClientPinsSnapshotHeight(t *testing.T) {
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"BuilderSet" || height != "77" {
			t.Fatalf("query = %q height %q", path, height)
		}
		var request hubv1.QueryBuilderSetRequest
		mustUnmarshalProto(t, data, &request)
		if request.GetHeight() != 77 {
			t.Fatalf("request = %#v, want the pinned height as the sole selector", &request)
		}
		return &hubv1.QueryBuilderSetResponse{}, 0, ""
	})
	defer server.Close()

	var response hubv1.QueryBuilderSetResponse
	err := NewKeeperABCIClient(server.URL).query(context.Background(), hubQuery+"BuilderSet", 77,
		&hubv1.QueryBuilderSetRequest{Selector: &hubv1.QueryBuilderSetRequest_Height{Height: 77}}, &response)
	if err != nil {
		t.Fatalf("query() error = %v", err)
	}
}

func TestKeeperABCIClientClassifiesErrors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
			return &hubv1.QueryModelResponse{}, 22, "rpc error: code = NotFound desc = model not found"
		})
		defer server.Close()
		_, err := NewKeeperABCIClient(server.URL).CurrentModel(context.Background(), "missing/model")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("http unavailable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
		defer server.Close()
		_, err := NewKeeperABCIClient(server.URL).CurrentModel(context.Background(), "model")
		if !IsRetryable(err) {
			t.Fatalf("error = %v, want retryable", err)
		}
	})

	t.Run("malformed value", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": map[string]any{"response": map[string]any{"code": 0, "value": "%%%"}}})
		}))
		defer server.Close()
		_, err := NewKeeperABCIClient(server.URL).CurrentModel(context.Background(), "model")
		if err == nil || !strings.Contains(err.Error(), "ABCI value") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestKeeperABCIClientChainHeight(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": map[string]any{"sync_info": map[string]any{"latest_block_height": "321"}}})
	}))
	defer server.Close()
	height, err := NewKeeperABCIClient(server.URL).ChainHeight(context.Background())
	if err != nil || height != 321 {
		t.Fatalf("ChainHeight() = %d, %v", height, err)
	}
}

func TestCurrentServiceKeyUsesNodeV1Wire(t *testing.T) {
	pubkey, err := hex.DecodeString("02" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("decode fixture pubkey: %v", err)
	}
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"CurrentServiceKey" {
			t.Fatalf("ABCI path = %q", path)
		}
		if height != "500" {
			t.Fatalf("ABCI height = %q, want 500", height)
		}
		var request nodeCurrentServiceKeyRequest
		if err := unmarshalTestProto(data, &request); err != nil {
			t.Fatalf("decode Node V1 request: %v", err)
		}
		if request.ParticipantType != 1 || request.OperatorAddress != "trueopen1operator" {
			t.Fatalf("request = %#v", request)
		}
		return &nodeCurrentServiceKeyResponse{Binding: nodeCurrentServiceKeyView{
			ParticipantType:           1,
			OperatorAddress:           "trueopen1operator",
			ServiceAddress:            "trueopen1service",
			ServicePubkey:             pubkey,
			ServiceAuthorizationNonce: 3,
			CortexServiceKeyStatus:    1,
			CurrentDescriptorVersion:  7,
		}}, 0, ""
	})

	binding, err := NewKeeperABCIClient(server.URL).CurrentServiceKey(
		context.Background(), ParticipantTypeCortexNode, "trueopen1operator", 500,
	)
	if err != nil {
		t.Fatalf("CurrentServiceKey() error = %v", err)
	}
	if binding.ParticipantType != ParticipantTypeCortexNode ||
		binding.OperatorAddress != "trueopen1operator" ||
		binding.ServiceAddress != "trueopen1service" ||
		binding.ServicePubkey != hex.EncodeToString(pubkey) ||
		binding.AuthorizationNonce.Uint64() != 3 ||
		binding.Status != "ACTIVE" {
		t.Fatalf("binding = %#v", binding)
	}
}

// newCommitBoundaryServer models a node at a commit boundary, which is the state a
// freshly restarted devnet node passes through: CometBFT has already saved block
// committedHeight+1 to its block store, so /status reports it, while the
// application has only committed committedHeight, so /abci_info reports that and
// an ABCI query pinned one block ahead is refused with the SDK's own
// ErrInvalidHeight response.
func newCommitBoundaryServer(t testing.TB, committedHeight uint64, binding *hubv1.CurrentServiceKeyViewV1) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encode := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": result})
		}
		switch r.URL.Path {
		case "/status":
			encode(map[string]any{"sync_info": map[string]any{
				"latest_block_height": strconv.FormatUint(committedHeight+1, 10),
			}})
		case "/abci_info":
			encode(map[string]any{"response": map[string]any{
				"last_block_height": strconv.FormatUint(committedHeight, 10),
			}})
		case "/abci_query":
			requested := r.URL.Query().Get("height")
			if requested != "" && requested != strconv.FormatUint(committedHeight, 10) {
				// Verbatim shape of the observed devnet failure.
				encode(map[string]any{"response": map[string]any{
					"code":      26,
					"codespace": "sdk",
					"log":       "cannot query with height in the future; please provide a valid height: invalid height",
					"height":    requested,
				}})
				return
			}
			payload, err := marshalTestProto(&hubv1.QueryCurrentServiceKeyResponse{Binding: binding})
			if err != nil {
				t.Fatalf("marshal binding: %v", err)
			}
			encode(map[string]any{"response": map[string]any{
				"code":   0,
				"value":  base64.StdEncoding.EncodeToString(payload),
				"height": requested,
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func commitBoundaryBinding() *hubv1.CurrentServiceKeyViewV1 {
	return &hubv1.CurrentServiceKeyViewV1{
		ParticipantType:           sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX,
		OperatorAddress:           "trueopen1operator",
		ServiceAddress:            "trueopen1service",
		ServicePubkey:             append([]byte{0x02}, bytes.Repeat([]byte{0xab}, 32)...),
		ServiceAuthorizationNonce: 3,
		ParticipantStatus:         &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE},
		CurrentDescriptorVersion:  1,
	}
}

// This is the devnet failure that took a node down at startup: the height read
// from /status is one block ahead of what the application will answer, and the
// pinned query is rejected outright. The committed read answers at the height the
// application actually served.
func TestCommittedReadsSurviveACommitBoundaryThatRejectsTheStatusHeight(t *testing.T) {
	const committed = uint64(53140)
	server := newCommitBoundaryServer(t, committed, commitBoundaryBinding())
	client := NewKeeperABCIClient(server.URL)

	// The defect, exactly as it was written: read /status, then pin that height.
	statusHeight, err := client.ChainHeight(context.Background())
	if err != nil {
		t.Fatalf("ChainHeight() error = %v", err)
	}
	if statusHeight != committed+1 {
		t.Fatalf("ChainHeight() = %d, want the block store height %d", statusHeight, committed+1)
	}
	_, err = client.CurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator", statusHeight)
	if err == nil || !strings.Contains(err.Error(), `codespace "sdk" code 26`) ||
		!strings.Contains(err.Error(), "cannot query with height in the future") {
		t.Fatalf("pinning the /status height succeeded or failed differently: %v", err)
	}

	// The fix: ask for the latest committed state and be told which height it came
	// from. Swap CommittedCurrentServiceKey back to the two lines above and this
	// assertion fails with the same code-26 rejection.
	binding, served, err := client.CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator")
	if err != nil {
		t.Fatalf("CommittedCurrentServiceKey() error = %v", err)
	}
	if served != committed {
		t.Fatalf("served height = %d, want the application's committed height %d", served, committed)
	}
	if binding.OperatorAddress != "trueopen1operator" || binding.Status != "ACTIVE" {
		t.Fatalf("binding = %#v", binding)
	}

	committedHeight, err := client.CommittedHeight(context.Background())
	if err != nil || committedHeight != committed {
		t.Fatalf("CommittedHeight() = %d, %v, want %d", committedHeight, err, committed)
	}
}

// A node that answers at a height other than the one it was asked for is refused:
// the pinned read is what binds a decision to a height, so a mismatch cannot be
// silently accepted.
func TestPinnedQueryRefusesAResponseServedAtAnotherHeight(t *testing.T) {
	binding := commitBoundaryBinding()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload, err := marshalTestProto(&hubv1.QueryCurrentServiceKeyResponse{Binding: binding})
		if err != nil {
			t.Fatalf("marshal binding: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": map[string]any{
			"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(payload), "height": "41"},
		}})
	}))
	defer server.Close()
	_, err := NewKeeperABCIClient(server.URL).CurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator", 40)
	if err == nil || !strings.Contains(err.Error(), "queried at height 40 and answered at height 41") {
		t.Fatalf("err = %v, want a served-height mismatch refusal", err)
	}
}

func TestKeeperABCIClientHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := NewKeeperABCIClient(server.URL).CurrentModel(ctx, "model")
	if err == nil || !IsRetryable(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want retryable deadline", err)
	}
}

// abciTestCommittedHeight is the height the fake application reports as committed,
// so a committed read pins its query there.
const abciTestCommittedHeight = uint64(900)

func newABCITestServer(t testing.TB, query func(path, height string, data []byte) (proto.Message, uint32, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abci_info" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": -1,
				"result": map[string]any{"response": map[string]any{
					"last_block_height": strconv.FormatUint(abciTestCommittedHeight, 10),
				}},
			})
			return
		}
		if r.URL.Path != "/abci_query" {
			http.NotFound(w, r)
			return
		}
		quotedPath := r.URL.Query().Get("path")
		path, err := strconvUnquote(quotedPath)
		if err != nil {
			t.Fatalf("ABCI path %q: %v", quotedPath, err)
		}
		encoded := strings.TrimPrefix(r.URL.Query().Get("data"), "0x")
		data, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("ABCI data: %v", err)
		}
		message, code, log := query(path, r.URL.Query().Get("height"), data)
		var value string
		if message != nil {
			payload, err := marshalTestProto(message)
			if err != nil {
				t.Fatalf("marshal ABCI response: %v", err)
			}
			value = base64.StdEncoding.EncodeToString(payload)
		}
		// A Cosmos SDK node echoes the requested height in the ABCI response, and
		// reports "0" when the caller asked for the latest committed state.
		servedHeight := r.URL.Query().Get("height")
		if servedHeight == "" {
			servedHeight = "0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": -1,
			"result": map[string]any{"response": map[string]any{"code": code, "log": log, "value": value, "height": servedHeight}},
		})
	}))
}

func strconvUnquote(value string) (string, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", errors.New("path must be quoted")
	}
	return value[1 : len(value)-1], nil
}

func mustUnmarshalProto(t testing.TB, data []byte, message proto.Message) {
	t.Helper()
	if err := unmarshalTestProto(data, message); err != nil {
		t.Fatalf("decode protobuf: %v", err)
	}
}

func mustReadFixture(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
