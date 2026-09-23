package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	hubQuery  = "/hub.v1.Query/"
	taskQuery = "/task.v1.Query/"
)

// ChainHeight reports CometBFT's block store height (/status
// sync_info.latest_block_height). It answers liveness and lag questions only:
// "is this node moving, and how far behind is our cursor".
//
// It MUST NOT be used as a query height. CometBFT saves a block to the block
// store before the application commits it, so this value can be one ahead of the
// newest height the application can serve, and pinning it makes the SDK reject
// the query with "cannot query with height in the future" (codespace "sdk" code
// 26). Use CommittedHeight for that.
func (c *KeeperABCIClient) ChainHeight(ctx context.Context) (uint64, error) {
	var rpc cometRPCResponse
	if err := c.getRPC(ctx, "/status", nil, &rpc); err != nil {
		return 0, err
	}
	if rpc.Error != nil {
		return 0, fmt.Errorf("Keeper status RPC error %d: %s", rpc.Error.Code, rpc.Error.Message)
	}
	var result struct {
		SyncInfo struct {
			LatestBlockHeight string `json:"latest_block_height"`
		} `json:"sync_info"`
	}
	if err := json.Unmarshal(rpc.Result, &result); err != nil {
		return 0, fmt.Errorf("decode Keeper status result: %w", err)
	}
	height, err := strconv.ParseUint(result.SyncInfo.LatestBlockHeight, 10, 64)
	if err != nil || height == 0 {
		return 0, fmt.Errorf("Keeper status response missing latest block height")
	}
	return height, nil
}

// CommittedHeight reports the newest height the application itself has
// committed, which is the newest height its state can be queried at and the only
// height a caller may pin a read to. It comes from /abci_info, which the
// application answers from its own store, so it can lag the block store but can
// never lead it.
func (c *KeeperABCIClient) CommittedHeight(ctx context.Context) (uint64, error) {
	var rpc cometRPCResponse
	if err := c.getRPC(ctx, "/abci_info", nil, &rpc); err != nil {
		return 0, err
	}
	if rpc.Error != nil {
		return 0, fmt.Errorf("Keeper abci_info RPC error %d: %s", rpc.Error.Code, rpc.Error.Message)
	}
	var result struct {
		Response struct {
			LastBlockHeight string `json:"last_block_height"`
		} `json:"response"`
	}
	if err := json.Unmarshal(rpc.Result, &result); err != nil {
		return 0, fmt.Errorf("decode Keeper abci_info result: %w", err)
	}
	height, err := strconv.ParseUint(strings.TrimSpace(result.Response.LastBlockHeight), 10, 64)
	if err != nil || height == 0 {
		return 0, fmt.Errorf("Keeper abci_info response missing a committed block height")
	}
	return height, nil
}

func (c *KeeperABCIClient) Params(ctx context.Context) (ParamsSnapshot, error) {
	var response hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", 0, &hubv1.QueryHubParamsRequest{}, &response); err != nil {
		return ParamsSnapshot{}, err
	}
	params := response.Params
	if params.GetSchemaVersion() != 2 {
		return ParamsSnapshot{}, fmt.Errorf("Keeper Hub params schema version is required")
	}
	epochLength := params.GetEpoch().GetEpochLengthBlocks()
	supportWindowEpochs := uint64(params.GetSupport().GetSupportWindowEpochs())
	if epochLength == 0 || supportWindowEpochs == 0 || epochLength > ^uint64(0)/supportWindowEpochs {
		return ParamsSnapshot{}, fmt.Errorf("Keeper daily support window is invalid")
	}
	if params.GetService().GetServiceUnbondingPeriodBlocks() == 0 {
		return ParamsSnapshot{}, fmt.Errorf("Keeper service unbonding period is required")
	}
	return ParamsSnapshot{
		ServiceUnbondingPeriodBlocks: Uint64String(params.Service.ServiceUnbondingPeriodBlocks),
		DailySupportWindowBlocks:     Uint64String(epochLength * supportWindowEpochs),
	}, nil
}

func (c *KeeperABCIClient) CortexNode(ctx context.Context, operatorAddress string) (CortexNodeSnapshot, error) {
	operatorAddress = strings.TrimSpace(operatorAddress)
	request := &hubv1.QueryCortexNodeRequest{OperatorAddress: operatorAddress}
	var response hubv1.QueryCortexNodeResponse
	if err := c.query(ctx, hubQuery+"CortexNode", 0, request, &response); err != nil {
		return CortexNodeSnapshot{}, err
	}
	node := response.Node
	if node == nil {
		return CortexNodeSnapshot{}, fmt.Errorf("Keeper Cortex node response is missing its node")
	}
	if node.SchemaVersion != 1 {
		return CortexNodeSnapshot{}, fmt.Errorf("Keeper Cortex node schema version %d is unsupported", node.SchemaVersion)
	}
	var status string
	switch node.ServiceKeyStatus {
	case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE:
		status = "ACTIVE"
	case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED:
		status = "REVOKED"
	default:
		return CortexNodeSnapshot{}, fmt.Errorf("Keeper Cortex node service key status %d is unsupported", node.ServiceKeyStatus)
	}
	snapshot := CortexNodeSnapshot{
		OperatorAddress:          node.OperatorAddress,
		CurrentServiceAddress:    node.CurrentServiceAddress,
		CurrentServicePubkey:     hex.EncodeToString(node.CurrentServicePubkey),
		AuthorizationNonce:       Uint64String(node.ServiceAuthorizationNonce),
		Status:                   status,
		RegisteredHeight:         Uint64String(node.RegisteredHeight),
		UpdatedHeight:            Uint64String(node.UpdatedHeight),
		CurrentDescriptorVersion: Uint64String(node.CurrentDescriptorVersion),
	}
	if snapshot.OperatorAddress != operatorAddress {
		return CortexNodeSnapshot{}, fmt.Errorf("Keeper Cortex node response does not match query identity")
	}
	return snapshot, snapshot.Validate()
}

func (c *KeeperABCIClient) ServiceBond(ctx context.Context, operatorAddress string) (ServiceBondSnapshot, error) {
	operatorAddress = strings.TrimSpace(operatorAddress)
	request := &hubv1.QueryServiceBondRequest{OperatorAddress: operatorAddress}
	var response hubv1.QueryServiceBondResponse
	if err := c.query(ctx, hubQuery+"ServiceBond", 0, request, &response); err != nil {
		return ServiceBondSnapshot{}, err
	}
	if response.Bond == nil {
		return ServiceBondSnapshot{}, fmt.Errorf("Keeper service bond response is missing its bond")
	}
	var status string
	switch response.Bond.Status {
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_REGISTERED:
		status = "REGISTERED"
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_ACTIVE:
		status = "ACTIVE"
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_JAILED:
		status = "JAILED"
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_UNBONDING:
		status = "UNBONDING"
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_EXITED:
		status = "EXITED"
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_TOMBSTONED:
		status = "TOMBSTONED"
	default:
		return ServiceBondSnapshot{}, fmt.Errorf("Keeper service bond status %d is unsupported", response.Bond.Status)
	}
	snapshot := ServiceBondSnapshot{
		OperatorAddress:       response.Bond.OperatorAddress,
		ActiveBond:            Uint64String(response.Bond.ActiveBond),
		ReservedLiability:     Uint64String(response.Bond.ReservedLiability),
		PendingUnbondingTotal: Uint64String(response.Bond.PendingUnbondingTotal),
		BondVersion:           Uint64String(response.Bond.BondVersion),
		EffectiveBondEpoch:    Uint64String(response.Bond.EffectiveBondEpoch),
		Status:                status,
		NodeJailCount:         Uint64String(response.Bond.JailCount),
	}
	if snapshot.OperatorAddress != operatorAddress {
		return ServiceBondSnapshot{}, fmt.Errorf("Keeper service bond response does not match query identity")
	}
	return snapshot, snapshot.Validate()
}

// CurrentServiceKey reads the current service key. snapshotHeight 0 reads the
// latest committed state; a non-zero height pins the read and MUST have come from
// CommittedHeight. Callers that bind a decision to the height the key was read at
// must use CommittedCurrentServiceKey instead of pairing this with a height of
// their own.
func (c *KeeperABCIClient) CurrentServiceKey(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (ServiceKeySnapshot, error) {
	binding, _, err := c.currentServiceKeyAt(ctx, participantType, operatorAddress, snapshotHeight)
	return binding, err
}

// CommittedCurrentServiceKey reads the current service key from the latest
// committed state and reports the height it was served at. The height is
// queryable by construction, and every check the caller derives from it (expiry,
// revocation) is bound to the same read that produced the key material.
func (c *KeeperABCIClient) CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (ServiceKeySnapshot, uint64, error) {
	committed, err := c.CommittedHeight(ctx)
	if err != nil {
		return ServiceKeySnapshot{}, 0, err
	}
	return c.currentServiceKeyAt(ctx, participantType, operatorAddress, committed)
}

func (c *KeeperABCIClient) currentServiceKeyAt(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (ServiceKeySnapshot, uint64, error) {
	wireParticipant, err := encodeParticipantType(participantType)
	if err != nil {
		return ServiceKeySnapshot{}, 0, err
	}
	operatorAddress = strings.TrimSpace(operatorAddress)
	if wireParticipant == sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER && snapshotHeight == 0 {
		snapshotHeight, err = c.CommittedHeight(ctx)
		if err != nil {
			return ServiceKeySnapshot{}, 0, err
		}
	}
	request := &hubv1.QueryCurrentServiceKeyRequest{
		ParticipantType: wireParticipant,
		OperatorAddress: operatorAddress,
	}
	var response hubv1.QueryCurrentServiceKeyResponse
	served, err := c.queryServed(ctx, hubQuery+"CurrentServiceKey", snapshotHeight, request, &response)
	if err != nil {
		return ServiceKeySnapshot{}, 0, err
	}
	binding, err := serviceKeySnapshotFromWire(response.Binding)
	if err != nil {
		return ServiceKeySnapshot{}, 0, err
	}
	if binding.ParticipantType != strings.TrimSpace(participantType) || binding.OperatorAddress != operatorAddress {
		return ServiceKeySnapshot{}, 0, fmt.Errorf("Keeper current service key response does not match query identity")
	}
	if err := binding.Validate(); err != nil {
		return ServiceKeySnapshot{}, 0, err
	}
	return binding, served, nil
}

func serviceKeySnapshotFromWire(binding *hubv1.CurrentServiceKeyViewV1) (ServiceKeySnapshot, error) {
	if binding == nil {
		return ServiceKeySnapshot{}, fmt.Errorf("Keeper current service key binding is missing")
	}
	participant, err := decodeParticipantType(binding.ParticipantType)
	if err != nil {
		return ServiceKeySnapshot{}, err
	}
	var status string
	switch binding.ParticipantType {
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX:
		if _, ok := binding.ParticipantStatus.(*hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus); !ok {
			return ServiceKeySnapshot{}, fmt.Errorf("Keeper current Cortex service key requires its service key status")
		}
		switch binding.GetCortexServiceKeyStatus() {
		case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE:
			status = "ACTIVE"
		case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED:
			status = "REVOKED"
		default:
			return ServiceKeySnapshot{}, fmt.Errorf("Keeper current Cortex service key status %d is unsupported", binding.GetCortexServiceKeyStatus())
		}
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		if _, ok := binding.ParticipantStatus.(*hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus); !ok {
			return ServiceKeySnapshot{}, fmt.Errorf("Keeper current Builder service key requires its service key status")
		}
		switch binding.GetBuilderServiceKeyStatus() {
		case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE:
			status = "ACTIVE"
		case hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED:
			status = "REVOKED"
		default:
			return ServiceKeySnapshot{}, fmt.Errorf("Keeper current Builder service key status %d is unsupported", binding.GetBuilderServiceKeyStatus())
		}
	}
	return ServiceKeySnapshot{
		ParticipantType:          participant,
		OperatorAddress:          binding.OperatorAddress,
		ServiceAddress:           binding.ServiceAddress,
		ServicePubkey:            hex.EncodeToString(binding.ServicePubkey),
		AuthorizationNonce:       Uint64String(binding.ServiceAuthorizationNonce),
		CurrentDescriptorVersion: Uint64String(binding.CurrentDescriptorVersion),
		Status:                   status,
	}, nil
}

func (c *KeeperABCIClient) Task(ctx context.Context, sessionID, taskID string) (TaskSnapshot, error) {
	taskHash, err := decodeTaskIDHash32(taskID)
	if err != nil {
		return TaskSnapshot{}, err
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return TaskSnapshot{}, err
	}
	var response taskv1.QueryTaskResponse
	if err := c.query(ctx, taskQuery+"Task", height, &taskv1.QueryTaskRequest{TaskId: taskHash}, &response); err != nil {
		return TaskSnapshot{}, err
	}
	snapshot, err := snapshotFromWireTask(strings.TrimSpace(sessionID), taskHash, &response)
	if err != nil {
		return TaskSnapshot{}, err
	}
	if response.GetTask().GetActive().GetCore().GetReceiptStatus() == taskv1.ReceiptStatus_RECEIPT_STATUS_RECEIPT_ACCEPTED {
		var receipt taskv1.QueryInferReceiptResponse
		if err := c.query(ctx, taskQuery+"InferReceipt", height, &taskv1.QueryInferReceiptRequest{TaskId: taskHash}, &receipt); err != nil {
			return TaskSnapshot{}, err
		}
		if receipt.Receipt == nil || !bytes.Equal(receipt.Receipt.TaskId, taskHash) ||
			len(receipt.Receipt.InferReceiptHash) != 32 || len(receipt.Receipt.OutputHash) != 32 ||
			receipt.Receipt.ReceiptHeight == 0 || receipt.Receipt.ReceiptHeight > height ||
			receipt.Receipt.OutputLeafCount == 0 || receipt.Receipt.OutputSizeBytes == 0 && receipt.Receipt.OutputLeafCount != 1 {
			return TaskSnapshot{}, fmt.Errorf("Keeper InferReceipt response is invalid")
		}
		snapshot.InferReceipt = InferReceiptSnapshot{
			SessionID: snapshot.Assignment.SessionID, TaskID: taskID, WinnerWorker: receipt.Receipt.WinnerWorker,
			InferReceiptHash: HexHash(receipt.Receipt.InferReceiptHash), OutputHash: HexHash(receipt.Receipt.OutputHash),
			// output_size_bytes lands in its own field. It used to be written into
			// TokenCount and WorkUnit as well; the frozen InferReceiptState deleted
			// both, so filling them asserted a fact this response never carried.
			OutputSizeBytes:     NewUint64String(receipt.Receipt.OutputSizeBytes),
			GeneratedTokenCount: NewUint64String(receipt.Receipt.GeneratedTokenCount),
			OutputLeafCount:     NewUint64String(receipt.Receipt.OutputLeafCount),
			ReceiptMode:         "CURRENT_V2", ReceiptHeight: NewUint64String(receipt.Receipt.ReceiptHeight),
		}
	}
	return snapshot, snapshot.Validate()
}

func (c *KeeperABCIClient) CurrentModel(ctx context.Context, modelID string) (CurrentModelSnapshot, error) {
	return c.currentModelAt(ctx, modelID, 0)
}

func (c *KeeperABCIClient) currentModelAt(ctx context.Context, modelID string, height uint64) (CurrentModelSnapshot, error) {
	var response hubv1.QueryModelResponse
	var snapshot struct {
		Model CurrentModelSnapshot `json:"model"`
	}
	request := &hubv1.QueryModelRequest{ModelId: strings.TrimSpace(modelID)}
	if err := c.querySnapshot(ctx, hubQuery+"Model", height, request, &response, &snapshot); err != nil {
		return CurrentModelSnapshot{}, err
	}
	normalizeCurrentModelStatus(&snapshot.Model)
	return snapshot.Model, snapshot.Model.Validate()
}

func (c *KeeperABCIClient) CurrentModelProfile(ctx context.Context, modelID, profileVersion string) (CurrentModelProfileSnapshot, error) {
	version, err := canonicalProfileVersionUint32(profileVersion)
	if err != nil {
		return CurrentModelProfileSnapshot{}, err
	}
	committedHeight, err := c.CommittedHeight(ctx)
	if err != nil {
		return CurrentModelProfileSnapshot{}, err
	}
	return c.currentModelProfileAt(ctx, strings.TrimSpace(modelID), version, committedHeight)
}

func (c *KeeperABCIClient) currentModelProfileAt(ctx context.Context, modelID string, version uint32, height uint64) (CurrentModelProfileSnapshot, error) {
	model, err := c.currentModelAt(ctx, modelID, height)
	if err != nil {
		return CurrentModelProfileSnapshot{}, err
	}
	var response hubv1.QueryProfileResponse
	request := &hubv1.QueryProfileRequest{ModelId: modelID, ProfileVersion: version}
	if err := c.query(ctx, hubQuery+"Profile", height, request, &response); err != nil {
		return CurrentModelProfileSnapshot{}, err
	}
	snapshot := CurrentModelProfileSnapshot{Model: model, Profile: currentProfileSnapshotFromWire(response.Profile)}
	return snapshot, snapshot.Validate()
}

// normalizeCurrentModelStatus preserves the REST-era bare status contract at
// the typed projection boundary. It intentionally touches only enum-backed
// status fields: model IDs and other response strings may legitimately begin
// with the same text as a protobuf enum name.
func normalizeCurrentModelStatus(snapshot *CurrentModelSnapshot) {
	snapshot.Status = strings.TrimPrefix(snapshot.Status, "MODEL_PROFILE_STATUS_")
	snapshot.StatusSource = strings.TrimPrefix(snapshot.StatusSource, "MODEL_STATUS_SOURCE_")
}

func (c *KeeperABCIClient) ModelCapability(ctx context.Context, operatorAddress, modelID, profileVersion string) (ModelCapabilitySnapshot, error) {
	version, err := canonicalProfileVersionUint32(profileVersion)
	if err != nil {
		return ModelCapabilitySnapshot{}, err
	}
	return c.modelCapabilityAt(ctx, strings.TrimSpace(operatorAddress), strings.TrimSpace(modelID), version, 0)
}

func (c *KeeperABCIClient) modelCapabilityAt(ctx context.Context, operatorAddress, modelID string, version uint32, height uint64) (ModelCapabilitySnapshot, error) {
	var response hubv1.QueryProfileCapabilityResponse
	request := &hubv1.QueryProfileCapabilityRequest{OperatorAddress: operatorAddress, ModelId: modelID, ProfileVersion: version}
	if err := c.query(ctx, hubQuery+"ProfileCapability", height, request, &response); err != nil {
		return ModelCapabilitySnapshot{}, err
	}
	capability := ModelCapabilitySnapshot{
		OperatorAddress: response.Capability.OperatorAddress, ModelID: response.Capability.ModelId,
		ProfileVersion:      NewProfileVersion(response.Capability.ProfileVersion),
		InferenceCapability: response.Capability.InferenceCapability, VerificationCapability: response.Capability.VerificationCapability,
		CapabilityVersion: NewUint64String(response.Capability.CapabilityVersion),
	}
	return capability, capability.Validate()
}

func (c *KeeperABCIClient) ModelSupport(ctx context.Context, operatorAddress, modelID, profileVersion string) (ModelSupportSnapshot, error) {
	version, err := canonicalProfileVersionUint32(profileVersion)
	if err != nil {
		return ModelSupportSnapshot{}, err
	}
	return c.modelSupportAt(ctx, strings.TrimSpace(operatorAddress), strings.TrimSpace(modelID), version, 0)
}

func (c *KeeperABCIClient) modelSupportAt(ctx context.Context, operatorAddress, modelID string, version uint32, height uint64) (ModelSupportSnapshot, error) {
	var response hubv1.QueryModelSupportResponse
	request := &hubv1.QueryModelSupportRequest{OperatorAddress: operatorAddress, ModelId: modelID, ProfileVersion: version}
	if err := c.query(ctx, hubQuery+"ModelSupport", height, request, &response); err != nil {
		return ModelSupportSnapshot{}, err
	}
	state := response.Support
	if state == nil {
		return ModelSupportSnapshot{}, fmt.Errorf("Keeper model support response is missing its support")
	}
	if state.OperatorAddress != operatorAddress || state.ModelId != modelID || state.ProfileVersion != version {
		return ModelSupportSnapshot{}, fmt.Errorf("Keeper model support response does not match query identity")
	}
	support := ModelSupportSnapshot{
		OperatorAddress: state.OperatorAddress, ModelID: state.ModelId, ProfileVersion: NewProfileVersion(state.ProfileVersion),
		DeclaredSupport: state.DeclaredSupport, SupportActive: state.SupportActive, ActivationKind: int32(state.ActivationKind),
		FirstActivationDuty: int32(state.FirstActivationDuty), FirstSupportTaskID: ProtoBytes32(state.FirstSupportTaskId),
		FirstSupportOrderValue: NewUint64String(state.FirstSupportOrderValue),
		SupportFreshUntilEpoch: NewUint64String(state.SupportFreshUntilEpoch), LastRefreshTaskID: ProtoBytes32(state.LastRefreshTaskId),
		LastRefreshHeight: NewUint64String(state.LastRefreshHeight), ActiveSupportStakeSnapshot: NewUint64String(state.ActiveSupportStakeSnapshot),
		EligibleSupportStakeSnapshot: NewUint64String(state.EligibleSupportStakeSnapshot), SupportVersion: NewUint64String(state.SupportVersion),
	}
	switch source := state.P30Source.(type) {
	case *hubv1.ModelSupportState_P30CutoffEpoch:
		epoch := NewUint64String(source.P30CutoffEpoch)
		support.P30CutoffEpoch = &epoch
	case *hubv1.ModelSupportState_P30Bootstrap:
		bootstrap := source.P30Bootstrap
		support.P30Bootstrap = &bootstrap
	}
	return support, support.Validate()
}

type CommittedModelSupportScope struct {
	Height              uint64
	EpochLengthBlocks   uint64
	SupportWindowEpochs uint32
	Profile             CurrentModelProfileSnapshot
	Capability          ModelCapabilitySnapshot
	Support             ModelSupportSnapshot
}

func (c *KeeperABCIClient) CommittedModelSupportScope(ctx context.Context, operatorAddress, modelID, profileVersion string) (CommittedModelSupportScope, error) {
	version, err := canonicalProfileVersionUint32(profileVersion)
	if err != nil {
		return CommittedModelSupportScope{}, err
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return CommittedModelSupportScope{}, err
	}
	operatorAddress, modelID = strings.TrimSpace(operatorAddress), strings.TrimSpace(modelID)
	profile, err := c.currentModelProfileAt(ctx, modelID, version, height)
	if err != nil {
		return CommittedModelSupportScope{}, err
	}
	capability, err := c.modelCapabilityAt(ctx, operatorAddress, modelID, version, height)
	if err != nil {
		return CommittedModelSupportScope{}, err
	}
	support, err := c.modelSupportAt(ctx, operatorAddress, modelID, version, height)
	if err != nil {
		return CommittedModelSupportScope{}, err
	}
	var paramsResponse hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", height, &hubv1.QueryHubParamsRequest{}, &paramsResponse); err != nil {
		return CommittedModelSupportScope{}, err
	}
	epochLength := paramsResponse.Params.Epoch.EpochLengthBlocks
	window := paramsResponse.Params.Support.SupportWindowEpochs
	if epochLength == 0 || window == 0 {
		return CommittedModelSupportScope{}, fmt.Errorf("Keeper support epoch parameters are required")
	}
	return CommittedModelSupportScope{
		Height: height, EpochLengthBlocks: epochLength, SupportWindowEpochs: window,
		Profile: profile, Capability: capability, Support: support,
	}, nil
}

func (c *KeeperABCIClient) SupportSigningScopeAt(ctx context.Context, height uint64) (epoch, expiryHeight uint64, err error) {
	if height == 0 {
		return 0, 0, fmt.Errorf("support signing query height is required")
	}
	var response hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", height, &hubv1.QueryHubParamsRequest{}, &response); err != nil {
		return 0, 0, err
	}
	epochLength := response.Params.Epoch.EpochLengthBlocks
	maxExpiry := response.Params.Service.MaxServiceMaterialExpiryBlocks
	if epochLength == 0 || maxExpiry == 0 {
		return 0, 0, fmt.Errorf("Keeper support signing parameters are required")
	}
	epoch = height / epochLength
	if epoch == ^uint64(0) || epoch+1 > ^uint64(0)/epochLength {
		return 0, 0, fmt.Errorf("support epoch end height overflows")
	}
	epochEnd := (epoch+1)*epochLength - 1
	expiryHeight = epochEnd
	if height <= ^uint64(0)-maxExpiry && height+maxExpiry < expiryHeight {
		expiryHeight = height + maxExpiry
	}
	if expiryHeight < height {
		return 0, 0, fmt.Errorf("support signing window is closed")
	}
	return epoch, expiryHeight, nil
}

func (c *KeeperABCIClient) Settlement(ctx context.Context, sessionID, taskID string) (TaskSettlementSnapshot, error) {
	_, key, err := canonicalTaskKey(taskID)
	if err != nil {
		return TaskSettlementSnapshot{}, err
	}
	var response taskv1.QuerySettlementResponse
	if err := c.query(ctx, taskQuery+"Settlement", 0, &taskv1.QuerySettlementRequest{TaskId: key}, &response); err != nil {
		return TaskSettlementSnapshot{}, err
	}
	row := response.GetSettlement()
	if row == nil || !bytes.Equal(row.TaskId, key) {
		return TaskSettlementSnapshot{}, fmt.Errorf("Keeper settlement task identity mismatch")
	}
	snapshot := TaskSettlementSnapshot{SessionID: sessionID, TaskID: taskID, SettlementID: hex.EncodeToString(row.SettlementId), Verdict: strings.TrimPrefix(row.Verdict.String(), "TASK_VERDICT_"), SettlementHeight: NewUint64String(row.SettlementHeight), TaskFinalityHeight: NewUint64String(row.TaskFinalityHeight)}
	return snapshot, snapshot.Validate()
}

func (c *KeeperABCIClient) VerificationRound(ctx context.Context, taskID string, verifyRound uint32) (*taskv1.VerificationRoundState, error) {
	_, key, err := canonicalTaskKey(taskID)
	if err != nil {
		return nil, err
	}
	if verifyRound < 1 || verifyRound > 2 {
		return nil, fmt.Errorf("verification round must be 1 or 2")
	}
	var response taskv1.QueryVerificationRoundResponse
	if err := c.query(ctx, taskQuery+"VerificationRound", 0, &taskv1.QueryVerificationRoundRequest{TaskId: key, VerifyRound: verifyRound}, &response); err != nil {
		return nil, err
	}
	row := response.GetRound()
	if row == nil || !bytes.Equal(row.TaskId, key) || row.VerifyRound != verifyRound {
		return nil, fmt.Errorf("Keeper verification round identity mismatch")
	}
	return row, nil
}

func canonicalProfileVersionUint32(value string) (uint32, error) {
	trimmed := strings.TrimSpace(value)
	parsed, err := parseProfileVersion(trimmed, false)
	if err != nil || value != trimmed {
		return 0, fmt.Errorf("Keeper profile_version must be a canonical non-zero uint32")
	}
	return parsed, nil
}

type retryableError struct{ err error }

func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err: err}
}
func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }
func (retryableError) Retryable() bool { return true }
func IsRetryable(err error) bool {
	var marker interface{ Retryable() bool }
	return errors.As(err, &marker) && marker.Retryable()
}
