package txclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// KeeperConfirmationReader names exactly the Keeper reads a confirmation
// performs. FullResultReveal is deliberately not among them: §10.9a removed the
// Msg that wrote FullResultRevealState, so no Cortex-submitted transaction can
// be confirmed against it.
type KeeperConfirmationReader interface {
	Task(context.Context, string, string) (chainclient.TaskSnapshot, error)
	ModelCapability(context.Context, string, string) (chainclient.ModelCapabilitySnapshot, error)
	ModelSupport(context.Context, string, string) (chainclient.ModelSupportSnapshot, error)
	Settlement(context.Context, string, string) (chainclient.TaskSettlementSnapshot, error)
}

type keeperConfirmer struct {
	reader KeeperConfirmationReader
}

type currentModelProfileConfirmationReader interface {
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
}

func NewKeeperConfirmer(reader KeeperConfirmationReader) Confirmer {
	return keeperConfirmer{reader: reader}
}

func (c keeperConfirmer) Confirm(ctx context.Context, req Request, included InclusionResult) (bool, error) {
	if c.reader == nil {
		return false, fmt.Errorf("Keeper confirmation reader is required")
	}
	if included.Code != CodeOK || included.Height == 0 {
		return false, fmt.Errorf("successful transaction inclusion is required")
	}
	if err := ValidateMessagePayload(req.Kind, req.Payload); err != nil {
		return false, err
	}

	switch req.Kind {
	case MsgRegisterModelProfile:
		var msg RegisterModelProfileMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		reader, ok := c.reader.(currentModelProfileConfirmationReader)
		if !ok {
			return false, fmt.Errorf("current Keeper model profile confirmation reader is required")
		}
		state, err := reader.CurrentModelProfile(ctx, string(msg.Profile.ModelID), strconv.FormatUint(uint64(msg.Profile.ProfileVersion), 10))
		if pendingKeeperState(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// ProfileState retains denomless amounts; successful transaction inclusion
		// establishes the coin denomination accepted by the chain.
		expected := msg.Profile
		expected.MinStake.Denom, expected.RegistrationFee.Denom = "", ""
		matches := state.Model.ModelID == string(msg.Profile.ModelID) && state.Profile.ModelID == string(msg.Profile.ModelID) &&
			state.Model.ProposerAddress == msg.ProposerAddress && state.Profile.ProposerAddress == msg.ProposerAddress &&
			state.Profile.CreatedHeight.Uint64() > 0 && state.Profile.CreatedHeight.Uint64() <= included.Height &&
			reflect.DeepEqual(ProjectionFromChainState(state.Model, state.Profile), expected)
		return matches, nil

	case MsgDeclareModelSupport:
		var msg DeclareModelSupportMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		state, err := c.reader.ModelCapability(ctx, msg.OperatorAddress, string(msg.ModelID))
		if pendingKeeperState(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !capabilityMatchesDeclaration(state, msg) {
			return false, nil
		}
		support, err := c.reader.ModelSupport(ctx, msg.OperatorAddress, string(msg.ModelID))
		if pendingKeeperState(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return supportMatchesDeclaration(support, msg), nil

	case MsgBatchConfirmModelSupport:
		var msg BatchConfirmModelSupportMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		for _, item := range msg.Confirmations {
			for _, model := range item.SupportedModels {
				state, err := c.reader.ModelSupport(ctx, item.OperatorAddress, string(model))
				if pendingKeeperState(err) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				if !state.DeclaredSupport || state.LastRefreshHeight.Uint64() < included.Height || state.OperatorAddress != item.OperatorAddress || state.ModelID != string(model) {
					return false, nil
				}
			}
		}
		return true, nil

	case MsgSubmitInferReceipt:
		var msg SubmitInferReceiptMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		taskID := msg.Receipt.TaskID.Hex()
		state, err := c.reader.Task(ctx, req.SessionID, taskID)
		if pendingKeeperState(err) {
			return false, nil
		}
		// The frozen receipt wire carries no canonical output package hash and no
		// session id, so confirmation asserts exactly the facts it does carry.
		return state.Assignment.SessionID == req.SessionID && state.Assignment.TaskID == taskID &&
			state.Assignment.SelectedWorker == msg.Receipt.WorkerOperatorAddress &&
			state.InferReceipt.OutputHash.String() == msg.Receipt.OutputHash.Hex(), err

	case MsgSubmitVerifyCommit, MsgSubmitVerifyResult:
		// The frozen Keeper registers no public Query RPC for CommitState or
		// ResultReceiptState. A code-0 DeliverTx inclusion is therefore the
		// strongest externally observable proof.
		return true, nil

	case MsgSettleTask:
		var msg SettleTaskMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		taskID := msg.TaskID.Hex()
		reader, ok := c.reader.(chainclient.SettlementContextReader)
		if !ok {
			return false, fmt.Errorf("registered Task settlement confirmation reader is required")
		}
		state, err := reader.SettlementContext(ctx, taskID)
		if pendingKeeperState(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Successful inclusion plus a committed terminal Task is observable even
		// after QuerySettlement was removed. A NOOP replay may retain the original
		// settlement height, so freshness applies to the query, not the mutation.
		return req.TaskID == taskID && state.TaskID == taskID &&
			(req.SessionID == "" || state.SessionID == req.SessionID) &&
			state.ObservedHeight >= included.Height && state.Terminal(), nil

	case MsgSweepDeadline:
		var msg SweepDeadlineMessage
		if err := json.Unmarshal(req.Payload, &msg); err != nil {
			return false, err
		}
		if msg.Locator.Task == nil && msg.Locator.TaskRound == nil {
			return false, fmt.Errorf("sweep deadline locator must set exactly one member")
		}
		var taskID string
		if msg.Locator.Task != nil {
			taskID = msg.Locator.Task.TaskID.Hex()
		} else {
			taskID = msg.Locator.TaskRound.TaskID.Hex()
		}
		state, err := c.reader.Task(ctx, req.SessionID, taskID)
		if pendingKeeperState(err) {
			return false, nil
		}
		// MsgSweepDeadlineResponse counts visited work rather than one named
		// mutation, so the observable proof is that the swept task's own state
		// moved at or after the inclusion height.
		return state.Assignment.SessionID == req.SessionID && state.Assignment.TaskID == taskID &&
			state.UpdatedHeight.Uint64() >= included.Height, err

	default:
		return false, fmt.Errorf("unsupported Keeper confirmation for %s", req.Kind)
	}
}

// ProjectionFromChainState rebuilds the registered projection. The source
// reference is split on chain: provider and repo_id live on ModelState, the
// rest on ProfileState.
func ProjectionFromChainState(model chainclient.CurrentModelSnapshot, state chainclient.CurrentProfileSnapshot) ModelProfileProjectionMessage {
	return ModelProfileProjectionMessage{
		Source: SourceRefMessage{
			Provider: model.Provider, RepoID: model.RepoID, SourceURI: state.Source.SourceURI,
			Revision: state.Source.Revision, ResolverVersion: state.Source.ResolverVersion, RepoType: state.Source.RepoType,
		},
		ToolCallParser:  ParserRefMessage{Name: state.ToolCallParser.Name, Version: ProtoUint32(state.ToolCallParser.Version)},
		ReasoningParser: ParserRefMessage{Name: state.ReasoningParser.Name, Version: ProtoUint32(state.ReasoningParser.Version)},
		ModelID:         ProtoBytes32(state.ModelID), ProfileVersion: ProtoUint32(state.ProfileVersion.Uint32()), ManifestHash: ProtoBytes32(state.ManifestHash.Hex()),
		TokenizerHash: ProtoBytes32(state.TokenizerHash.Hex()), RuntimeClass: state.RuntimeClass, RequiredTopK: ProtoUint32(state.RequiredTopK),
		TaskTypes: append([]string(nil), state.TaskTypes...), GenerationType: state.GenerationType, ResourceTier: ProtoUint32(state.ResourceTier),
		MinStake: CoinMessage{Amount: ProtoUint64(state.MinStake.Uint64())}, ChallengeOpenWindowBlocks: ProtoUint64(state.ChallengeOpenWindowBlocks.Uint64()),
		VerificationProfile: VerificationProfileMessage{
			VerificationProfileID: ProtoUint32(state.VerificationProfile.VerificationProfileID), JudgmentFunctionVersion: state.VerificationProfile.JudgmentFunctionVersion,
			VerificationMode: state.VerificationProfile.VerificationMode, TokenScope: state.VerificationProfile.TokenScope,
			IncludeGeneratedSpecialTokens: state.VerificationProfile.IncludeGeneratedSpecialTokens, IncludePromptTokens: state.VerificationProfile.IncludePromptTokens,
			IncludePaddingTokens: state.VerificationProfile.IncludePaddingTokens, RequireOutputTokenIDs: state.VerificationProfile.RequireOutputTokenIDs,
			RequireFinishReason: state.VerificationProfile.RequireFinishReason,
			Metrics: MetricSpecMessage{
				CompareLogprobDiff: state.VerificationProfile.Metrics.CompareLogprobDiff, CompareRankDelta: state.VerificationProfile.Metrics.CompareRankDelta,
				CompareTopKJaccard: state.VerificationProfile.Metrics.CompareTopKJaccard, CompareUnionJS: state.VerificationProfile.Metrics.CompareUnionJS,
				ComparedTopK: ProtoUint32(state.VerificationProfile.Metrics.ComparedTopK), NumericScale: state.VerificationProfile.Metrics.NumericScale,
			},
			CanonicalEncodingVersion: state.VerificationProfile.CanonicalEncodingVersion, EvidenceSchemaHash: ProtoBytes32(state.VerificationProfile.EvidenceSchemaHash.Hex()),
			MetricAggregateProofVersion: state.VerificationProfile.MetricAggregateProofVersion,
			EvidenceSchema:              currentEvidenceSchemaFromState(state.VerificationProfile.EvidenceSchema),
		},
		VerificationThresholds: currentVerificationThresholdsFromState(state.VerificationThresholds),
		BatchVerification: BatchVerificationMessage{
			Enabled: state.BatchVerification.Enabled, MinSampleCount: ProtoUint32(state.BatchVerification.MinSampleCount), MinValidSampleCount: ProtoUint32(state.BatchVerification.MinValidSampleCount),
			PassMinSamplePassRatioBPS: ProtoUint32(state.BatchVerification.PassMinSamplePassRatioBPS), RejectMinSampleRejectRatioBPS: ProtoUint32(state.BatchVerification.RejectMinSampleRejectRatioBPS),
		},
		PricingProfile: PricingProfileMessage{
			InitialOutputPrice: ProtoUint64(state.PricingProfile.InitialOutputPrice.Uint64()), VerifyRatioBPS: ProtoUint32(state.PricingProfile.VerifyRatioBPS), MinOrderValue: ProtoUint64(state.PricingProfile.MinOrderValue.Uint64()),
		},
		TimeoutBootstrapProfile: TimeoutBootstrapProfileMessage{
			InferTimeoutBootstrapBlocks: ProtoUint32(state.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks), VerifyTimeoutBootstrapBlocks: ProtoUint32(state.TimeoutBootstrapProfile.VerifyTimeoutBootstrapBlocks),
			CommitTimeoutBootstrapBlocks: ProtoUint32(state.TimeoutBootstrapProfile.CommitTimeoutBootstrapBlocks), BootstrapValidUntilEpoch: ProtoUint64(state.TimeoutBootstrapProfile.BootstrapValidUntilEpoch.Uint64()),
		},
		SchemaHash: ProtoBytes32(state.SchemaHash.Hex()), PreviousProfileVersion: ProtoUint32(state.PreviousProfileVersion.Uint32()),
		RegistrationFee: CoinMessage{Amount: ProtoUint64(state.RegistrationFeePaid.Uint64())},
	}
}

func currentEvidenceSchemaFromState(state chainclient.CurrentEvidenceSchemaSnapshot) EvidenceSchemaMessage {
	requirements := make([]InferEvidenceRequirementMessage, len(state.RequiredInferEvidence))
	for index, requirement := range state.RequiredInferEvidence {
		requirements[index] = InferEvidenceRequirementMessage{
			EvidenceKind:            evidenceKindName(requirement.EvidenceKind),
			CommitmentSchemaVersion: ProtoUint32(requirement.CommitmentSchemaVersion),
			MaxEncodedSizeBytes:     ProtoUint64(requirement.MaxEncodedSizeBytes.Uint64()),
		}
	}
	return EvidenceSchemaMessage{SchemaVersion: ProtoUint32(state.SchemaVersion), RequiredInferEvidence: requirements}
}

func evidenceKindName(value int32) string {
	switch value {
	case 1:
		return "EVIDENCE_KIND_WORKER_VALUE_OPENING"
	case 2:
		return "EVIDENCE_KIND_VERIFIER_VALUE_OPENING"
	case 3:
		return "EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING"
	case 4:
		return "EVIDENCE_KIND_WORKER_TOKEN_OPENING"
	default:
		return ""
	}
}

func currentVerificationThresholdsFromState(state chainclient.CurrentVerificationThresholdsSnapshot) VerificationThresholdsMessage {
	return VerificationThresholdsMessage{
		PassMinFiniteCount: ProtoUint32(state.PassMinFiniteCount), PassMaxMissingComparedCount: ProtoUint32(state.PassMaxMissingComparedCount),
		PassMeanAbsLogprobDiffMax: ProtoUint32(state.PassMeanAbsLogprobDiffMax), PassAbsLogprobDiffP95Max: ProtoUint32(state.PassAbsLogprobDiffP95Max),
		PassAbsLogprobDiffP99Max: ProtoUint32(state.PassAbsLogprobDiffP99Max), PassRankDeltaNonzeroRateMax: ProtoUint32(state.PassRankDeltaNonzeroRateMax),
		PassTopKJaccardMeanMin: ProtoUint32(state.PassTopKJaccardMeanMin), PassUnionJSP99Max: ProtoUint32(state.PassUnionJSP99Max),
		RejectMeanAbsLogprobDiffMin: ProtoUint32(state.RejectMeanAbsLogprobDiffMin), RejectAbsLogprobDiffP95Min: ProtoUint32(state.RejectAbsLogprobDiffP95Min),
		RejectAbsLogprobDiffP99Min: ProtoUint32(state.RejectAbsLogprobDiffP99Min), RejectRankDeltaNonzeroRateMin: ProtoUint32(state.RejectRankDeltaNonzeroRateMin),
		RejectTopKJaccardMeanMax: ProtoUint32(state.RejectTopKJaccardMeanMax), RejectUnionJSP99Min: ProtoUint32(state.RejectUnionJSP99Min),
	}
}

func capabilityMatchesDeclaration(state chainclient.ModelCapabilitySnapshot, msg DeclareModelSupportMessage) bool {
	return state.OperatorAddress == msg.OperatorAddress &&
		state.ModelID == string(msg.ModelID) &&
		state.InferenceCapability == msg.InferenceCapability &&
		state.VerificationCapability == msg.VerificationCapability
}

func supportMatchesDeclaration(state chainclient.ModelSupportSnapshot, msg DeclareModelSupportMessage) bool {
	return state.OperatorAddress == msg.OperatorAddress &&
		state.ModelID == string(msg.ModelID) &&
		state.DeclaredSupport
}

func pendingKeeperState(err error) bool {
	return errors.Is(err, chainclient.ErrNotFound)
}
