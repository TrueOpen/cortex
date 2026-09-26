package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
)

type KeeperHandraiseEligibilityConfig struct {
	ChainStatus         ChainStatusReader
	Keeper              KeeperHandraiseReader
	Model               modelservice.Client
	ChainID             string
	OperatorAddress     string
	ModelServiceID      string
	VerifyDeadlineDelta uint64
	SelfRescueGasBudget uint64
}

type KeeperHandraiseReader interface {
	KeeperIdentityReader
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
}

type committedModelSupportScopeReader interface {
	CommittedModelSupportScope(context.Context, string, string, string) (chainclient.CommittedModelSupportScope, error)
}

type keeperHandraiseEligibility struct {
	cfg KeeperHandraiseEligibilityConfig
}

func NewKeeperHandraiseEligibility(cfg KeeperHandraiseEligibilityConfig) HandraiseEligibility {
	if cfg.VerifyDeadlineDelta == 0 {
		cfg.VerifyDeadlineDelta = 40
	}
	return keeperHandraiseEligibility{cfg: cfg}
}

func (e keeperHandraiseEligibility) Worker(ctx context.Context, candidate WorkerHandraiseCandidate) (policy.WorkerPrecheckInput, uint64, error) {
	// order_sequence 0 is a session's first order, not a missing field - see
	// validateNexusOrderBroadcast for why a zero check has nothing to detect. The
	// identity equation is what binds the sequence, and it applies at zero too.
	if candidate.SessionID == "" || candidate.TaskID != identity.TaskIDString(candidate.SessionID, candidate.OrderSequence) {
		return policy.WorkerPrecheckInput{}, 0, fmt.Errorf("Worker handraise candidate identity is not canonical")
	}
	if candidate.ModelID == "" || candidate.ProfileVersion == 0 || strings.TrimSpace(candidate.Capability) == "" || candidate.DeadlineHeight == 0 {
		return policy.WorkerPrecheckInput{}, 0, fmt.Errorf("Worker handraise model, profile, capability, and deadline are required")
	}
	height, support, supportState, freshnessWindow, capacityRef, availableSlots, err := e.facts(ctx, candidate.ModelID, candidate.ProfileVersion, candidate.Capability, "WORKER")
	if err != nil {
		return policy.WorkerPrecheckInput{}, 0, err
	}
	input := policy.WorkerPrecheckInput{
		ChainSynced: true, CurrentHeight: height, SupportState: supportState,
		SupportLastConfirmedHeight: support.LastRefreshHeight.Uint64(), SupportFreshnessWindow: freshnessWindow, Profile: candidate.Capability,
		SupportedProfiles: []string{candidate.Capability}, AvailableSlots: availableSlots, CapacitySnapshotRef: capacityRef,
		P30ColdStartCandidate: supportState == policy.SupportDeclaredBootstrap,
		// TODO(wire v0.3.0): support is model-scoped and the bootstrap-eligible
		// stake snapshot is gone. A declared-bootstrap node is treated as reward
		// eligible on its service bond, which facts has already checked against
		// the profile's min_stake, until the bootstrap reward rule is restated
		// for model-scoped support.
		RewardEligible:         support.ActiveSupportStakeSnapshot.Uint64() > 0 || supportState == policy.SupportDeclaredBootstrap,
		SelfRescueGasAvailable: e.cfg.SelfRescueGasBudget > 0, SelfRescueGasBudgetNanoTRUEOPEN: e.cfg.SelfRescueGasBudget,
	}
	if candidate.DeadlineHeight <= height {
		return policy.WorkerPrecheckInput{}, 0, fmt.Errorf("Worker handraise deadline %d is not above current height %d", candidate.DeadlineHeight, height)
	}
	return input, candidate.DeadlineHeight, nil
}

func (e keeperHandraiseEligibility) Verifier(ctx context.Context, candidate VerifierHandraiseCandidate) (policy.VerifierPrecheckInput, error) {
	if candidate.TaskID == "" || candidate.SessionID == "" || candidate.ModelID == "" || candidate.ProfileVersion == 0 || strings.TrimSpace(candidate.Capability) == "" || candidate.WorkerAddress == "" || candidate.OpenHeight == 0 {
		return policy.VerifierPrecheckInput{}, fmt.Errorf("Verifier handraise identity, model, profile, capability, worker, and open height are required")
	}
	height, support, supportState, freshnessWindow, _, availableSlots, err := e.facts(ctx, candidate.ModelID, candidate.ProfileVersion, candidate.Capability, "VERIFIER")
	if err != nil {
		return policy.VerifierPrecheckInput{}, err
	}
	return policy.VerifierPrecheckInput{
		ChainSynced: true, CurrentHeight: height, SupportState: supportState,
		SupportLastConfirmedHeight: support.LastRefreshHeight.Uint64(), SupportFreshnessWindow: freshnessWindow, Profile: candidate.Capability,
		SupportedProfiles: []string{candidate.Capability}, AvailableSlots: availableSlots,
		VerifyDeadlineHeight: candidate.OpenHeight + e.cfg.VerifyDeadlineDelta, BeaconDelayHeights: 1,
	}, nil
}

func (e keeperHandraiseEligibility) facts(ctx context.Context, modelID string, profileVersion uint32, requiredCapability string, duty string) (uint64, chainclient.ModelSupportSnapshot, string, uint64, string, int, error) {
	if e.cfg.ChainStatus == nil || e.cfg.Keeper == nil || e.cfg.Model == nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("chain status, Keeper, and model service are required for handraise eligibility")
	}
	height, chainID, err := e.cfg.ChainStatus.ChainStatus(ctx)
	if err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query chain status for handraise: %w", err))
	}
	if height == 0 || strings.TrimSpace(chainID) != strings.TrimSpace(e.cfg.ChainID) {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("handraise chain status does not match configured chain")
	}
	profileVersionText := fmt.Sprintf("%d", profileVersion)
	var projection chainclient.CurrentModelProfileSnapshot
	var capability chainclient.ModelCapabilitySnapshot
	var support chainclient.ModelSupportSnapshot
	var epochLength uint64
	freshnessWindow := uint64(0)
	committedScope := false
	if reader, ok := e.cfg.Keeper.(committedModelSupportScopeReader); ok {
		scope, err := reader.CommittedModelSupportScope(ctx, e.cfg.OperatorAddress, modelID, profileVersionText)
		if err != nil {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query committed Keeper model support scope: %w", err))
		}
		height, projection, capability, support = scope.Height, scope.Profile, scope.Capability, scope.Support
		epochLength = scope.EpochLengthBlocks
		freshnessWindow = uint64(scope.SupportWindowEpochs) * epochLength
		committedScope = true
	} else {
		params, err := e.cfg.Keeper.Params(ctx)
		if err != nil {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper params for handraise: %w", err))
		}
		freshnessWindow = params.DailySupportWindowBlocks.Uint64()
		if freshnessWindow == 0 {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper daily support freshness window is required for handraise")
		}
		projection, err = e.cfg.Keeper.CurrentModelProfile(ctx, modelID, profileVersionText)
		if err != nil {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper model profile for handraise: %w", err))
		}
	}
	if projection.Model.ModelID != modelID || projection.Profile.ModelID != modelID || projection.Profile.ProfileVersion.Uint32() != profileVersion {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model profile identity does not match handraise candidate %s@%d", modelID, profileVersion)
	}
	modelStatus := strings.ToUpper(strings.TrimSpace(projection.Model.Status))
	profileStatus := strings.ToUpper(strings.TrimSpace(projection.Profile.Status))
	if (modelStatus != "REGISTERED" && modelStatus != "ACTIVE") || (profileStatus != "REGISTERED" && profileStatus != "ACTIVE") || projection.Profile.MinStake.Uint64() == 0 {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model profile is not accepting handraise candidates")
	}
	node, err := e.cfg.Keeper.CortexNode(ctx, e.cfg.OperatorAddress)
	if err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper Cortex node for handraise: %w", err))
	}
	if err := node.Validate(); err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, err
	}
	if node.OperatorAddress != e.cfg.OperatorAddress || (!strings.EqualFold(node.Status, "REGISTERED") && !strings.EqualFold(node.Status, "ACTIVE")) {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper Cortex node is not eligible for handraise")
	}
	bond, err := e.cfg.Keeper.ServiceBond(ctx, e.cfg.OperatorAddress)
	if err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper service bond for handraise: %w", err))
	}
	if err := bond.Validate(); err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, err
	}
	// Same admission set as the readiness gate and as the chain: a REGISTERED bond
	// hand-raises, which is the only way it ever becomes ACTIVE. Relaxing readiness
	// alone would move the deadlock here rather than remove it. The stake floor
	// below is the substantive test and is unchanged.
	if bond.OperatorAddress != e.cfg.OperatorAddress || !bond.CandidateEligible() || bond.ActiveBond.Uint64() < projection.Profile.MinStake.Uint64() {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper service bond is not eligible for handraise")
	}
	if !committedScope {
		capability, err = e.cfg.Keeper.ModelCapability(ctx, e.cfg.OperatorAddress, modelID)
		if err != nil {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper model capability for handraise: %w", err))
		}
	}
	if err := capability.Validate(); err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, err
	}
	if capability.OperatorAddress != e.cfg.OperatorAddress || capability.ModelID != modelID {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model capability identity does not match handraise candidate %s@%d", modelID, profileVersion)
	}
	switch duty {
	case "WORKER":
		if !capability.InferenceCapability {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model capability does not enable WORKER inference for %s@%d", modelID, profileVersion)
		}
	case "VERIFIER":
		if !capability.VerificationCapability {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model capability does not enable VERIFIER verification for %s@%d", modelID, profileVersion)
		}
	default:
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("unsupported handraise duty %q", duty)
	}
	if !committedScope {
		support, err = e.cfg.Keeper.ModelSupport(ctx, e.cfg.OperatorAddress, modelID)
		if err != nil {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query Keeper model support for handraise: %w", err))
		}
	}
	if err := support.Validate(); err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, err
	}
	if support.OperatorAddress != e.cfg.OperatorAddress || support.ModelID != modelID || !support.DeclaredSupport {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model support is not declared for handraise candidate %s@%d", modelID, profileVersion)
	}
	if committedScope {
		currentEpoch := height / epochLength
		if support.SupportFreshUntilEpoch.Uint64() == 0 || currentEpoch >= support.SupportFreshUntilEpoch.Uint64() {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model support is stale for handraise candidate %s@%d", modelID, profileVersion)
		}
	} else {
		lastRefreshHeight := support.LastRefreshHeight.Uint64()
		if lastRefreshHeight == 0 || lastRefreshHeight > height || height-lastRefreshHeight > freshnessWindow {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model support is stale for handraise candidate %s@%d", modelID, profileVersion)
		}
	}
	supportState := policy.SupportActive
	if !support.SupportActive {
		if profileStatus != "REGISTERED" {
			return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("Keeper model support is not active for ACTIVE handraise profile %s@%d", modelID, profileVersion)
		}
		supportState = policy.SupportDeclaredBootstrap
	}
	requestID := fmt.Sprintf("handraise-capability-%s-%d", modelID, height)
	capabilities, err := e.cfg.Model.ListCapabilities(ctx, modelservice.ListCapabilitiesRequest{
		RequestID: requestID, ModelServiceID: e.cfg.ModelServiceID, DeadlineMS: time.Now().Add(5 * time.Second).UnixMilli(),
	})
	if err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("query model capabilities for handraise: %w", err))
	}
	// Readiness and capacity are the two refusals in this function that describe
	// a MOMENT rather than a fact, and both are marked retryable for that reason.
	//
	// Everything above -- identity, signature shape, chain membership, bond,
	// declared support, whether this node's capability covers the model at all --
	// answers "may this node ever serve this order", and the answer does not
	// change between two deliveries of the same broadcast. "Every slot is busy"
	// and "the engine has not finished loading" answer "can it serve it right
	// now", and that answer changes the moment a task finishes.
	//
	// Left unmarked they were permanent verdicts, and a permanent verdict is the
	// harshest disposition in the pipeline: the inbox records admissionRefused
	// for the frame, the envelope's replay claim stays consumed, and the Verifier
	// re-drive drops the round (updateVerifierHandraiseRedrive re-arms on a
	// retryable refusal and on nothing else). A node that was briefly full
	// therefore refused the round for good and went quiet.
	//
	// The capability MISMATCH below stays unmarked, deliberately: a model service
	// that does not expose this capability at all is a deployment fact, not a
	// moment.
	if capabilities.Error != nil || capabilities.ModelServiceID != e.cfg.ModelServiceID || capabilities.ResourceSnapshot.LoadedModels <= 0 {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("model service is not ready for handraise: loaded_models=%d service=%q", capabilities.ResourceSnapshot.LoadedModels, capabilities.ModelServiceID))
	}
	// An unset max_concurrency is a configuration gap and stays permanent: the
	// operator has not told the node how much work it may admit, and no amount
	// of waiting supplies that. Every other AvailableSlots refusal is a reading
	// of the moment -- a queue depth above the configured maximum is what an
	// engine reports while it is over-subscribed, which is "full", not "broken".
	if capabilities.ResourceSnapshot.MaxConcurrency == 0 {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("model service max concurrency is not configured for handraise")
	}
	availableSlots, err := capabilities.ResourceSnapshot.AvailableSlots()
	if err != nil {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("model service capacity is unavailable for handraise: %w", err))
	}
	if availableSlots <= 0 {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, builderclient.Retryable(fmt.Errorf("model service has no available handraise capacity: queue_depth=%d max_concurrency=%d", capabilities.ResourceSnapshot.QueueDepth, capabilities.ResourceSnapshot.MaxConcurrency))
	}
	found := false
	for _, advertised := range capabilities.Capabilities {
		if advertised.ModelID == modelID && advertised.Capability == requiredCapability {
			found = true
			break
		}
	}
	if !found {
		return 0, chainclient.ModelSupportSnapshot{}, "", 0, "", 0, fmt.Errorf("model service does not expose %s capability %s", modelID, requiredCapability)
	}
	capacityRef := fmt.Sprintf(
		"model-service:%s:height:%d:loaded:%d:queue:%d:max:%d:available:%d",
		e.cfg.ModelServiceID,
		height,
		capabilities.ResourceSnapshot.LoadedModels,
		capabilities.ResourceSnapshot.QueueDepth,
		capabilities.ResourceSnapshot.MaxConcurrency,
		availableSlots,
	)
	return height, support, supportState, freshnessWindow, capacityRef, availableSlots, nil
}
