package modelregistry

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type ModelStatus struct {
	ModelID             string `json:"model_id"`
	ManifestHash        string `json:"manifest_hash"`
	ProfileVersion      string `json:"profile_version,omitempty"`
	ChainState          string `json:"chain_state"`
	DisplayVisibility   string `json:"display_visibility"`
	VerificationLabel   string `json:"verification_label"`
	RewardState         string `json:"reward_state"`
	Supported           bool   `json:"supported"`
	DailySupportEnabled bool   `json:"daily_support_enabled"`
}

const (
	ChainStateRegistered             = "REGISTERED"
	ChainStateActive                 = "ACTIVE"
	ChainStateFrozen                 = "FROZEN"
	ChainStateEmergencyFrozen        = "EMERGENCY_FROZEN"
	ChainStateDelisted               = "DELISTED"
	DisplayVisible                   = "VISIBLE"
	DisplayArchived                  = "ARCHIVED"
	DisplayHidden                    = "HIDDEN"
	VerificationOfficial             = "OFFICIAL"
	VerificationCommunity            = "COMMUNITY_VERIFIED"
	VerificationUnverified           = "UNVERIFIED"
	RewardEligibleIfMarked           = "ELIGIBLE_IF_MARKED"
	RewardFeeOnlyNoBlockReward       = "FEE_ONLY_NO_BLOCK_REWARD"
	RewardFrozenNoNewTasks           = "FROZEN_NO_NEW_TASKS"
	SupportUnsupported               = "UNSUPPORTED"
	SupportDeclaredBootstrap         = "DECLARED_BOOTSTRAP"
	SupportActive                    = "ACTIVE"
	SupportStale                     = "STALE"
	FailureClassNone                 = "NONE"
	FailureClassInsufficientVerifier = "INSUFFICIENT_VERIFIER"
	FailureClassValueMismatch        = "VALUE_MISMATCH"
	FailureClassSchemaFault          = "SCHEMA_FAULT"
	FailureClassWorkerRevealFault    = "WORKER_REVEAL_FAULT"
	ClaimResponsibilityWalletSDK     = "wallet/SDK"
)

type ModelDetails struct {
	Status   ModelStatus `json:"status"`
	Manifest Manifest    `json:"manifest,omitempty"`
}

type StatusObservation struct {
	ModelID                  string
	ProfileVersion           string
	ChainState               string
	DisplayVisibility        string
	VerificationLabel        string
	DeclaredSupport          bool
	SupportActive            bool
	SupportWindowCloseHeight uint64
	LastP30TaskID            string
	P30Cutoff                uint64
	Top10Cutoff              uint64
	MarkGateOpen             bool
	LastMarkedTaskID         string
	HardwareTier             string
	HardwareTierProofTaskID  string
	HardwareTierProofRole    string
	Treasury                 TreasuryState
	Builder                  BuilderObservation
	FailureClasses           []FailureClassObservation
	EmergencyFreezeAccepted  bool
	Earnings                 EarningsObservation
}

type StatusProjection struct {
	ModelID           string                `json:"model_id"`
	ProfileVersion    string                `json:"profile_version"`
	ChainState        string                `json:"chain_state"`
	DisplayVisibility string                `json:"display_visibility"`
	VerificationLabel string                `json:"verification_label"`
	RewardState       string                `json:"reward_state"`
	Support           SupportProjection     `json:"support"`
	MarkGate          MarkGateProjection    `json:"mark_gate"`
	Risk              ProfileRiskProjection `json:"risk"`
	Treasury          TreasuryState         `json:"treasury"`
	Builder           BuilderObservation    `json:"builder"`
	HardwareTierProof HardwareTierProof     `json:"hardware_tier_proof"`
	EmergencyFreeze   EmergencyFreezeState  `json:"emergency_freeze"`
	Earnings          EarningsView          `json:"earnings"`
}

type SupportProjection struct {
	DeclaredSupport          bool   `json:"declared_support"`
	SupportActive            bool   `json:"support_active"`
	SupportState             string `json:"support_state"`
	LastP30TaskID            string `json:"last_p30_task_id,omitempty"`
	SupportWindowCloseHeight uint64 `json:"support_window_close_height,omitempty"`
	P30CutoffSnapshot        uint64 `json:"p30_cutoff_snapshot,omitempty"`
	HardwareTier             string `json:"hardware_tier,omitempty"`
}

type MarkGateProjection struct {
	Open             bool   `json:"open"`
	P30Cutoff        uint64 `json:"p30_cutoff"`
	Top10Cutoff      uint64 `json:"top10_cutoff"`
	LastMarkedTaskID string `json:"last_marked_task_id,omitempty"`
}

type FailureClassObservation struct {
	Class string
	Count uint64
}

type ProfileRiskProjection struct {
	Counts                   map[string]uint64 `json:"counts"`
	EmergencyFreezeRiskCount uint64            `json:"emergency_freeze_risk_count"`
}

type TreasuryState struct {
	Denom                   string `json:"denom"`
	Balance                 uint64 `json:"balance"`
	MaintenanceRate         uint64 `json:"maintenance_rate"`
	MaxReimbursementPerTx   uint64 `json:"max_reimbursement_per_tx"`
	MaxReimbursementPerTask uint64 `json:"max_reimbursement_per_task"`
}

type BuilderObservation struct {
	Connected       bool   `json:"connected"`
	MissedMessages  uint64 `json:"missed_messages"`
	FaultedMessages uint64 `json:"faulted_messages"`
}

type HardwareTierProof struct {
	HardwareTier string `json:"hardware_tier,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	Role         string `json:"role,omitempty"`
}

type EmergencyFreezeState struct {
	Frozen bool   `json:"frozen"`
	Reason string `json:"reason,omitempty"`
}

type EarningsObservation struct {
	PendingTaskFee        uint64
	ClaimableTaskFee      uint64
	TaskFinalityHeight    uint64
	ClaimableAfterHeight  uint64
	LatestClaimTxObserved string
}

type EarningsView struct {
	PendingTaskFee        uint64 `json:"pending_task_fee"`
	ClaimableTaskFee      uint64 `json:"claimable_task_fee"`
	TaskFinalityHeight    uint64 `json:"task_finality_height"`
	ClaimableAfterHeight  uint64 `json:"claimable_after_height"`
	LatestClaimTxObserved string `json:"latest_claim_tx_observed,omitempty"`
	ReadOnly              bool   `json:"read_only"`
	ClaimResponsibility   string `json:"claim_responsibility"`
}

type StatusRequest struct {
	ModelID string
	Height  uint64
}

type ListRequest struct {
	Height uint64
}

type ShowRequest struct {
	ModelID string
	Height  uint64
}

type SupportRequest struct {
	ModelID        string `json:"model_id"`
	ProfileVersion string `json:"profile_version,omitempty"`
	Supported      bool   `json:"supported"`
	DryRun         bool   `json:"dry_run"`
}

type DailySupportRequest struct {
	ModelID string
	Enabled bool
	DryRun  bool
}

func (r *Registry) PutStatus(status ModelStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.statuses == nil {
		r.statuses = make(map[string]ModelStatus)
	}
	r.statuses[status.ModelID] = status
}

func (r *Registry) PutStatusProjection(projection StatusProjection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.projections == nil {
		r.projections = make(map[string]StatusProjection)
	}
	r.projections[projection.ModelID] = projection
}

func (r *Registry) Status(_ context.Context, req StatusRequest) (ModelStatus, error) {
	return r.statusForModel(req.ModelID)
}

func (r *Registry) List(_ context.Context, _ ListRequest) ([]ModelStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	modelIDs := make([]string, 0, len(r.statuses))
	for modelID := range r.statuses {
		modelIDs = append(modelIDs, modelID)
	}
	sort.Strings(modelIDs)
	out := make([]ModelStatus, 0, len(modelIDs))
	for _, modelID := range modelIDs {
		out = append(out, r.statuses[modelID])
	}
	return out, nil
}

func (r *Registry) Show(_ context.Context, req ShowRequest) (ModelDetails, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status, err := r.statusForModelLocked(req.ModelID)
	if err != nil {
		return ModelDetails{}, err
	}
	return ModelDetails{
		Status:   status,
		Manifest: cloneManifest(r.manifests[status.ManifestHash]),
	}, nil
}

func (r *Registry) StatusProjection(ctx context.Context, req StatusRequest) (StatusProjection, error) {
	status, err := r.Status(ctx, req)
	if err != nil {
		return StatusProjection{}, err
	}
	r.mu.RLock()
	if projection, ok := r.projections[status.ModelID]; ok {
		r.mu.RUnlock()
		return projection, nil
	}
	r.mu.RUnlock()
	return ProjectStatusFromModelStatus(status), nil
}

func (r *Registry) ListProjections(ctx context.Context, req ListRequest) ([]StatusProjection, error) {
	statuses, err := r.List(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]StatusProjection, 0, len(statuses))
	for _, status := range statuses {
		r.mu.RLock()
		projection, ok := r.projections[status.ModelID]
		r.mu.RUnlock()
		if !ok {
			projection = ProjectStatusFromModelStatus(status)
		}
		out = append(out, projection)
	}
	return out, nil
}

func (r *Registry) ShowProjection(ctx context.Context, req ShowRequest) (StatusProjection, error) {
	details, err := r.Show(ctx, req)
	if err != nil {
		return StatusProjection{}, err
	}
	projection := ProjectStatusFromModelStatus(details.Status)
	r.mu.RLock()
	if cached, ok := r.projections[details.Status.ModelID]; ok {
		projection = cached
	}
	r.mu.RUnlock()
	if projection.ProfileVersion == "" {
		projection.ProfileVersion = details.Manifest.Verification.ProfileVersion
	}
	return projection, nil
}

func (r *Registry) ensureStatusLocked(modelID string) (ModelStatus, error) {
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return ModelStatus{}, fmt.Errorf("model_id is required")
	}
	status, ok := r.statuses[modelID]
	if !ok {
		status = ModelStatus{
			ModelID:           modelID,
			ChainState:        "local",
			DisplayVisibility: "hidden",
			VerificationLabel: "unverified",
			RewardState:       "ineligible",
		}
	}
	return status, nil
}

func (r *Registry) statusForModel(modelID string) (ModelStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.statusForModelLocked(modelID)
}

func (r *Registry) statusForModelLocked(modelID string) (ModelStatus, error) {
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return ModelStatus{}, fmt.Errorf("model_id is required")
	}
	status, ok := r.statuses[modelID]
	if !ok {
		return ModelStatus{}, fmt.Errorf("model %q not found", modelID)
	}
	return status, nil
}

func cloneManifest(manifest Manifest) Manifest {
	if len(manifest.Metadata) == 0 {
		return manifest
	}
	manifest.Metadata = cloneStringMap(manifest.Metadata)
	return manifest
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func ProjectStatus(obs StatusObservation) StatusProjection {
	chainState := normalizeChainState(obs.ChainState)
	displayVisibility := normalizeDisplayVisibility(obs.DisplayVisibility)
	verificationLabel := normalizeVerificationLabel(obs.VerificationLabel)
	return StatusProjection{
		ModelID:           obs.ModelID,
		ProfileVersion:    obs.ProfileVersion,
		ChainState:        chainState,
		DisplayVisibility: displayVisibility,
		VerificationLabel: verificationLabel,
		RewardState:       projectRewardState(chainState),
		Support: SupportProjection{
			DeclaredSupport:          obs.DeclaredSupport,
			SupportActive:            obs.SupportActive,
			SupportState:             projectSupportState(obs),
			LastP30TaskID:            obs.LastP30TaskID,
			SupportWindowCloseHeight: obs.SupportWindowCloseHeight,
			P30CutoffSnapshot:        obs.P30Cutoff,
			HardwareTier:             obs.HardwareTier,
		},
		MarkGate: MarkGateProjection{
			Open:             obs.MarkGateOpen,
			P30Cutoff:        obs.P30Cutoff,
			Top10Cutoff:      obs.Top10Cutoff,
			LastMarkedTaskID: obs.LastMarkedTaskID,
		},
		Risk:     ProjectProfileRisk(obs.FailureClasses),
		Treasury: obs.Treasury,
		Builder:  obs.Builder,
		HardwareTierProof: HardwareTierProof{
			HardwareTier: obs.HardwareTier,
			TaskID:       obs.HardwareTierProofTaskID,
			Role:         obs.HardwareTierProofRole,
		},
		EmergencyFreeze: EmergencyFreezeState{
			Frozen: obs.EmergencyFreezeAccepted || chainState == ChainStateEmergencyFrozen,
			Reason: emergencyFreezeReason(obs),
		},
		Earnings: ProjectEarnings(obs.Earnings),
	}
}

func ProjectStatusFromModelStatus(status ModelStatus) StatusProjection {
	profileVersion := status.ProfileVersion
	if profileVersion == "" {
		profileVersion = status.ManifestHash
	}
	return ProjectStatus(StatusObservation{
		ModelID:           status.ModelID,
		ProfileVersion:    profileVersion,
		ChainState:        status.ChainState,
		DisplayVisibility: status.DisplayVisibility,
		VerificationLabel: status.VerificationLabel,
		DeclaredSupport:   status.Supported || status.DailySupportEnabled,
		SupportActive:     status.Supported,
	})
}

func ProjectProfileRisk(observations []FailureClassObservation) ProfileRiskProjection {
	counts := make(map[string]uint64, len(observations))
	var risk uint64
	for _, obs := range observations {
		counts[obs.Class] += obs.Count
		if isFreezeEligibleFailureClass(obs.Class) {
			risk += obs.Count
		}
	}
	return ProfileRiskProjection{Counts: counts, EmergencyFreezeRiskCount: risk}
}

func ProjectEarnings(obs EarningsObservation) EarningsView {
	return EarningsView{
		PendingTaskFee:        obs.PendingTaskFee,
		ClaimableTaskFee:      obs.ClaimableTaskFee,
		TaskFinalityHeight:    obs.TaskFinalityHeight,
		ClaimableAfterHeight:  obs.ClaimableAfterHeight,
		LatestClaimTxObserved: obs.LatestClaimTxObserved,
		ReadOnly:              true,
		ClaimResponsibility:   ClaimResponsibilityWalletSDK,
	}
}

func projectRewardState(chainState string) string {
	switch chainState {
	case ChainStateActive:
		return RewardEligibleIfMarked
	case ChainStateFrozen, ChainStateEmergencyFrozen, ChainStateDelisted:
		return RewardFrozenNoNewTasks
	default:
		return RewardFeeOnlyNoBlockReward
	}
}

func projectSupportState(obs StatusObservation) string {
	switch {
	case obs.SupportActive:
		return SupportActive
	case obs.DeclaredSupport && obs.LastP30TaskID == "":
		return SupportDeclaredBootstrap
	case obs.DeclaredSupport:
		return SupportStale
	default:
		return SupportUnsupported
	}
}

func isFreezeEligibleFailureClass(failureClass string) bool {
	switch failureClass {
	case FailureClassValueMismatch, FailureClassSchemaFault, FailureClassWorkerRevealFault:
		return true
	default:
		return false
	}
}

func emergencyFreezeReason(obs StatusObservation) string {
	if obs.EmergencyFreezeAccepted {
		return "chain_emergency_freeze_accepted"
	}
	if obs.ChainState == ChainStateEmergencyFrozen {
		return "profile_emergency_frozen"
	}
	return ""
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeChainState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "registered", "registration_submitted", "pending":
		return ChainStateRegistered
	case "active":
		return ChainStateActive
	case "frozen":
		return ChainStateFrozen
	case "emergency_frozen":
		return ChainStateEmergencyFrozen
	case "delisted":
		return ChainStateDelisted
	default:
		return value
	}
}

func normalizeDisplayVisibility(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "visible", "public":
		return DisplayVisible
	case "archived":
		return DisplayArchived
	case "", "hidden", "local":
		return DisplayHidden
	default:
		return value
	}
}

func normalizeVerificationLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "official":
		return VerificationOfficial
	case "community_verified", "trace verified", "trace_verified":
		return VerificationCommunity
	case "", "unverified":
		return VerificationUnverified
	default:
		return value
	}
}
