package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/TrueOpen/cortex/internal/modelregistry"
)

type Projector struct {
	Source   ObservationSource
	Registry *modelregistry.Registry
	Metrics  *MetricsRegistry
}

var ErrObservationSourceRequired = errors.New("authoritative observation source is required")

type ObservationSource interface {
	ModelObservations(context.Context) ([]ModelObservation, error)
}

type ModelObservation struct {
	EventType      string
	SubjectID      string
	Phase          string
	ModelID        string
	ProfileVersion string
	Payload        []byte
}

type projectionPayload struct {
	ChainState            string `json:"chain_state"`
	DisplayVisibility     string `json:"display_visibility"`
	VerificationLabel     string `json:"verification_label"`
	DeclaredSupport       bool   `json:"declared_support"`
	SupportActive         bool   `json:"support_active"`
	MarkGateOpen          bool   `json:"mark_gate_open"`
	P30Cutoff             uint64 `json:"p30_cutoff"`
	Top10Cutoff           uint64 `json:"top10_cutoff"`
	LastMarkedTaskID      string `json:"last_marked_task_id"`
	FailureClass          string `json:"failure_class"`
	Count                 uint64 `json:"count"`
	Reason                string `json:"reason"`
	BuilderID             string `json:"builder_id"`
	FaultClass            string `json:"fault_class"`
	TreasuryDenom         string `json:"treasury_denom"`
	TreasuryBalance       uint64 `json:"treasury_balance"`
	MaintenanceRate       uint64 `json:"maintenance_rate"`
	MaxReimbursement      uint64 `json:"max_reimbursement"`
	TaskFinalityHeight    uint64 `json:"task_finality_height"`
	ClaimableAfterHeight  uint64 `json:"claimable_after_height"`
	ClaimableTaskFee      uint64 `json:"claimable_task_fee"`
	LatestClaimTxObserved string `json:"latest_claim_tx_observed"`
}

type projectionAccumulator struct {
	status         modelregistry.ModelStatus
	obs            modelregistry.StatusObservation
	failureClasses map[string]uint64
	builderFaults  map[string]uint64
}

func (p *Projector) RunOnce(ctx context.Context) error {
	if p == nil {
		return fmt.Errorf("projector is required")
	}
	if p.Source == nil {
		return ErrObservationSourceRequired
	}
	rows, err := p.Source.ModelObservations(ctx)
	if err != nil {
		return err
	}
	accs := map[string]*projectionAccumulator{}
	for _, row := range rows {
		if row.ModelID == "" {
			continue
		}
		key := row.ModelID + "\x00" + row.ProfileVersion
		acc := accs[key]
		if acc == nil {
			acc = &projectionAccumulator{
				status: modelregistry.ModelStatus{
					ModelID:           row.ModelID,
					ManifestHash:      row.ProfileVersion,
					ChainState:        modelregistry.ChainStateRegistered,
					DisplayVisibility: modelregistry.DisplayVisible,
					VerificationLabel: modelregistry.VerificationCommunity,
					RewardState:       modelregistry.RewardFeeOnlyNoBlockReward,
				},
				obs: modelregistry.StatusObservation{
					ModelID:           row.ModelID,
					ProfileVersion:    row.ProfileVersion,
					ChainState:        modelregistry.ChainStateRegistered,
					DisplayVisibility: modelregistry.DisplayVisible,
					VerificationLabel: modelregistry.VerificationCommunity,
				},
				failureClasses: map[string]uint64{},
				builderFaults:  map[string]uint64{},
			}
			accs[key] = acc
		}
		if err := applyProjectionRow(acc, row); err != nil {
			return err
		}
	}
	for _, acc := range accs {
		for class, count := range acc.failureClasses {
			acc.obs.FailureClasses = append(acc.obs.FailureClasses, modelregistry.FailureClassObservation{Class: class, Count: count})
		}
		for _, count := range acc.builderFaults {
			acc.obs.Builder.FaultedMessages += count
		}
		projection := modelregistry.ProjectStatus(acc.obs)
		acc.status.ChainState = projection.ChainState
		acc.status.DisplayVisibility = projection.DisplayVisibility
		acc.status.VerificationLabel = projection.VerificationLabel
		acc.status.RewardState = projection.RewardState
		acc.status.Supported = projection.Support.SupportActive
		if p.Registry != nil {
			p.Registry.PutStatus(acc.status)
			p.Registry.PutStatusProjection(projection)
		}
	}
	if p.Metrics != nil {
		p.Metrics.ObserveSnapshot(p.metricsSnapshot(accs))
	}
	return nil
}

func applyProjectionRow(acc *projectionAccumulator, row ModelObservation) error {
	payload, err := decodeProjectionPayload(row.Payload)
	if err != nil {
		return err
	}
	switch row.EventType {
	case "EventRewardMarked":
		mergeStatusFields(acc, payload)
	case "EventMarkGateUpdated":
		acc.obs.MarkGateOpen = payload.MarkGateOpen
		acc.obs.P30Cutoff = payload.P30Cutoff
		acc.obs.Top10Cutoff = payload.Top10Cutoff
		acc.obs.LastMarkedTaskID = payload.LastMarkedTaskID
	case "EventEmergencyFreezeAccepted":
		acc.obs.EmergencyFreezeAccepted = true
		if payload.Reason != "" {
			acc.failureClasses[payload.Reason]++
		}
	case "EventTaskFailureClassUpdated":
		if payload.FailureClass != "" {
			count := payload.Count
			if count == 0 {
				count = 1
			}
			acc.failureClasses[payload.FailureClass] += count
		}
	case "EventFaultRecorded":
		key := firstNonEmpty(payload.BuilderID, row.SubjectID) + "\x00" + firstNonEmpty(payload.FaultClass, row.Phase)
		acc.builderFaults[key]++
	case "EventSettlementFinalityUpdated":
		acc.obs.Earnings.TaskFinalityHeight = payload.TaskFinalityHeight
		acc.obs.Earnings.ClaimableAfterHeight = payload.ClaimableAfterHeight
		acc.obs.Earnings.ClaimableTaskFee = payload.ClaimableTaskFee
		acc.obs.Earnings.LatestClaimTxObserved = payload.LatestClaimTxObserved
	}
	return nil
}

func decodeProjectionPayload(raw []byte) (projectionPayload, error) {
	var payload projectionPayload
	if len(raw) == 0 {
		return payload, nil
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, err
	}
	var envelope struct {
		Payload    json.RawMessage   `json:"payload"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return payload, err
	}
	if len(envelope.Payload) == 0 || string(envelope.Payload) == "null" {
		if len(envelope.Attributes) == 0 {
			return payload, nil
		}
		return projectionPayloadFromAttributes(envelope.Attributes)
	}
	var inner projectionPayload
	if err := json.Unmarshal(envelope.Payload, &inner); err != nil {
		return payload, err
	}
	return inner, nil
}

func projectionPayloadFromAttributes(attributes map[string]string) (projectionPayload, error) {
	payload := projectionPayload{
		ChainState:            attributes["chain_state"],
		DisplayVisibility:     attributes["display_visibility"],
		VerificationLabel:     attributes["verification_label"],
		LastMarkedTaskID:      attributes["last_marked_task_id"],
		FailureClass:          attributes["failure_class"],
		Reason:                attributes["reason"],
		BuilderID:             attributes["builder_id"],
		FaultClass:            attributes["fault_class"],
		TreasuryDenom:         attributes["treasury_denom"],
		LatestClaimTxObserved: attributes["latest_claim_tx_observed"],
	}
	for key, target := range map[string]*bool{
		"declared_support": &payload.DeclaredSupport,
		"support_active":   &payload.SupportActive,
		"mark_gate_open":   &payload.MarkGateOpen,
	} {
		value := attributes[key]
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return projectionPayload{}, fmt.Errorf("invalid Keeper event attribute %s=%q: %w", key, value, err)
		}
		*target = parsed
	}
	for key, target := range map[string]*uint64{
		"p30_cutoff":             &payload.P30Cutoff,
		"top10_cutoff":           &payload.Top10Cutoff,
		"count":                  &payload.Count,
		"treasury_balance":       &payload.TreasuryBalance,
		"maintenance_rate":       &payload.MaintenanceRate,
		"max_reimbursement":      &payload.MaxReimbursement,
		"task_finality_height":   &payload.TaskFinalityHeight,
		"claimable_after_height": &payload.ClaimableAfterHeight,
		"claimable_task_fee":     &payload.ClaimableTaskFee,
	} {
		value := attributes[key]
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != value {
			return projectionPayload{}, fmt.Errorf("invalid Keeper event uint64 attribute %s=%q", key, value)
		}
		*target = parsed
	}
	return payload, nil
}

func mergeStatusFields(acc *projectionAccumulator, payload projectionPayload) {
	if payload.ChainState != "" {
		acc.obs.ChainState = payload.ChainState
		acc.status.ChainState = payload.ChainState
	}
	if payload.DisplayVisibility != "" {
		acc.obs.DisplayVisibility = payload.DisplayVisibility
		acc.status.DisplayVisibility = payload.DisplayVisibility
	}
	if payload.VerificationLabel != "" {
		acc.obs.VerificationLabel = payload.VerificationLabel
		acc.status.VerificationLabel = payload.VerificationLabel
	}
	acc.obs.DeclaredSupport = payload.DeclaredSupport
	acc.obs.SupportActive = payload.SupportActive
	acc.status.Supported = payload.SupportActive
	if payload.TreasuryDenom != "" {
		acc.obs.Treasury.Denom = payload.TreasuryDenom
	}
	if payload.TreasuryBalance != 0 {
		acc.obs.Treasury.Balance = payload.TreasuryBalance
	}
	if payload.MaintenanceRate != 0 {
		acc.obs.Treasury.MaintenanceRate = payload.MaintenanceRate
	}
	if payload.MaxReimbursement != 0 {
		acc.obs.Treasury.MaxReimbursementPerTask = payload.MaxReimbursement
	}
	if payload.LastMarkedTaskID != "" {
		acc.obs.LastMarkedTaskID = payload.LastMarkedTaskID
	}
}

func (p *Projector) metricsSnapshot(accs map[string]*projectionAccumulator) MetricsSnapshot {
	snapshot := MetricsSnapshot{}
	for _, acc := range accs {
		projection := modelregistry.ProjectStatus(acc.obs)
		for class := range projection.Risk.Counts {
			snapshot.ProfileRisks = append(snapshot.ProfileRisks, ProfileRiskMetric{ModelID: projection.ModelID, ProfileVersion: projection.ProfileVersion, FailureClass: class})
		}
		for key := range acc.builderFaults {
			builderID, faultClass := splitPair(key)
			snapshot.BuilderFaults = append(snapshot.BuilderFaults, BuilderFaultMetric{BuilderID: builderID, FaultClass: faultClass})
		}
		snapshot.RewardEligibility = append(snapshot.RewardEligibility, RewardEligibilityMetric{
			ModelID:           projection.ModelID,
			ProfileVersion:    projection.ProfileVersion,
			RewardState:       projection.RewardState,
			DisplayVisibility: projection.DisplayVisibility,
			VerificationLabel: projection.VerificationLabel,
		})
	}
	return snapshot
}

func splitPair(value string) (string, string) {
	for i := range value {
		if value[i] == 0 {
			return value[:i], value[i+1:]
		}
	}
	return value, ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
