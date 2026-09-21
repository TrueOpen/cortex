package observability

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Labels map[string]string

type MetricDefinition struct {
	Name   string
	Labels []string
}

type MetricsRegistry struct {
	mu          sync.RWMutex
	definitions []MetricDefinition
	counters    map[string]uint64
	gauges      map[string]uint64
	freezeRisk  uint64
}

func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		definitions: defaultMetricDefinitions(),
		counters:    make(map[string]uint64),
		gauges:      make(map[string]uint64),
	}
}

type MetricsSnapshot struct {
	ChainLagBlocks         uint64
	WorkerQueueDepth       uint64
	VerifierQueueDepth     uint64
	BuilderOutboxPending   uint64
	BuilderOutboxRetry     uint64
	ModelServiceJobLatency uint64
	EvidencePendingCleanup uint64
	// TaskQueueFailed surfaces terminal queue rows so an operator can find the
	// rows that `cortexctl task requeue` expects to be told about.
	TaskQueueFailed   uint64
	SelfRescueTxs     []SelfRescueMetric
	ProofSubmissions  []ProofMetric
	BuilderFaults     []BuilderFaultMetric
	ProfileRisks      []ProfileRiskMetric
	RewardEligibility []RewardEligibilityMetric
}

type SelfRescueMetric struct {
	Role         string
	DeadlineKind string
	TxKind       string
	Accepted     bool
}

type ProofMetric struct {
	ProofType string
}

type BuilderFaultMetric struct {
	BuilderID  string
	FaultClass string
}

type ProfileRiskMetric struct {
	ModelID        string
	ProfileVersion string
	FailureClass   string
}

type RewardEligibilityMetric struct {
	ModelID           string
	ProfileVersion    string
	RewardState       string
	DisplayVisibility string
	VerificationLabel string
}

func (r *MetricsRegistry) DefinitionsByName() map[string]MetricDefinition {
	out := make(map[string]MetricDefinition, len(r.definitions))
	for _, def := range r.definitions {
		out[def.Name] = def
	}
	return out
}

func (r *MetricsRegistry) ObserveTaskVerdict(verdict string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.increment("cortex_task_verdict_total", Labels{"verdict": strings.TrimSpace(verdict)})
}

func (r *MetricsRegistry) ObserveTaskFailureClass(failureClass string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	failureClass = strings.TrimSpace(failureClass)
	r.increment("cortex_task_failure_class_total", Labels{"failure_class": failureClass})
	if isEmergencyFreezeFailureClass(failureClass) {
		r.freezeRisk++
	}
}

func (r *MetricsRegistry) ObserveSnapshot(snapshot MetricsSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setGauge("cortex_chain_sync_lag_blocks", nil, snapshot.ChainLagBlocks)
	r.setGauge("cortex_worker_queue_depth", nil, snapshot.WorkerQueueDepth)
	r.setGauge("cortex_verifier_queue_depth", nil, snapshot.VerifierQueueDepth)
	r.setGauge("cortex_builder_outbox_pending", nil, snapshot.BuilderOutboxPending)
	r.setGauge("cortex_builder_outbox_retry", nil, snapshot.BuilderOutboxRetry)
	r.setGauge("cortex_model_service_job_latency_seconds", nil, snapshot.ModelServiceJobLatency)
	r.setGauge("cortex_evidence_pending_cleanup", nil, snapshot.EvidencePendingCleanup)
	r.setGauge("cortex_task_queue_failed", nil, snapshot.TaskQueueFailed)
	for _, metric := range snapshot.SelfRescueTxs {
		r.increment("cortex_self_rescue_tx_total", Labels{"role": strings.TrimSpace(metric.Role), "deadline_kind": strings.TrimSpace(metric.DeadlineKind)})
		if metric.Accepted {
			r.increment("cortex_self_rescue_tx_accepted_total", Labels{"tx_kind": strings.TrimSpace(metric.TxKind)})
		}
	}
	for _, metric := range snapshot.ProofSubmissions {
		r.increment("cortex_proof_material_generated_total", Labels{"proof_type": strings.TrimSpace(metric.ProofType)})
	}
	for _, metric := range snapshot.BuilderFaults {
		r.increment("cortex_builder_fault_total", Labels{"builder_id": strings.TrimSpace(metric.BuilderID), "fault_class": strings.TrimSpace(metric.FaultClass)})
	}
	for _, metric := range snapshot.ProfileRisks {
		r.increment("cortex_profile_risk_total", Labels{"model_id": strings.TrimSpace(metric.ModelID), "profile_version": strings.TrimSpace(metric.ProfileVersion), "failure_class": strings.TrimSpace(metric.FailureClass)})
	}
	for _, metric := range snapshot.RewardEligibility {
		labels := Labels{"model_id": strings.TrimSpace(metric.ModelID), "profile_version": strings.TrimSpace(metric.ProfileVersion)}
		r.increment("cortex_model_reward_state", mergeLabels(labels, Labels{"reward_state": strings.TrimSpace(metric.RewardState)}))
		r.increment("cortex_model_display_visibility", mergeLabels(labels, Labels{"display_visibility": strings.TrimSpace(metric.DisplayVisibility)}))
		r.increment("cortex_model_verification_label", mergeLabels(labels, Labels{"verification_label": strings.TrimSpace(metric.VerificationLabel)}))
	}
}

func (r *MetricsRegistry) CounterValue(name string, labels Labels) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.counters[counterKey(name, labels)]
}

func (r *MetricsRegistry) GaugeValue(name string, labels Labels) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gauges[counterKey(name, labels)]
}

func (r *MetricsRegistry) EmergencyFreezeRiskCount() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.freezeRisk
}

// Render writes the registry in Prometheus text exposition format.
//
// Without this the registry was write-only: ObserveSnapshot populated it every
// projection pass and nothing could read it back, so gauges such as
// cortex_task_queue_failed existed only as in-process integers. Every declared
// metric is emitted, including ones still at zero, so a missing series means the
// exporter is broken rather than the value being uninteresting.
func (r *MetricsRegistry) Render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{}, len(r.counters)+len(r.gauges))
	var out strings.Builder
	emit := func(kind string, values map[string]uint64) {
		names := make([]string, 0, len(values))
		for key := range values {
			names = append(names, key)
		}
		sort.Strings(names)
		for _, key := range names {
			name, labels := splitCounterKey(key)
			if _, ok := seen[name]; !ok {
				fmt.Fprintf(&out, "# TYPE %s %s\n", name, kind)
				seen[name] = struct{}{}
			}
			fmt.Fprintf(&out, "%s%s %d\n", name, labels, values[key])
		}
	}
	emit("counter", r.counters)
	emit("gauge", r.gauges)

	for _, definition := range r.definitions {
		if _, ok := seen[definition.Name]; ok {
			continue
		}
		// A declared metric with no observation is reported as zero rather than
		// omitted, so an operator can tell "nothing happened" from "the metric
		// was never wired".
		if len(definition.Labels) != 0 {
			continue
		}
		fmt.Fprintf(&out, "# TYPE %s gauge\n%s 0\n", definition.Name, definition.Name)
	}
	return out.String()
}

// splitCounterKey reverses counterKey. Labels are rendered in the sorted order
// counterKey produced, so output is stable across passes.
func splitCounterKey(key string) (string, string) {
	parts := strings.Split(key, "\xff")
	if len(parts) == 1 {
		return parts[0], ""
	}
	pairs := make([]string, 0, len(parts)-1)
	for _, pair := range parts[1:] {
		name, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s=%q", name, value))
	}
	if len(pairs) == 0 {
		return parts[0], ""
	}
	return parts[0], "{" + strings.Join(pairs, ",") + "}"
}

func (r *MetricsRegistry) increment(name string, labels Labels) {
	r.counters[counterKey(name, labels)]++
}

func (r *MetricsRegistry) setGauge(name string, labels Labels, value uint64) {
	r.gauges[counterKey(name, labels)] = value
}

func mergeLabels(a Labels, b Labels) Labels {
	out := make(Labels, len(a)+len(b))
	for key, value := range a {
		out[key] = value
	}
	for key, value := range b {
		out[key] = value
	}
	return out
}

func counterKey(name string, labels Labels) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	parts = append(parts, name)
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, "\xff")
}

func isEmergencyFreezeFailureClass(failureClass string) bool {
	switch failureClass {
	case "VALUE_MISMATCH", "SCHEMA_FAULT", "WORKER_REVEAL_FAULT":
		return true
	default:
		return false
	}
}

func defaultMetricDefinitions() []MetricDefinition {
	return []MetricDefinition{
		{Name: "cortex_chain_sync_lag_blocks"},
		{Name: "cortex_builder_connected"},
		{Name: "cortex_supported_profiles"},
		{Name: "cortex_worker_queue_depth"},
		{Name: "cortex_verifier_queue_depth"},
		{Name: "cortex_builder_outbox_pending"},
		{Name: "cortex_builder_outbox_retry"},
		{Name: "cortex_model_service_health"},
		{Name: "cortex_model_service_job_latency_seconds"},
		{Name: "cortex_model_service_queue_depth", Labels: []string{"model_service_id", "queue_kind"}},
		{Name: "cortex_model_service_inflight_jobs", Labels: []string{"model_service_id", "job_kind"}},
		{Name: "cortex_model_service_capacity_units", Labels: []string{"model_service_id", "resource_kind"}},
		{Name: "cortex_model_service_resource_used", Labels: []string{"model_service_id", "resource_kind", "unit"}},
		{Name: "cortex_worker_accept_total", Labels: []string{"reason"}},
		{Name: "cortex_worker_reject_total", Labels: []string{"reason"}},
		{Name: "cortex_verifier_accept_total", Labels: []string{"reason"}},
		{Name: "cortex_verifier_reject_total", Labels: []string{"reason"}},
		{Name: "cortex_infer_latency_seconds_bucket"},
		{Name: "cortex_verify_latency_seconds_bucket"},
		{Name: "cortex_deadline_risk_total", Labels: []string{"role"}},
		{Name: "cortex_self_rescue_tx_total", Labels: []string{"role", "deadline_kind"}},
		{Name: "cortex_self_rescue_tx_accepted_total", Labels: []string{"tx_kind"}},
		{Name: "cortex_verifier_commit_accepted_total"},
		{Name: "cortex_result_receipt_accepted_total"},
		{Name: "cortex_worker_reveal_receipt_accepted_total"},
		{Name: "cortex_task_verdict_total", Labels: []string{"verdict"}},
		{Name: "cortex_task_failure_class_total", Labels: []string{"failure_class"}},
		{Name: "cortex_proof_material_generated_total", Labels: []string{"proof_type"}},
		{Name: "cortex_builder_fault_total", Labels: []string{"builder_id", "fault_class"}},
		{Name: "cortex_profile_risk_total", Labels: []string{"model_id", "profile_version", "failure_class"}},
		{Name: "cortex_support_active", Labels: []string{"model_id", "profile_version", "support_mode"}},
		{Name: "cortex_model_display_visibility", Labels: []string{"model_id", "profile_version", "display_visibility"}},
		{Name: "cortex_model_verification_label", Labels: []string{"model_id", "profile_version", "verification_label"}},
		{Name: "cortex_model_reward_state", Labels: []string{"model_id", "profile_version", "reward_state"}},
		{Name: "cortex_model_registration_fee_quote", Labels: []string{"fee_kind", "denom"}},
		{Name: "cortex_model_registration_fee_paid_total", Labels: []string{"fee_kind", "denom"}},
		{Name: "cortex_hardware_tier_proof", Labels: []string{"role", "hardware_tier"}},
		{Name: "cortex_reward_mark_gate", Labels: []string{"hardware_tier", "role"}},
		{Name: "cortex_p30_cutoff", Labels: []string{"hardware_tier", "role"}},
		{Name: "cortex_top10_cutoff", Labels: []string{"hardware_tier", "role"}},
		{Name: "cortex_treasury_maintenance_rate"},
		{Name: "cortex_treasury_balance", Labels: []string{"denom"}},
		{Name: "cortex_reimbursement_cap", Labels: []string{"kind"}},
		{Name: "cortex_evidence_pending_cleanup"},
		{Name: "cortex_task_queue_failed"},
		{Name: "cortex_model_service_job_fail_total", Labels: []string{"reason"}},
	}
}
