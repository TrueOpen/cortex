package observability

import (
	"strings"
	"sync"
	"testing"
)

func TestRegistryExposesRequiredMetricNamesAndLabels(t *testing.T) {
	registry := NewMetricsRegistry()
	defs := registry.DefinitionsByName()

	required := map[string][]string{
		"cortex_chain_sync_lag_blocks":                nil,
		"cortex_builder_connected":                    nil,
		"cortex_supported_profiles":                   nil,
		"cortex_worker_queue_depth":                   nil,
		"cortex_verifier_queue_depth":                 nil,
		"cortex_builder_outbox_pending":               nil,
		"cortex_builder_outbox_retry":                 nil,
		"cortex_model_service_health":                 nil,
		"cortex_model_service_job_latency_seconds":    nil,
		"cortex_model_service_queue_depth":            {"model_service_id", "queue_kind"},
		"cortex_model_service_inflight_jobs":          {"model_service_id", "job_kind"},
		"cortex_model_service_capacity_units":         {"model_service_id", "resource_kind"},
		"cortex_model_service_resource_used":          {"model_service_id", "resource_kind", "unit"},
		"cortex_worker_accept_total":                  {"reason"},
		"cortex_worker_reject_total":                  {"reason"},
		"cortex_verifier_accept_total":                {"reason"},
		"cortex_verifier_reject_total":                {"reason"},
		"cortex_infer_latency_seconds_bucket":         nil,
		"cortex_verify_latency_seconds_bucket":        nil,
		"cortex_deadline_risk_total":                  {"role"},
		"cortex_self_rescue_tx_total":                 {"role", "deadline_kind"},
		"cortex_self_rescue_tx_accepted_total":        {"tx_kind"},
		"cortex_verifier_commit_accepted_total":       nil,
		"cortex_result_receipt_accepted_total":        nil,
		"cortex_worker_reveal_receipt_accepted_total": nil,
		"cortex_task_verdict_total":                   {"verdict"},
		"cortex_task_failure_class_total":             {"failure_class"},
		"cortex_proof_material_generated_total":       {"proof_type"},
		"cortex_builder_fault_total":                  {"builder_id", "fault_class"},
		"cortex_profile_risk_total":                   {"model_id", "profile_version", "failure_class"},
		"cortex_support_active":                       {"model_id", "profile_version", "support_mode"},
		"cortex_model_display_visibility":             {"model_id", "profile_version", "display_visibility"},
		"cortex_model_verification_label":             {"model_id", "profile_version", "verification_label"},
		"cortex_model_reward_state":                   {"model_id", "profile_version", "reward_state"},
		"cortex_model_registration_fee_quote":         {"fee_kind", "denom"},
		"cortex_model_registration_fee_paid_total":    {"fee_kind", "denom"},
		"cortex_hardware_tier_proof":                  {"role", "hardware_tier"},
		"cortex_reward_mark_gate":                     {"hardware_tier", "role"},
		"cortex_p30_cutoff":                           {"hardware_tier", "role"},
		"cortex_top10_cutoff":                         {"hardware_tier", "role"},
		"cortex_treasury_maintenance_rate":            nil,
		"cortex_treasury_balance":                     {"denom"},
		"cortex_reimbursement_cap":                    {"kind"},
		"cortex_evidence_pending_cleanup":             nil,
		"cortex_model_service_job_fail_total":         {"reason"},
	}

	for name, labels := range required {
		def, ok := defs[name]
		if !ok {
			t.Fatalf("metric %s is not registered", name)
		}
		if !sameStrings(def.Labels, labels) {
			t.Fatalf("metric %s labels = %#v, want %#v", name, def.Labels, labels)
		}
	}
}

func TestTaskVerdictFailDoesNotIncrementValueMismatch(t *testing.T) {
	registry := NewMetricsRegistry()

	registry.ObserveTaskVerdict("FAIL")

	if got := registry.CounterValue("cortex_task_verdict_total", Labels{"verdict": "FAIL"}); got != 1 {
		t.Fatalf("FAIL verdict counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_task_failure_class_total", Labels{"failure_class": "VALUE_MISMATCH"}); got != 0 {
		t.Fatalf("VALUE_MISMATCH counter = %d, want 0", got)
	}
}

func TestEmergencyFreezeRiskOnlyCountsChainEligibleFailureClasses(t *testing.T) {
	registry := NewMetricsRegistry()

	for _, failureClass := range []string{"VALUE_MISMATCH", "SCHEMA_FAULT", "WORKER_REVEAL_FAULT", "INSUFFICIENT_VERIFIER", "NONE"} {
		registry.ObserveTaskFailureClass(failureClass)
	}

	if got := registry.EmergencyFreezeRiskCount(); got != 3 {
		t.Fatalf("EmergencyFreeze risk count = %d, want 3", got)
	}
}

func TestObserveSnapshotPopulatesProductionOperatorMetrics(t *testing.T) {
	registry := NewMetricsRegistry()

	registry.ObserveSnapshot(MetricsSnapshot{
		ChainLagBlocks:         7,
		WorkerQueueDepth:       3,
		VerifierQueueDepth:     4,
		BuilderOutboxPending:   5,
		BuilderOutboxRetry:     2,
		ModelServiceJobLatency: 12,
		EvidencePendingCleanup: 9,
		SelfRescueTxs: []SelfRescueMetric{
			{Role: "worker", DeadlineKind: "infer_receipt", TxKind: "MsgInferReceiptCommitOnlyTx", Accepted: true},
			{Role: "verifier", DeadlineKind: "commit", TxKind: "MsgCommitTx", Accepted: false},
		},
		ProofSubmissions: []ProofMetric{{ProofType: "verdict_fraud"}, {ProofType: "payload_mismatch"}},
		BuilderFaults:    []BuilderFaultMetric{{BuilderID: "builder-1", FaultClass: "delivery_miss"}},
		ProfileRisks: []ProfileRiskMetric{{
			ModelID:        "model-a",
			ProfileVersion: "llm_text_v1",
			FailureClass:   "WORKER_REVEAL_FAULT",
		}},
		RewardEligibility: []RewardEligibilityMetric{{
			ModelID:           "model-a",
			ProfileVersion:    "llm_text_v1",
			RewardState:       "FEE_ONLY_NO_BLOCK_REWARD",
			DisplayVisibility: "VISIBLE",
			VerificationLabel: "OFFICIAL",
		}},
	})

	gauges := []struct {
		name string
		want uint64
	}{
		{"cortex_chain_sync_lag_blocks", 7},
		{"cortex_worker_queue_depth", 3},
		{"cortex_verifier_queue_depth", 4},
		{"cortex_builder_outbox_pending", 5},
		{"cortex_builder_outbox_retry", 2},
		{"cortex_model_service_job_latency_seconds", 12},
		{"cortex_evidence_pending_cleanup", 9},
	}
	for _, tt := range gauges {
		if got := registry.GaugeValue(tt.name, nil); got != tt.want {
			t.Fatalf("gauge %s = %d, want %d", tt.name, got, tt.want)
		}
	}
	if got := registry.CounterValue("cortex_self_rescue_tx_total", Labels{"role": "worker", "deadline_kind": "infer_receipt"}); got != 1 {
		t.Fatalf("worker self rescue counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_self_rescue_tx_accepted_total", Labels{"tx_kind": "MsgInferReceiptCommitOnlyTx"}); got != 1 {
		t.Fatalf("accepted self rescue counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_proof_material_generated_total", Labels{"proof_type": "verdict_fraud"}); got != 1 {
		t.Fatalf("verdict fraud proof counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_builder_fault_total", Labels{"builder_id": "builder-1", "fault_class": "delivery_miss"}); got != 1 {
		t.Fatalf("builder fault counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_profile_risk_total", Labels{"model_id": "model-a", "profile_version": "llm_text_v1", "failure_class": "WORKER_REVEAL_FAULT"}); got != 1 {
		t.Fatalf("profile risk counter = %d, want 1", got)
	}
	if got := registry.CounterValue("cortex_model_reward_state", Labels{"model_id": "model-a", "profile_version": "llm_text_v1", "reward_state": "FEE_ONLY_NO_BLOCK_REWARD"}); got != 1 {
		t.Fatalf("reward state counter = %d, want 1", got)
	}
}

func TestMetricsRegistrySupportsConcurrentObservationAndReads(t *testing.T) {
	registry := NewMetricsRegistry()
	const writers = 4
	const iterations = 250

	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				registry.ObserveSnapshot(MetricsSnapshot{
					ChainLagBlocks:   uint64(i),
					ProofSubmissions: []ProofMetric{{ProofType: "verdict_fraud"}},
				})
				_ = registry.GaugeValue("cortex_chain_sync_lag_blocks", nil)
				_ = registry.CounterValue("cortex_proof_material_generated_total", Labels{"proof_type": "verdict_fraud"})
				_ = registry.EmergencyFreezeRiskCount()
			}
		}()
	}
	wg.Wait()

	if got, want := registry.CounterValue("cortex_proof_material_generated_total", Labels{"proof_type": "verdict_fraud"}), uint64(writers*iterations); got != want {
		t.Fatalf("proof counter = %d, want %d", got, want)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The registry used to be write-only: the projector filled it on every pass and
// no surface could read it back, so cortex_task_queue_failed existed only as an
// in-process integer.
func TestRenderExposesObservedValuesInPrometheusFormat(t *testing.T) {
	registry := NewMetricsRegistry()
	registry.ObserveSnapshot(MetricsSnapshot{
		TaskQueueFailed:      3,
		BuilderOutboxPending: 7,
		SelfRescueTxs: []SelfRescueMetric{
			{Role: "worker", DeadlineKind: "infer_receipt", TxKind: "MsgInferReceiptCommitOnlyTx", Accepted: true},
		},
	})

	out := registry.Render()
	for _, want := range []string{
		"# TYPE cortex_task_queue_failed gauge",
		"cortex_task_queue_failed 3",
		"cortex_builder_outbox_pending 7",
		`cortex_self_rescue_tx_total{deadline_kind="infer_receipt",role="worker"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Render() missing %q in:\n%s", want, out)
		}
	}
}

// A declared metric that has never been observed is reported as zero rather than
// omitted, so a missing series means the exporter is broken instead of the value
// being uninteresting.
func TestRenderEmitsDeclaredUnlabelledMetricsAtZero(t *testing.T) {
	out := NewMetricsRegistry().Render()
	if !strings.Contains(out, "cortex_task_queue_failed 0") {
		t.Fatalf("Render() = %q, want declared metrics present at zero", out)
	}
}
