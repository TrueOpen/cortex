package observability

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SingaXYZ/cortex/internal/modelregistry"
)

type observationSourceStub struct {
	rows []ModelObservation
	err  error
}

func (s observationSourceStub) ModelObservations(context.Context) ([]ModelObservation, error) {
	return append([]ModelObservation(nil), s.rows...), s.err
}

func TestProjectorReconstructsViewsFromAuthoritativeObservations(t *testing.T) {
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{})
	metrics := NewMetricsRegistry()
	source := observationSourceStub{rows: []ModelObservation{
		observation(t, "EventRewardMarked", "model-a", "llm_text_v1", map[string]any{
			"chain_state": modelregistry.ChainStateActive, "display_visibility": modelregistry.DisplayVisible,
			"verification_label": modelregistry.VerificationOfficial, "declared_support": true, "support_active": true,
			"treasury_denom": "utrueopen", "treasury_balance": 100, "max_reimbursement": 22,
		}),
		observation(t, "EventEmergencyFreezeAccepted", "model-a", "llm_text_v1", map[string]any{"reason": "VALUE_MISMATCH"}),
		observation(t, "EventTaskFailureClassUpdated", "model-a", "llm_text_v1", map[string]any{"failure_class": "WORKER_REVEAL_FAULT", "count": 3}),
		observation(t, "EventFaultRecorded", "model-a", "llm_text_v1", map[string]any{"builder_id": "builder-1", "fault_class": "delivery_miss"}),
	}}

	projector := Projector{Source: source, Registry: registry, Metrics: metrics}
	if err := projector.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	projection, err := registry.StatusProjection(context.Background(), modelregistry.StatusRequest{ModelID: "model-a"})
	if err != nil {
		t.Fatalf("StatusProjection returned error: %v", err)
	}
	if projection.ChainState != modelregistry.ChainStateActive || projection.Risk.Counts["WORKER_REVEAL_FAULT"] != 3 || projection.Builder.FaultedMessages != 1 {
		t.Fatalf("projection = %#v", projection)
	}
	if got := metrics.CounterValue("cortex_builder_fault_total", Labels{"builder_id": "builder-1", "fault_class": "delivery_miss"}); got != 1 {
		t.Fatalf("builder fault metric = %d, want 1", got)
	}
}

func TestProjectorRequiresAuthoritativeSource(t *testing.T) {
	err := (&Projector{Metrics: NewMetricsRegistry()}).RunOnce(context.Background())
	if !errors.Is(err, ErrObservationSourceRequired) {
		t.Fatalf("RunOnce error = %v, want ErrObservationSourceRequired", err)
	}
}

func TestProjectorPropagatesAuthoritativeSourceError(t *testing.T) {
	want := errors.New("keeper unavailable")
	err := (&Projector{Source: observationSourceStub{err: want}}).RunOnce(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("RunOnce error = %v, want %v", err, want)
	}
}

func TestInMemoryObservationSourceOwnsAnImmutableSnapshot(t *testing.T) {
	original := []ModelObservation{observation(t, "EventRewardMarked", "model-a", "1", map[string]any{"support_active": true})}
	source := NewInMemoryObservationSource(original)
	original[0].ModelID = "mutated"
	original[0].Payload[0] = 'x'

	first, err := source.ModelObservations(context.Background())
	if err != nil {
		t.Fatalf("ModelObservations error = %v", err)
	}
	if first[0].ModelID != "model-a" || !json.Valid(first[0].Payload) {
		t.Fatalf("source snapshot aliased caller input: %#v", first)
	}
	first[0].ModelID = "also-mutated"
	first[0].Payload[0] = 'x'
	second, _ := source.ModelObservations(context.Background())
	if second[0].ModelID != "model-a" || !json.Valid(second[0].Payload) {
		t.Fatalf("source snapshot aliased reader output: %#v", second)
	}
}

func TestInMemoryObservationSourceReplacesSnapshotAtomically(t *testing.T) {
	source := NewInMemoryObservationSource(nil)
	source.ReplaceModelObservations([]ModelObservation{{EventType: "EventRewardMarked", ModelID: "model-b", ProfileVersion: "2"}})
	rows, err := source.ModelObservations(context.Background())
	if err != nil || len(rows) != 1 || rows[0].ModelID != "model-b" {
		t.Fatalf("ModelObservations = %#v, %v", rows, err)
	}
}

func TestDecodeProjectionPayloadReadsKeeperEventAttributes(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"attributes": map[string]string{
		"chain_state": "ACTIVE", "declared_support": "true", "support_active": "true", "treasury_balance": "100",
	}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decodeProjectionPayload(raw)
	if err != nil {
		t.Fatalf("decodeProjectionPayload returned error: %v", err)
	}
	if payload.ChainState != "ACTIVE" || !payload.SupportActive || payload.TreasuryBalance != 100 {
		t.Fatalf("payload = %#v", payload)
	}
}

func observation(t *testing.T, eventType, modelID, profile string, payload map[string]any) ModelObservation {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return ModelObservation{EventType: eventType, ModelID: modelID, ProfileVersion: profile, Payload: body}
}
