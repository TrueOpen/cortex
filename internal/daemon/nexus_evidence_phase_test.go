package daemon

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// ADR-0023 decision 4 at the confirmer: the A-level call downloads the token
// bundle and nothing of the value bundle.
func TestNexusEvidenceConfirmerTokenPhaseFetchesNoValueObject(t *testing.T) {
	f := newEvidenceFixture(t)
	client := &evidenceTaskDataClient{objects: f.objects()}
	result, err := newEvidenceConfirmer(t, client).ConfirmWorkerTokenEvidence(context.Background(), f.Commitments)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.WorkerValues) != 0 || !bytes.Equal(result.GeneratedTokenIDs, f.GeneratedTokenIDs) || result.FinishReason != f.FinishReason {
		t.Fatalf("token phase result = %+v", result)
	}
	keys := f.keys()
	for _, fetch := range client.fetches {
		if fetch.Key == keys[0] || fetch.Key == keys[1] {
			t.Fatal("the token phase requested a B-level object")
		}
	}
	if len(client.fetches) != 4 {
		t.Fatalf("fetches = %d, want the token manifest and its three artifacts", len(client.fetches))
	}
}

func TestNexusEvidenceConfirmerValuePhaseFetchesOnlyTheValueBundle(t *testing.T) {
	f := newEvidenceFixture(t)
	client := &evidenceTaskDataClient{objects: f.objects()}
	values, err := newEvidenceConfirmer(t, client).ConfirmWorkerValueEvidence(context.Background(), f.Commitments)
	if err != nil || !bytes.Equal(values, f.WorkerValues) {
		t.Fatalf("value phase = %d bytes, %v", len(values), err)
	}
	keys := f.keys()
	if len(client.fetches) != 2 || client.fetches[0].Key != keys[0] || client.fetches[1].Key != keys[1] {
		t.Fatalf("fetches = %d, want only the value manifest and worker_values", len(client.fetches))
	}
	leaves, err := nodewire.DecodeWorkerValues(f.valueBinding(t), f.WorkerValues)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint32, len(leaves))
	for i := range leaves {
		ids[i] = leaves[i].TokenID
	}
	ids[0]++
	wrong, err := nodewire.EncodeTokenIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	commitments := f.Commitments
	commitments.GeneratedTokenIDs = wrong
	if _, err := newEvidenceConfirmer(t, &evidenceTaskDataClient{objects: f.objects()}).ConfirmWorkerValueEvidence(context.Background(), commitments); err == nil ||
		!strings.Contains(err.Error(), "not the generated token") {
		t.Fatalf("err = %v, want the leaf/token cross-check when A-level ids are supplied", err)
	}
}
