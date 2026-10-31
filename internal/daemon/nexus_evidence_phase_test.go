package daemon

import (
	"bytes"
	"context"
	"testing"
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
}

// confirmBothBundles drives the two phase methods over one Builder the way
// the retired whole-set call did, value bundle first, so the tamper tests
// below exercise every check either phase makes. Production never calls both
// in one step (ADR-0023).
func confirmBothBundles(c *NexusEvidenceConfirmer, commitments EvidenceCommitments) (WorkerEvidence, error) {
	values, err := c.ConfirmWorkerValueEvidence(context.Background(), commitments)
	if err != nil {
		return WorkerEvidence{}, err
	}
	tokens, err := c.ConfirmWorkerTokenEvidence(context.Background(), commitments)
	if err != nil {
		return WorkerEvidence{}, err
	}
	tokens.WorkerValues = values
	return tokens, nil
}
