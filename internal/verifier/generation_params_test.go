package verifier

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

const generationTestTaskID = "41b9f86c8b73b7d740c641c07e7a4b9994a2563abff4bf0020b2189a2b70af63"

func generationTestContext() nodewire.GenerationContext {
	return nodewire.GenerationContext{
		ModelID: modelservice.FakeModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 64, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000,
				Seed: 9, RepetitionPenaltyPPM: 1000000, StopSequences: []string{"</s>"}, StopTokenIDs: []uint32{}}},
	}
}

// generationTestVerifier serves chainDigest as the task's generation_params_digest.
func generationTestVerifier(chainDigest codec.Hash, fake bool) *Verifier {
	return &Verifier{cfg: Config{FakeOutput: fake, TaskFacts: taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
		accepted := codec.HashBytes([]byte("accepted"))
		profile := codec.HashBytes([]byte("profile"))
		return taskfacts.Facts{TaskID: taskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash: chainclient.ProtoBytes32(accepted[:]), GenerationParamsDigest: chainclient.ProtoBytes32(chainDigest[:]),
			ProfileExecutionSnapshotHash: chainclient.ProtoBytes32(profile[:]),
		}}, nil
	})}}
}

// The prefill's parameters come only from the confirmed A-level artifact,
// checked against the chain and the receipt by hashing the received bytes.
func TestVerifierTakesGenerationOnlyFromTheConfirmedArtifact(t *testing.T) {
	want := generationTestContext()
	raw, err := want.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	digest := nodewire.GenerationParamsDigest(raw)
	state := TaskState{TaskID: generationTestTaskID, ModelID: want.ModelID, ProfileVersion: 1,
		ConfirmedInferReceipt: &builderclient.SignedInferReceipt{GenerationParamsDigest: digest.String()}}

	got, gotDigest, err := generationTestVerifier(digest, false).taskGeneration(context.Background(), state, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, want) || codec.Hash(gotDigest) != digest {
		t.Fatalf("generation = %+v digest %x, want the artifact's parameters and digest", *got, gotDigest)
	}

	other := codec.HashBytes([]byte("other params"))
	for name, run := range map[string]func() error{
		"missing artifact": func() error {
			_, _, err := generationTestVerifier(digest, false).taskGeneration(context.Background(), state, nil)
			return err
		},
		"chain digest differs": func() error {
			_, _, err := generationTestVerifier(other, false).taskGeneration(context.Background(), state, raw)
			return err
		},
		"receipt digest differs": func() error {
			mismatched := state
			mismatched.ConfirmedInferReceipt = &builderclient.SignedInferReceipt{GenerationParamsDigest: other.String()}
			_, _, err := generationTestVerifier(digest, false).taskGeneration(context.Background(), mismatched, raw)
			return err
		},
		"html escaped bytes": func() error {
			escaped := []byte(strings.Replace(string(raw), "</s>", `\u003c/s\u003e`, 1))
			_, _, err := generationTestVerifier(nodewire.GenerationParamsDigest(escaped), false).taskGeneration(context.Background(), state, escaped)
			return err
		},
		"other model": func() error {
			foreign := state
			foreign.ModelID = strings.Repeat("ab", 32)
			_, _, err := generationTestVerifier(digest, false).taskGeneration(context.Background(), foreign, raw)
			return err
		},
	} {
		if run() == nil {
			t.Fatalf("%s: generation accepted", name)
		}
	}

	// Only the fake/dev configuration may prefill without parameters.
	if got, _, err := generationTestVerifier(digest, true).taskGeneration(context.Background(), state, nil); err != nil || got != nil {
		t.Fatalf("fake verifier without artifact = %+v, %v", got, err)
	}
}
