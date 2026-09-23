package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

func generationEvidenceFixture(t *testing.T, h harness) (TaskState, nodewire.GenerationContext, codec.Hash) {
	t.Helper()
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.ConfirmedOutput = []byte("worker output")
	state.OutputPackage.OutputHash, _ = codec.OutputMMRRootFromLengths(state.ConfirmedOutput, state.ConfirmedOutputChunkLengths)
	state.OutputPackage.OutputRef, state.OutputPackage.TraceRef, state.OutputPackage.CheckpointRef = "", "", ""
	state.OutputPackage.FromTaskData = true
	state.ConfirmedFinishReason = nodewire.FinishReasonV1EosToken
	generation := nodewire.GenerationContext{
		ModelID: state.ModelID, ProfileVersion: state.ProfileVersion, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 1024, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, RepetitionPenaltyPPM: 1000000}},
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	trace := map[string]any{
		"generation_context": generation, "model_id": state.ModelID, "profile_version": fmt.Sprint(state.ProfileVersion),
		"output": string(state.ConfirmedOutput), "input_token_ids": []int{1},
		"input_token_ids_hash":     fmt.Sprint(codec.HashBytes([]byte("[1]"))),
		"generated_token_ids_hash": fmt.Sprint(codec.HashBytes([]byte("[7]"))),
		"generated_token_count":    1, "finish_reason": "stop",
		"out_tokens": []map[string]any{{"token_id": 7, "logprob": -0.25, "rank": 1, "top_logprobs": map[string]float64{"token_id:7": -0.25}}},
	}
	state.ConfirmedTrace, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	trace["out_tokens"] = nil
	state.ConfirmedCheckpoint, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.cfg.FakeOutput = false
	h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
		facts := servedTaskFacts(taskID)
		facts.GenerationParamsDigest = chainclient.ProtoBytes32(digest[:])
		return facts, nil
	})
	state.WorkerAddress = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	bindWorkerReceiptForTest(t, h.verifier, &state)
	return state, generation, digest
}

func TestVerifierUsesGenerationFromEvidenceWithoutOriginalOrder(t *testing.T) {
	h := newHarness(t)
	state, generation, digest := generationEvidenceFixture(t, h)
	result, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil || !result.Started {
		t.Fatalf("verify committed evidence: %v", err)
	}
	if len(h.model.verifyRequests) != 1 {
		t.Fatalf("verify calls=%d", len(h.model.verifyRequests))
	}
	req := h.model.verifyRequests[0]
	if req.Generation == nil || req.Generation.Params.MaxOutputTokens != generation.Params.MaxOutputTokens || !bytes.Equal(req.GenerationParamsDigest, digest[:]) {
		t.Fatalf("Verifier dropped committed generation context: %+v", req)
	}
}

func TestVerifierRejectsTamperedGenerationBeforeScoring(t *testing.T) {
	for _, name := range []string{"missing context", "wrong digest", "wrong model", "changed checkpoint", "missing committed finish reason"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			state, _, _ := generationEvidenceFixture(t, h)
			switch name {
			case "missing context":
				state.ConfirmedTrace = []byte(`{"output":"worker output"}`)
			case "wrong digest":
				h.verifier.cfg.TaskFacts = fixtureTaskFacts{}
			case "wrong model":
				state.ConfirmedTrace = bytes.ReplaceAll(state.ConfirmedTrace, []byte(state.ModelID), []byte("different-model"))
			case "changed checkpoint":
				state.ConfirmedCheckpoint = bytes.Replace(state.ConfirmedCheckpoint, []byte(`"max_output_tokens":1024`), []byte(`"max_output_tokens":8`), 1)
			case "missing committed finish reason":
				state.ConfirmedFinishReason = nodewire.FinishReasonV1Unspecified
			}
			_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
			if err == nil || h.model.VerifyCalls != 0 {
				t.Fatalf("err=%v verify calls=%d", err, h.model.VerifyCalls)
			}
			if !strings.Contains(err.Error(), "generation") && !strings.Contains(err.Error(), "model/profile") {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

func TestVerifierRejectsCommittedEOSWithLengthEvidenceBeforeScoring(t *testing.T) {
	h := newHarness(t)
	state, generation, _ := generationEvidenceFixture(t, h)
	generation.Params.MaxOutputTokens = 1
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []*[]byte{&state.ConfirmedTrace, &state.ConfirmedCheckpoint} {
		var env map[string]any
		if err := json.Unmarshal(*artifact, &env); err != nil {
			t.Fatal(err)
		}
		env["generation_context"], env["finish_reason"] = generation, "length"
		*artifact, err = json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
	}
	h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
		facts := servedTaskFacts(taskID)
		facts.GenerationParamsDigest = chainclient.ProtoBytes32(digest[:])
		return facts, nil
	})
	_, reason, err := modelservice.ValidateGenerationEvidence(&generation, digest[:], state.ConfirmedOutput, state.ConfirmedTrace, state.ConfirmedCheckpoint)
	if err != nil || reason != nodewire.FinishReasonV1MaxOutputTokens {
		t.Fatalf("fixture must be valid length-at-limit evidence: reason=%v err=%v", reason, err)
	}
	_, err = h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || h.model.VerifyCalls != 0 {
		t.Fatalf("committed EOS and length evidence must refuse before scoring: err=%v calls=%d", err, h.model.VerifyCalls)
	}
}
