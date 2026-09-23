package generationfixture

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// Bound serves one accepted task's generation context and matching Keeper facts.
type Bound struct {
	taskID       string
	acceptedHash codec.Hash
	generation   nodewire.GenerationContext
	digest       codec.Hash
}

func New(t testing.TB, taskID, modelID, acceptedDomain string) Bound {
	t.Helper()
	generation := nodewire.GenerationContext{
		ModelID: modelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 1024, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700,
				TopPPPM: 950000, RepetitionPenaltyPPM: 1000000}},
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return Bound{taskID: taskID, acceptedHash: codec.HashWithDomain(acceptedDomain, []byte(taskID)), generation: generation, digest: digest}
}

func (b Bound) TaskGeneration(_ context.Context, taskID string, acceptedHash codec.Hash) (nodewire.GenerationContext, error) {
	if taskID != b.taskID || acceptedHash != b.acceptedHash {
		return nodewire.GenerationContext{}, fmt.Errorf("generation fixture requested without matching accepted task identity")
	}
	return b.generation.Clone(), nil
}

func (b Bound) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	if taskID != b.taskID {
		return taskfacts.Facts{}, fmt.Errorf("generation fixture requested for a different task")
	}
	profileHash := codec.HashWithDomain("TEST_PROFILE_EXECUTION_SNAPSHOT_V1", []byte(b.taskID))
	return taskfacts.Facts{
		TaskID: taskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			ProfileExecutionSnapshotHash: chainclient.ProtoBytes32(profileHash[:]),
			AcceptedTaskHash:             chainclient.ProtoBytes32(b.acceptedHash[:]), GenerationParamsDigest: chainclient.ProtoBytes32(b.digest[:]),
		},
	}, nil
}

func Evidence(req modelservice.InferRequest, output []byte, count uint64) ([]byte, []byte, error) {
	tokenIDs := make([]int, count)
	tokens := make([]map[string]any, count)
	for i := range tokenIDs {
		tokenIDs[i] = 1000 + i
		tokens[i] = map[string]any{"token_id": tokenIDs[i], "logprob": -0.5, "rank": 1}
	}
	encodedIDs, err := json.Marshal(tokenIDs)
	if err != nil {
		return nil, nil, err
	}
	env := map[string]any{
		"generation_context": req.Generation, "model_id": req.ModelID, "profile_version": req.ProfileVersion,
		"output": string(output), "input_token_ids": []int{1}, "input_token_ids_hash": fmt.Sprint(codec.HashBytes([]byte("[1]"))),
		"generated_token_ids_hash": fmt.Sprint(codec.HashBytes(encodedIDs)), "generated_token_count": count,
		"finish_reason": "stop", "out_tokens": tokens,
	}
	trace, err := json.Marshal(env)
	if err != nil {
		return nil, nil, err
	}
	env["out_tokens"] = nil
	checkpoint, err := json.Marshal(env)
	if err != nil {
		return nil, nil, err
	}
	_, _, err = modelservice.ValidateGenerationEvidence(req.Generation, req.GenerationParamsDigest, output, trace, checkpoint)
	return trace, checkpoint, err
}
