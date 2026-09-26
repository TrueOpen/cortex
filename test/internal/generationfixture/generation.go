package generationfixture

import (
	"context"
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
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

// FixtureTopK is how many ranked alternatives Material reports per position.
const FixtureTopK = 32

// Material builds a model service's token-id and position-value material for
// count generated tokens, validated against the request's generation context.
func Material(req modelservice.InferRequest, count uint64) ([]byte, []byte, error) {
	ids := modelservice.TokenIDs{Input: []uint32{1}, Generated: make([]uint32, count)}
	values := make([]metric.PositionValue, count)
	for i := range ids.Generated {
		id := uint32(1000 + i)
		ids.Generated[i] = id
		topK := make([]metric.TokenLogprob, FixtureTopK)
		topK[0] = metric.TokenLogprob{TokenID: id, Logprob: -0.5}
		for rank := 1; rank < FixtureTopK; rank++ {
			topK[rank] = metric.TokenLogprob{TokenID: 100000 + uint32(rank), Logprob: -0.5 - float64(rank)}
		}
		values[i] = metric.PositionValue{TokenID: id, Logprob: -0.5, Rank: 1, TopK: topK}
	}
	if _, err := modelservice.ValidateGenerationMaterial(req.Generation, req.GenerationParamsDigest, ids, values); err != nil {
		return nil, nil, err
	}
	tokenIDs, err := modelservice.EncodeTokenIDsArtifact(ids)
	if err != nil {
		return nil, nil, err
	}
	positionValues, err := modelservice.EncodePositionValuesArtifact(values)
	return tokenIDs, positionValues, err
}
