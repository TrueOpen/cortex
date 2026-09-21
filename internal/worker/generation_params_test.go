package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
)

type generationReaderFunc func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error)

func (f generationReaderFunc) TaskGeneration(ctx context.Context, taskID string, hash codec.Hash) (nodewire.GenerationContext, error) {
	return f(ctx, taskID, hash)
}

type generationCaptureModel struct {
	modelservice.Client
	infer func(modelservice.InferRequest) (modelservice.InferResponse, error)
}

func (m generationCaptureModel) Infer(_ context.Context, req modelservice.InferRequest) (modelservice.InferResponse, error) {
	return m.infer(req)
}

func generationBoundHarness(t *testing.T, limit uint64, modelIDs ...string) (harness, nodewire.GenerationContext, codec.Hash) {
	t.Helper()
	h := newHarness(t)
	h.worker.cfg.FakeOutput = false
	generation := nodewire.GenerationContext{
		ModelID: finalizedTask().ModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: limit, MaxOutputDuration: 2000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700,
				TopPPPM: 950000, TopK: 20, Seed: 7, RepetitionPenaltyPPM: 1050000}},
	}
	if len(modelIDs) != 0 {
		generation.ModelID = modelIDs[0]
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.taskFacts.override = func(taskID string) (taskfacts.Facts, error) {
		facts := workerTestServedTaskFacts(taskID)
		facts.GenerationParamsDigest = chainclient.ProtoBytes32(digest[:])
		return facts, nil
	}
	h.worker.cfg.GenerationReader = generationReaderFunc(func(_ context.Context, taskID string, hash codec.Hash) (nodewire.GenerationContext, error) {
		if taskID != finalizedTask().TaskID || hash != codec.Hash(workerTestServedTaskFacts(taskID).AcceptedTaskHash) {
			return nodewire.GenerationContext{}, fmt.Errorf("generation reader called without accepted task identity")
		}
		return generation.Clone(), nil
	})
	return h, generation, digest
}

func TestRealWorkerForwardsFrozenGenerationParameters(t *testing.T) {
	requestDigests := map[codec.Hash]bool{}
	for _, limit := range []uint64{8, 128, 1024} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			h, _, digest := generationBoundHarness(t, limit)
			stop := errors.New("captured model request")
			h.worker.cfg.Model = generationCaptureModel{Client: h.model, infer: func(req modelservice.InferRequest) (modelservice.InferResponse, error) {
				if req.Generation == nil || req.Generation.Params.MaxOutputTokens != limit || !bytes.Equal(req.GenerationParamsDigest, digest[:]) {
					t.Fatalf("model request lost frozen generation: %+v", req)
				}
				if req.Generation.Params.DecodingParams.TemperatureMilli != 700 || req.Generation.Params.DecodingParams.Seed != 7 {
					t.Fatalf("model request replaced decoding params: %+v", req.Generation)
				}
				requestDigests[codec.Hash(req.RequestDigest)] = true
				return modelservice.InferResponse{}, stop
			}}
			_, err := h.worker.prepareOutput(context.Background(), finalizedTask())
			if !errors.Is(err, stop) {
				t.Fatalf("did not reach the parameter-bound model call: %v", err)
			}
		})
	}
	if len(requestDigests) != 3 {
		t.Fatalf("request identity failed to bind generation parameters: %d unique requests", len(requestDigests))
	}
}

func TestRealWorkerRejectsIgnoredGenerationAndExcessTokens(t *testing.T) {
	for name, response := range map[string]func(codec.Hash) modelservice.InferResponse{
		"missing digest": func(codec.Hash) modelservice.InferResponse { return modelservice.InferResponse{GeneratedTokenCount: 8} },
		"excess token count": func(digest codec.Hash) modelservice.InferResponse {
			return modelservice.InferResponse{GenerationParamsDigest: digest[:], GeneratedTokenCount: 9}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, digest := generationBoundHarness(t, 8)
			h.worker.cfg.Model = generationCaptureModel{Client: h.model, infer: func(modelservice.InferRequest) (modelservice.InferResponse, error) {
				return response(digest), nil
			}}
			_, err := h.worker.prepareOutput(context.Background(), finalizedTask())
			if err == nil || name == "missing digest" && !strings.Contains(err.Error(), "generation_params_digest") ||
				name == "excess token count" && !strings.Contains(err.Error(), "above order limit") {
				t.Fatalf("invalid model response did not fail at generation boundary: %v", err)
			}
			if len(h.persistence.receipts) != 0 {
				t.Fatal("signed receipt despite invalid model generation response")
			}
		})
	}
}

func TestRealWorkerRefusesMissingGenerationBeforeModelCall(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.FakeOutput = false
	_, err := h.worker.prepareOutput(context.Background(), finalizedTask())
	if err == nil || !strings.Contains(err.Error(), "generation") || h.model.InferCalls != 0 {
		t.Fatalf("err=%v, model calls=%d: missing frozen parameters must stop inference", err, h.model.InferCalls)
	}
}

func TestRealWorkerRefusesGenerationDigestMismatchBeforeModelCall(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.FakeOutput = false
	h.worker.cfg.GenerationReader = generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
		return nodewire.GenerationContext{
			ModelID: finalizedTask().ModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
			Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 8, MaxOutputDuration: 2000,
				DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}},
		}, nil
	})
	_, err := h.worker.prepareOutput(context.Background(), finalizedTask())
	if err == nil || !strings.Contains(err.Error(), "generation_params_digest") || h.model.InferCalls != 0 {
		t.Fatalf("err=%v, model calls=%d: mismatched parameters must stop inference", err, h.model.InferCalls)
	}
}
