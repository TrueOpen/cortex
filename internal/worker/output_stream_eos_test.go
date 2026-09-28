package worker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/modelservice/vllmstub"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// testnetManifestBytes is the testnet Qwen3.8-27B-FP8 manifest, whose
// output_decoding.eos_token_ids are [248044, 248046].
func testnetManifestBytes(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("../modelmanifest/testdata/testnet_qwen3.8-27b-fp8.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type manifestBytesSource []byte

func (m manifestBytesSource) OutputDecoding(_ context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
	return modelmanifest.VerifyOutputDecoding(m, profile.ManifestHash)
}

type staticProfileResolver chainclient.CurrentProfileSnapshot

func (r staticProfileResolver) ResolveLocalProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error) {
	return chainclient.CurrentProfileSnapshot(r), nil
}

// chainProfile is a registered profile the local model service executes, with
// the given manifest_hash and a 16-wide top-k.
func chainProfile(modelID string, manifestHash codec.Hash) chainclient.CurrentProfileSnapshot {
	profile := chainclient.CurrentProfileSnapshot{
		ModelID: modelID, ProfileVersion: chainclient.NewProfileVersion(1), ManifestHash: manifestHash[:],
		RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 16,
	}
	metrics := &profile.VerificationProfile.Metrics
	metrics.ComparedTopK, metrics.CompareLogprobDiff, metrics.CompareRankDelta, metrics.CompareTopKJaccard, metrics.CompareUnionJS = 16, true, true, true, true
	profile.VerificationProfile.IncludeGeneratedSpecialTokens = true
	profile.VerificationThresholds.PassMinFiniteCount = 1
	return profile
}

// chatTopLogprobs is a full 16-wide chat top_logprobs list led by tokenID.
func chatTopLogprobs(tokenID int) []map[string]any {
	row := []map[string]any{{"token": fmt.Sprintf("token_id:%d", tokenID), "logprob": -0.25}}
	for id := 900000; len(row) < 16; id++ {
		row = append(row, map[string]any{"token": fmt.Sprintf("token_id:%d", id), "logprob": -0.25 - float64(len(row))})
	}
	return row
}

type streamedToken struct {
	id    int
	bytes []byte
}

// chatStreamFrames is tokens as vLLM chat SSE frames, one token per frame,
// with the finish reason on the last token and a usage-only frame after it.
func chatStreamFrames(tokens []streamedToken, finish string) []any {
	frames := make([]any, 0, len(tokens)+1)
	for i, token := range tokens {
		byteValues := make([]int, len(token.bytes))
		for j, b := range token.bytes {
			byteValues[j] = int(b)
		}
		choice := map[string]any{
			"index": 0, "delta": map[string]any{"content": "ENGINE-TEXT"}, "token_ids": []int{token.id},
			"logprobs": map[string]any{"content": []any{map[string]any{
				"token": fmt.Sprintf("token_id:%d", token.id), "logprob": -0.25, "bytes": byteValues,
				"top_logprobs": chatTopLogprobs(token.id),
			}}},
		}
		if i == len(tokens)-1 {
			choice["finish_reason"] = finish
		}
		frame := map[string]any{"id": "chatcmpl-worker", "created": 1700000000, "model": "test/chat-eos", "choices": []any{choice}}
		if i == 0 {
			frame["prompt_token_ids"] = []int{42}
		}
		frames = append(frames, frame)
	}
	return append(frames, map[string]any{"id": "chatcmpl-worker", "created": 1700000000, "model": "test/chat-eos", "choices": []any{},
		"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": len(tokens), "total_tokens": 1 + len(tokens)}})
}

// chatGenerationHarness is generationBoundHarness for a CHAT task whose
// sampling parameters the chat endpoint accepts.
func chatGenerationHarness(t *testing.T, limit uint64, modelID string) harness {
	t.Helper()
	h := newHarness(t)
	h.worker.cfg.FakeOutput = false
	generation := nodewire.GenerationContext{
		ModelID: modelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: limit, MaxOutputDuration: 5000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, Seed: 7, RepetitionPenaltyPPM: 1000000}},
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
	h.worker.cfg.GenerationReader = generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
		return generation.Clone(), nil
	})
	return h
}

// TestWorkerStreamsExactlyTheCommittedOutput runs a chat task end to end
// through the local model service and the real SSE stub, with every streamed
// byte signed and sent as soon as it arrives (a one-byte minimum frame). The
// frames the Worker signs and sends to the Builders must concatenate to the
// committed output, which is also what the MMR root in the receipt and the
// signed Fin commit to. In particular a trailing EOS token is never sent: it is
// not part of the committed output, and a frame, once signed and sent, cannot
// be taken back.
func TestWorkerStreamsExactlyTheCommittedOutput(t *testing.T) {
	const servedModel = "test/chat-eos"
	manifest := testnetManifestBytes(t)
	eos := streamedToken{248046, []byte("<|im_end|>")}
	otherEOS := streamedToken{248044, []byte("<|endoftext|>")}
	hello := streamedToken{7, []byte("hello")}
	world := streamedToken{8, []byte(" world")}
	for _, test := range []struct {
		name   string
		tokens []streamedToken
		finish string
		want   string
	}{
		{"eos ending", []streamedToken{hello, world, eos}, "stop", "hello world"},
		{"other eos ending", []streamedToken{hello, world, otherEOS}, "stop", "hello world"},
		{"max tokens ending", []streamedToken{hello, world}, "length", "hello world"},
		{"eos in the middle", []streamedToken{hello, eos, world}, "length", "hello<|im_end|> world"},
		// U+4F60 U+597D cut so that each character spans two tokens, then an EOS.
		{"split multibyte then eos", []streamedToken{{20, []byte{0xE4, 0xBD}}, {21, []byte{0xA0, 0xE5, 0xA5}}, {22, []byte{0xBD}}, eos}, "stop", "\u4f60\u597d"},
	} {
		t.Run(test.name, func(t *testing.T) {
			modelID := codec.HashBytes([]byte("huggingface:" + servedModel)).String()
			server := vllmstub.ChatStream{Frames: chatStreamFrames(test.tokens, test.finish), Models: []string{servedModel}}.Start(t)

			h := chatGenerationHarness(t, uint64(len(test.tokens)), modelID)
			enableEvidenceSchema(&h)
			h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 1
			event := finalizedTask()
			event.ModelID = modelID
			event.Input = []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
			h.snapshotReader.seedFrom(event)

			service := modelservice.NewLocalService(server.URL, "chat-eos", 1, 5*time.Second, time.Second)
			if err := service.BindModel(modelID, modelservice.LocalModelProvider, servedModel); err != nil {
				t.Fatal(err)
			}
			service.SetStreamInference(true)
			service.SetProfileResolver(staticProfileResolver(chainProfile(modelID, modelmanifest.Hash(manifest))))
			service.SetOutputDecodingSource(manifestBytesSource(manifest))
			h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "chat-eos"
			data := &observedTaskData{recordingTaskData: h.taskData}
			h.worker.cfg.TaskData = data
			var sent [][]byte
			data.onSend = func(chunk builderclient.OutputChunk) error {
				sent = append(sent, append([]byte(nil), chunk.Text...))
				return nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := h.worker.HandleAssignmentFinalized(ctx, event)
			if err != nil {
				t.Fatal(err)
			}

			frames, err := h.persistence.OutputStreamFrames(ctx, event.TaskID)
			if err != nil {
				t.Fatal(err)
			}
			// More than one signed frame: the output really was streamed rather
			// than committed whole after the generation.
			if len(frames) < 2 {
				t.Fatalf("signed frames = %d, want the output streamed in several", len(frames))
			}
			var signed, lengths = []byte{}, []uint64{}
			for _, frame := range frames {
				signed = append(signed, frame.Text...)
				lengths = append(lengths, uint64(len(frame.Text)))
			}
			if string(signed) != test.want {
				t.Fatalf("signed frames concatenate to %q, want the committed output %q", signed, test.want)
			}
			if got := bytes.Join(sent, nil); !bytes.Equal(got, signed) {
				t.Fatalf("frames sent to the Builder %q differ from the signed frames %q", got, signed)
			}
			if test.finish == "stop" {
				for i, chunk := range sent {
					if bytes.Contains(chunk, test.tokens[len(test.tokens)-1].bytes) {
						t.Fatalf("frame %d sent to the Builder carries the trailing EOS: %q", i, chunk)
					}
				}
			}
			root, err := codec.OutputMMRRootFromLengths([]byte(test.want), lengths)
			if err != nil {
				t.Fatal(err)
			}
			receipt := result.TaskDataReceipt
			if receipt.OutputHash != root.String() || receipt.OutputSizeBytes != uint64(len(test.want)) || receipt.OutputLeafCount != uint64(len(frames)) {
				t.Fatalf("receipt output %s/%d bytes/%d leaves, want %s/%d/%d", receipt.OutputHash, receipt.OutputSizeBytes, receipt.OutputLeafCount, root, len(test.want), len(frames))
			}
			if receipt.GeneratedTokenCount != uint64(len(test.tokens)) {
				t.Fatalf("generated_token_count = %d, want %d: the EOS stays a generated token", receipt.GeneratedTokenCount, len(test.tokens))
			}
			wantFinish := nodewire.FinishReasonV1EosToken
			if test.finish == "length" {
				wantFinish = nodewire.FinishReasonV1MaxOutputTokens
			}
			if len(data.fins) != 1 || data.fins[0].FinishReason != wantFinish || frames[len(frames)-1].MMRRoot != root {
				t.Fatalf("Fin %+v over root %s, want %v over %s", data.fins, frames[len(frames)-1].MMRRoot, wantFinish, root)
			}
		})
	}
}
