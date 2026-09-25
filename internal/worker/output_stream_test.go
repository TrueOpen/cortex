package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
)

type observedTaskData struct {
	*recordingTaskData
	onSend      func(builderclient.OutputChunk) error
	finishError error
	onFinish    func() error
	requests    []builderclient.OutputStreamRequest
	fins        []builderclient.OutputFin
}

func (c *observedTaskData) OpenTaskOutputStream(ctx context.Context, endpoint string, request builderclient.OutputStreamRequest) (builderclient.TaskOutputStream, error) {
	c.requests = append(c.requests, request)
	stream, err := c.recordingTaskData.OpenTaskOutputStream(ctx, endpoint, request)
	if err != nil {
		return nil, err
	}
	return &observedOutputStream{TaskOutputStream: stream, client: c}, nil
}

type observedOutputStream struct {
	builderclient.TaskOutputStream
	client *observedTaskData
}

func TestOutputFinIsSignedOncePersistedAndReused(t *testing.T) {
	for _, reason := range nodewire.SuccessfulFinishReasonsV1() {
		t.Run(fmt.Sprintf("reason-%d", reason), func(t *testing.T) {
			h := newHarness(t)
			randomized := &randomizedWorkerSigner{
				private: h.signer.private,
				address: h.worker.cfg.SignerAddress,
				keyRef:  h.worker.cfg.SignerKeyRef,
			}
			h.worker.cfg.Signer = randomized
			taskHash := codec.HashBytes([]byte("fin-task"))
			root := codec.HashBytes([]byte("fin-root"))
			first, err := h.worker.loadOrCreateOutputFin(context.Background(), "task-fin", taskHash, 7, root, reason)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := nodewire.OutputFinSigningDigest(h.worker.cfg.ChainID, taskHash[:], 7, root[:], reason)
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, digest, first.WorkerSignature); err != nil {
				t.Fatal(err)
			}
			second, err := h.worker.loadOrCreateOutputFin(context.Background(), "task-fin", taskHash, 7, root, reason)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first.WorkerSignature, second.WorkerSignature) || randomized.countDigest(digest) != 1 {
				t.Fatal("Fin retry was re-signed instead of replaying the persisted signature")
			}
			stored, err := h.persistence.ReadArtifact(context.Background(), "task-fin", OutputStreamFinKind)
			if err != nil || len(stored) == 0 {
				t.Fatalf("persisted Fin missing: %v", err)
			}
		})
	}
}

func TestOutputFinRecoveryRejectsTampering(t *testing.T) {
	for _, field := range []string{"task hash", "final seq", "root", "reason", "signature"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			taskHash := codec.HashBytes([]byte("fin-task"))
			root := codec.HashBytes([]byte("fin-root"))
			if _, err := h.worker.loadOrCreateOutputFin(context.Background(), "task-fin", taskHash, 7, root, nodewire.FinishReasonV1EosToken); err != nil {
				t.Fatal(err)
			}
			for index := range h.persistence.evidence {
				record := &h.persistence.evidence[index]
				if record.TaskID != "task-fin" || record.Kind != OutputStreamFinKind {
					continue
				}
				var fin signedOutputFin
				if err := json.Unmarshal(record.Data, &fin); err != nil {
					t.Fatal(err)
				}
				switch field {
				case "task hash":
					fin.TaskHash[0] ^= 1
				case "final seq":
					fin.FinalSeq++
				case "root":
					fin.OutputMMRRoot[0] ^= 1
				case "reason":
					fin.FinishReason = nodewire.FinishReasonV1StopSequence
				case "signature":
					fin.WorkerSignature[0] ^= 1
				}
				record.Data, _ = json.Marshal(fin)
			}
			if _, err := h.worker.loadOrCreateOutputFin(context.Background(), "task-fin", taskHash, 7, root, nodewire.FinishReasonV1EosToken); err == nil {
				t.Fatalf("tampered %s accepted", field)
			}
		})
	}
}

func (s *observedOutputStream) SendChunk(chunk builderclient.OutputChunk) error {
	if s.client.onSend != nil {
		if err := s.client.onSend(chunk); err != nil {
			return err
		}
	}
	return s.TaskOutputStream.SendChunk(chunk)
}

func (s *observedOutputStream) Finish(fin builderclient.OutputFin) (builderclient.OutputStreamResult, error) {
	fin.WorkerSignature = append([]byte(nil), fin.WorkerSignature...)
	s.client.fins = append(s.client.fins, fin)
	if s.client.onFinish != nil {
		if err := s.client.onFinish(); err != nil {
			return builderclient.OutputStreamResult{}, err
		}
	}
	if s.client.finishError != nil {
		return builderclient.OutputStreamResult{}, s.client.finishError
	}
	return s.TaskOutputStream.Finish(fin)
}

func TestWorkerStreamsPersistedSignedPrefixBeforeGenerationCompletes(t *testing.T) {
	const servedModel = "test/live-stream"
	const first = "first-frame-text"
	const tail = "tail"
	modelID := "hf-" + codec.HashBytes([]byte("huggingface:"+servedModel)).String()
	prefixSent := make(chan struct{})
	var generationComplete atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": servedModel}}})
			return
		}
		if request.URL.Path != "/v1/completions" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		writeFrame := func(text string, token int, final bool) {
			var finish any
			if final {
				finish = "stop"
			}
			payload, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
				"text": text, "finish_reason": finish, "prompt_token_ids": []int{42}, "token_ids": []int{token},
				"logprobs": map[string]any{"token_logprobs": []float64{-0.25}, "top_logprobs": []map[string]float64{{fmt.Sprintf("token_id:%d", token): -0.25}}},
			}}})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			w.(http.Flusher).Flush()
		}
		writeFrame(first, 7, false)
		select {
		case <-prefixSent:
		case <-request.Context().Done():
			return
		}
		writeFrame(tail, 8, true)
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		generationComplete.Store(true)
	}))
	defer server.Close()
	h, _, _ := generationBoundHarness(t, 8, modelID)
	enableEvidenceSchema(&h)
	event := finalizedTask()
	event.ModelID = modelID
	h.snapshotReader.seedFrom(event)
	service := modelservice.NewLocalService(server.URL, "live-stream", 1, 5*time.Second, time.Second)
	service.SetStreamInference(true)
	h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "live-stream"
	data := &observedTaskData{recordingTaskData: h.taskData}
	h.worker.cfg.TaskData = data
	var firstSent sync.Once
	data.onSend = func(chunk builderclient.OutputChunk) error {
		stored, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, OutputStreamFrameKind(chunk.Seq))
		if err != nil {
			return fmt.Errorf("sent frame before persistence: %w", err)
		}
		var durable builderclient.OutputChunk
		if err := json.Unmarshal(stored, &durable); err != nil {
			return err
		}
		if !reflect.DeepEqual(durable, chunk) {
			return errors.New("sent frame differs from durable bytes")
		}
		facts := workerTestServedTaskFacts(event.TaskID)
		digest, err := nodewire.OutputChunkSigningDigest("chain-A", facts.AcceptedTaskHash, chunk.Seq, chunk.MMRRoot[:])
		if err != nil {
			return err
		}
		if err := signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, digest, chunk.WorkerSignature); err != nil {
			return err
		}
		if chunk.Seq == 0 {
			if generationComplete.Load() {
				return errors.New("first signed frame arrived after generation completed")
			}
			firstSent.Do(func() { close(prefixSent) })
		}
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
	if len(frames) != 2 || string(frames[0].Text) != first || string(frames[1].Text) != tail || result.TaskDataReceipt.OutputLeafCount != 2 || result.TaskDataReceipt.GeneratedTokenCount != 2 {
		t.Fatalf("frames=%+v receipt=%+v", frames, result.TaskDataReceipt)
	}
	if len(data.fins) != 1 || data.fins[0].FinishReason != nodewire.FinishReasonV1EosToken {
		t.Fatalf("signed Fin=%+v", data.fins)
	}
	finFacts := workerTestServedTaskFacts(event.TaskID)
	finDigest, err := nodewire.OutputFinSigningDigest(h.worker.cfg.ChainID, finFacts.AcceptedTaskHash, frames[1].Seq, frames[1].MMRRoot[:], data.fins[0].FinishReason)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, finDigest, data.fins[0].WorkerSignature); err != nil {
		t.Fatal(err)
	}
	if len(h.builder.ValidatedPackages) != 1 || !reflect.DeepEqual(h.builder.ValidatedPackages[0].OutputChunkLengths, []uint64{uint64(len(first)), uint64(len(tail))}) {
		t.Fatal("output package lost exact streamed frame lengths")
	}
}

// TestWorkerFinFailureReplaysOriginalSignedFramesWithoutRegeneration also pins
// the ADR-0027 ordering: the Fin is delivered BEFORE the receipt is relayed, so
// a receipt in a Builder's hands always has a Fin behind it.
//
// This test used to assert the opposite -- "Fin failure must allow receipt relay
// while holding object finalization" -- which left a refused Fin with the
// receipt already relayed, a state nothing downstream can tell apart from a
// Worker that never finished.
func TestWorkerFinFailureReplaysOriginalSignedFramesWithoutRegeneration(t *testing.T) {
	h := newHarness(t)
	enableEvidenceSchema(&h)
	data := &observedTaskData{recordingTaskData: h.taskData, finishError: builderclient.Retryable(errors.New("Fin unavailable"))}
	data.onFinish = func() error {
		if len(h.taskData.relays) != 0 {
			return errors.New("receipt was relayed before the Fin")
		}
		return nil
	}
	h.worker.cfg.TaskData = data
	event := finalizedTask()
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("Fin failure=%v", err)
	}
	// Nothing reached the Builder: the Fin is what failed, and the receipt is
	// behind it. The retry below is what delivers both.
	if len(h.taskData.relays) != 0 || len(h.taskData.uploads) != 0 || pendingOutputAvailable(h.persistence.outbox) {
		t.Fatal("a refused Fin must hold the receipt back, not leave it relayed")
	}
	frames, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
	if err != nil || len(frames) == 0 {
		t.Fatalf("signed journal missing: %v", err)
	}
	before, _ := json.Marshal(frames)
	data.finishError = nil
	result, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if h.model.InferCalls != 1 || len(data.requests) < 2 {
		t.Fatalf("model calls=%d stream attempts=%d", h.model.InferCalls, len(data.requests))
	}
	replayed, _ := json.Marshal(data.requests[len(data.requests)-1].ReplayChunks)
	if !bytes.Equal(before, replayed) {
		t.Fatal("resume changed signed frame bytes")
	}
	if result.TaskDataReceipt.OutputLeafCount != uint64(len(frames)) || len(h.persistence.confirmations) != 2 {
		t.Fatal("resumed finalization lost receipt or storage facts")
	}
	// One relay, not two: the first attempt never got past the Fin, so the
	// receipt went out exactly once, on the retry that delivered the Fin.
	if len(h.taskData.relays) != 1 {
		t.Fatalf("receipt relays=%d, want exactly the one the successful retry sent", len(h.taskData.relays))
	}
	if len(data.fins) != 2 || !reflect.DeepEqual(data.fins[0], data.fins[1]) {
		t.Fatal("Fin retry changed the persisted terminal frame")
	}
}

func TestWorkerRecoveryRejectsTamperedSignedFrames(t *testing.T) {
	for _, change := range []string{"text", "sequence", "signature", "attachment"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			receipt := h.seedPreparedOutput(t, event)
			for index := range h.persistence.evidence {
				record := &h.persistence.evidence[index]
				if !strings.HasPrefix(record.Kind, OutputStreamFramePrefix) {
					continue
				}
				var chunk builderclient.OutputChunk
				if err := json.Unmarshal(record.Data, &chunk); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "text":
					chunk.Text[0] ^= 1
				case "sequence":
					chunk.Seq++
				case "signature":
					chunk.WorkerSignature[0] ^= 1
				case "attachment":
					chunk.Attachment = []byte{1}
				}
				record.Data, _ = json.Marshal(chunk)
			}
			if err := h.worker.ensureOutputStreamStored(context.Background(), event, receipt); err == nil {
				t.Fatal("accepted tampered signed frame journal")
			}
		})
	}
}

func TestOutputStreamRecorderEnforcesLimitsBeforeSigningExtraFrames(t *testing.T) {
	for _, test := range []struct {
		name       string
		maxBytes   uint64
		maxLeaves  uint64
		chunks     []string
		wantFrames int
	}{
		{"byte limit", 4, 100, []string{"too-long"}, 0},
		{"leaf limit", 100, 1, []string{"first-frame-text", "second-frame-now"}, 1},
		{"invalid UTF-8", 100, 100, []string{string([]byte{0xff})}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			h.worker.cfg.MaxOutputBytes = test.maxBytes
			h.worker.cfg.StreamLimits.MaxOutputMMRLeaves = test.maxLeaves
			event := finalizedTask()
			recorder, err := h.worker.newOutputRecorder(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			defer recorder.stream.Close()
			for _, text := range test.chunks {
				err = recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: text})
			}
			if err == nil {
				t.Fatal("accepted stream outside protocol limits")
			}
			frames, readErr := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
			if readErr != nil || len(frames) != test.wantFrames {
				t.Fatalf("frames=%d err=%v", len(frames), readErr)
			}
			if len(h.taskData.relays) != 0 || pendingOutputAvailable(h.persistence.outbox) {
				t.Fatal("invalid stream released availability")
			}
		})
	}
}

func TestWorkerFinalizesAndRecoversEmptyOutputAsOneSignedLeaf(t *testing.T) {
	const servedModel = "test/empty-output"
	modelID := "hf-" + codec.HashBytes([]byte("huggingface:"+servedModel)).String()
	var inferCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": servedModel}}})
			return
		}
		if request.URL.Path != "/v1/completions" {
			http.NotFound(w, request)
			return
		}
		inferCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{
			"text": "", "finish_reason": "stop", "prompt_token_ids": []int{42}, "token_ids": []int{},
			"logprobs": map[string]any{"token_logprobs": []float64{}, "top_logprobs": []map[string]float64{}},
		}}})
	}))
	defer server.Close()
	h, _, _ := generationBoundHarness(t, 8, modelID)
	enableEvidenceSchema(&h)
	event := finalizedTask()
	event.ModelID = modelID
	h.snapshotReader.seedFrom(event)
	service := modelservice.NewLocalService(server.URL, "empty-output", 1, 5*time.Second, time.Second)
	service.SetStreamInference(false)
	h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "empty-output"
	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
	if err != nil || len(frames) != 1 || frames[0].Seq != 0 || len(frames[0].Text) != 0 || len(frames[0].WorkerSignature) != 64 {
		t.Fatalf("empty output journal=%+v error=%v", frames, err)
	}
	if result.TaskDataReceipt.OutputSizeBytes != 0 || result.TaskDataReceipt.GeneratedTokenCount != 0 || result.TaskDataReceipt.OutputLeafCount != 1 || result.TaskDataReceipt.OutputHash != frames[0].MMRRoot.String() {
		t.Fatalf("empty receipt=%+v", result.TaskDataReceipt)
	}
	if len(h.persistence.confirmations) != 2 || len(h.taskData.FinalizedTaskResults) != 1 {
		t.Fatal("empty output was not finalized")
	}
	recovered, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if inferCalls.Load() != 1 || !reflect.DeepEqual(recovered.TaskDataReceipt, result.TaskDataReceipt) || len(h.taskData.FinalizedTaskResults) != 1 {
		t.Fatal("empty-output recovery reran generation or changed finalized receipt")
	}
}

type transientArtifactModel struct {
	modelservice.Client
	kind   string
	failed bool
}

func (m *transientArtifactModel) FetchArtifact(ctx context.Context, request modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	if !m.failed && strings.HasPrefix(request.RequestID, "fetch-"+m.kind+"-") {
		m.failed = true
		return modelservice.Artifact{}, builderclient.Retryable(errors.New("artifact temporarily unavailable"))
	}
	return m.Client.FetchArtifact(ctx, request)
}

func TestWorkerRetriesCompletedGenerationArtifactReadsWithoutResigningPrefix(t *testing.T) {
	for _, kind := range []string{"output", "trace", "checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t)
			enableEvidenceSchema(&h)
			h.worker.cfg.Model = &transientArtifactModel{Client: h.model, kind: kind}
			event := finalizedTask()
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil || !builderclient.IsRetryable(err) {
				t.Fatalf("initial fetch error=%v", err)
			}
			frames, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
			if err != nil || len(frames) == 0 {
				t.Fatalf("initial signed prefix missing: %v", err)
			}
			original, _ := json.Marshal(frames)
			if _, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, "worker-model-result"); err != nil {
				t.Fatal("completed model response was not checkpointed")
			}
			if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			recovered, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(recovered)
			if h.model.InferCalls != 1 || !bytes.Equal(original, after) || len(h.persistence.confirmations) != 2 {
				t.Fatal("artifact retry reran generation or changed signed frames")
			}
		})
	}
}

type interruptedModel struct{ modelservice.Client }

func (m interruptedModel) Infer(ctx context.Context, request modelservice.InferRequest) (modelservice.InferResponse, error) {
	response, err := m.Client.Infer(ctx, request)
	if err != nil {
		return response, err
	}
	return response, errors.New("generation interrupted before successful response")
}

func TestWorkerNeverRegeneratesInterruptedSignedOutput(t *testing.T) {
	h := newHarness(t)
	enableEvidenceSchema(&h)
	h.worker.cfg.Model = interruptedModel{Client: h.model}
	event := finalizedTask()
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatal("interrupted generation accepted")
	}
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err == nil || !strings.Contains(err.Error(), "signing output frames") {
		t.Fatalf("interrupted prefix retry=%v", err)
	}
	if h.model.InferCalls != 1 || len(h.taskData.relays) != 0 {
		t.Fatal("interrupted signed output was regenerated or relayed")
	}
}

func TestOutputRecorderRecoversCompletedUnsignedTail(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"first-frame-text", "tail"} {
		if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: text}); err != nil {
			t.Fatal(err)
		}
	}
	original, _ := json.Marshal(recorder.frames[0])
	saved := completedModelInference{TaskHash: recorder.taskHash, FrameCount: uint64(len(recorder.frames)), Pending: recorder.pending, ObservedBytes: recorder.total}
	_ = recorder.stream.Close()
	restored, err := h.worker.resumeOutputRecorder(context.Background(), event, saved)
	if err != nil {
		t.Fatal(err)
	}
	lengths, err := restored.finish(context.Background(), []byte("first-frame-texttail"))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(restored.frames[0])
	if !bytes.Equal(original, after) || !reflect.DeepEqual(lengths, []uint64{16, 4}) || string(restored.frames[1].Text) != "tail" {
		t.Fatal("completed-generation recovery changed the signed prefix or tail boundary")
	}
}

type failingSecondFrameSigner struct {
	signer.DigestSigner
	calls int
}

func (s *failingSecondFrameSigner) SignDigest(ctx context.Context, request signer.DigestRequest) ([]byte, error) {
	s.calls++
	if s.calls == 2 {
		return nil, signer.ErrRetryable
	}
	return s.DigestSigner.SignDigest(ctx, request)
}

func TestWorkerCompletesGenerationAfterDeferredFrameFailureAndResumesSuffix(t *testing.T) {
	for _, failure := range []string{"signer", "journal"} {
		t.Run(failure, func(t *testing.T) {
			const servedModel = "test/deferred-frame"
			parts := []string{"first-frame-text", "second-frame-two", "third-frame-tail"}
			modelID := "hf-" + codec.HashBytes([]byte("huggingface:"+servedModel)).String()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/v1/models" {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": servedModel}}})
					return
				}
				if request.URL.Path != "/v1/completions" {
					http.NotFound(w, request)
					return
				}
				calls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				for index, part := range parts {
					var finish any
					if index == len(parts)-1 {
						finish = "stop"
					}
					payload, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
						"text": part, "finish_reason": finish, "prompt_token_ids": []int{42}, "token_ids": []int{index + 7},
						"logprobs": map[string]any{"token_logprobs": []float64{-0.25}, "top_logprobs": []map[string]float64{{fmt.Sprintf("token_id:%d", index+7): -0.25}}},
					}}})
					_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
					w.(http.Flusher).Flush()
				}
				_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer server.Close()
			h, _, _ := generationBoundHarness(t, 8, modelID)
			enableEvidenceSchema(&h)
			event := finalizedTask()
			event.ModelID = modelID
			h.snapshotReader.seedFrom(event)
			service := modelservice.NewLocalService(server.URL, "deferred-frame", 1, 5*time.Second, time.Second)
			service.SetStreamInference(true)
			h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "deferred-frame"
			if failure == "signer" {
				h.worker.cfg.Signer = &failingSecondFrameSigner{DigestSigner: h.signer}
			} else {
				h.persistence.evidenceWriteError = func(record EvidenceRecord) error {
					if record.Kind == OutputStreamFrameKind(1) {
						return errors.New("journal temporarily unavailable")
					}
					return nil
				}
			}
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
				t.Fatal("deferred frame failure was not reported")
			}
			frames, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
			if err != nil || len(frames) != 1 {
				t.Fatalf("failed emission advanced journal: %+v %v", frames, err)
			}
			original, _ := json.Marshal(frames[0])
			completedBytes, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, "worker-model-result")
			if err != nil {
				t.Fatal(err)
			}
			var completed completedModelInference
			if err := json.Unmarshal(completedBytes, &completed); err != nil {
				t.Fatal(err)
			}
			if completed.FrameCount != 1 || string(completed.Pending) != parts[1]+parts[2] || completed.ObservedBytes != uint64(len(strings.Join(parts, ""))) {
				t.Fatalf("completed generation lost unsigned suffix: %+v", completed)
			}
			h.worker.cfg.Signer = h.signer
			h.persistence.evidenceWriteError = nil
			result, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			resumed, err := h.persistence.OutputStreamFrames(context.Background(), event.TaskID)
			if err != nil || len(resumed) != 2 {
				t.Fatalf("resumed frames=%+v error=%v", resumed, err)
			}
			after, _ := json.Marshal(resumed[0])
			if calls.Load() != 1 || !bytes.Equal(original, after) || string(resumed[1].Text) != parts[1]+parts[2] || result.TaskDataReceipt.OutputLeafCount != 2 {
				t.Fatal("recovery regenerated or changed signed output")
			}
		})
	}
}
