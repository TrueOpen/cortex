package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func TestWorkerUploadsFullOutputBeyond128TokensAndRecoversIt(t *testing.T) {
	const tokens = 512
	const servedModel = "test/generation-model"
	modelID := "hf-" + fmt.Sprint(codec.HashBytes([]byte("huggingface:"+servedModel)))
	output := strings.Repeat("\u5b8c\u6574\u8f93\u51fa ", tokens)
	ids := make([]int, tokens)
	logprobs := make([]float64, tokens)
	top := make([]map[string]float64, tokens)
	for i := range ids {
		ids[i], logprobs[i], top[i] = 7, -0.25, map[string]float64{"token_id:7": -0.25}
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": servedModel}}})
			return
		}
		if r.URL.Path != "/v1/completions" {
			http.NotFound(w, r)
			return
		}
		requests++
		var request struct {
			MaxTokens int `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.MaxTokens != 1024 {
			t.Errorf("engine request max_tokens=%d err=%v, want1024", request.MaxTokens, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{
			"text": output, "finish_reason": "stop", "prompt_token_ids": []int{42}, "token_ids": ids,
			"logprobs": map[string]any{"token_logprobs": logprobs, "top_logprobs": top},
		}}})
	}))
	defer server.Close()
	h, _, _ := generationBoundHarness(t, 1024, modelID)
	enableEvidenceSchema(&h)
	service := modelservice.NewLocalService(server.URL, "generation-test", 1, time.Minute, time.Second)
	service.SetStreamInference(false)
	h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "generation-test"
	event := finalizedTask()
	event.ModelID = modelID
	h.snapshotReader.seedFrom(event)
	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	for _, upload := range h.taskData.uploads {
		if upload.Key.Kind == builderclient.DataKindOutput {
			t.Fatal("output used the removed whole-object upload path")
		}
	}
	outputKey := builderclient.TaskDataKey{TaskHash: result.TaskDataReceipt.TaskHash, SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput, ContentHash: result.TaskDataReceipt.OutputHash}
	if len(h.taskData.UploadedOutputStreams) != 1 || !bytes.Equal(h.taskData.TaskData[outputKey], []byte(output)) {
		t.Fatal("Nexus stream did not contain the complete >128-token output")
	}
	root, err := codec.OutputMMRRootFromLengths([]byte(output), []uint64{uint64(len(output))})
	if err != nil {
		t.Fatal(err)
	}
	if result.TaskDataReceipt.GeneratedTokenCount != tokens || result.TaskDataReceipt.OutputSizeBytes != uint64(len(output)) || result.TaskDataReceipt.OutputHash != root.String() || result.TaskDataReceipt.OutputLeafCount != 1 {
		t.Fatalf("receipt does not commit the whole uploaded output: %+v", result.TaskDataReceipt)
	}
	// Recreate the Worker over the existing durable evidence and order reader.
	restarted := New(h.worker.cfg)
	if _, err := restarted.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("recover completed generation: %v", err)
	}
	if requests != 1 {
		t.Fatalf("recovery regenerated the output: %d engine requests", requests)
	}
	// Receipt reconstruction after an output checkpoint must retain the count
	// validated against the complete generation evidence.
	retained := h.persistence.evidence[:0]
	for _, record := range h.persistence.evidence {
		if record.Kind != "worker-infer-receipt" && record.Kind != "worker-result" {
			retained = append(retained, record)
		}
	}
	h.persistence.evidence = retained
	rebuilt, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err != nil || rebuilt.TaskDataReceipt.GeneratedTokenCount != tokens || requests != 1 {
		t.Fatalf("reconstructed receipt lost token count: count=%d requests=%d err=%v", rebuilt.TaskDataReceipt.GeneratedTokenCount, requests, err)
	}
	for i := range h.persistence.evidence {
		record := &h.persistence.evidence[i]
		if record.Kind != "worker-output-descriptor" {
			continue
		}
		original := append([]byte(nil), record.Data...)
		var descriptor outputDescriptor
		if err := json.Unmarshal(record.Data, &descriptor); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"token count", "finish reason"} {
			t.Run("retained "+field, func(t *testing.T) {
				changed := descriptor
				if field == "token count" {
					changed.GeneratedTokenCount--
				} else {
					changed.FinishReason = nodewire.FinishReasonV1Unspecified
				}
				record.Data, err = json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("accepted tampered retained %s: %v", field, err)
				}
			})
		}
		record.Data = original
	}
	stored, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, "worker-output")
	if err != nil || !bytes.Equal(stored, []byte(output)) {
		t.Fatalf("retained output was truncated or replaced: %v", err)
	}
	// Pre-upgrade or damaged evidence must not be reused under today's bound
	// parameters simply because an output/receipt checkpoint exists.
	for i := range h.persistence.evidence {
		if h.persistence.evidence[i].Kind != "worker-trace" {
			continue
		}
		var trace map[string]json.RawMessage
		if err := json.Unmarshal(h.persistence.evidence[i].Data, &trace); err != nil {
			t.Fatal(err)
		}
		delete(trace, "generation_context")
		h.persistence.evidence[i].Data, err = json.Marshal(trace)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("recovery accepted old evidence without generation binding: %v", err)
	}
}
