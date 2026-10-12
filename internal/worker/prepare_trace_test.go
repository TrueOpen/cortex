package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/modelservice/vllmstub"
)

// runTracedGeneration drives one assignment end to end against a stubbed engine
// and returns the milestone lines an operator would read.
func runTracedGeneration(t *testing.T) *traceLines {
	t.Helper()
	const servedModel = "test/chat-prepare"
	manifest := testnetManifestBytes(t)
	tokens := []streamedToken{{7, []byte("hello")}, {8, []byte(" world")}, {248046, []byte("<|im_end|>")}}
	modelID := codec.HashBytes([]byte("huggingface:" + servedModel)).String()
	server := vllmstub.ChatStream{Frames: chatStreamFrames(tokens, "stop"), Models: []string{servedModel}}.Start(t)

	h := chatGenerationHarness(t, uint64(len(tokens)), modelID)
	enableEvidenceSchema(&h)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 1
	collected := &traceLines{}
	h.worker.cfg.Trace = collected.trace()

	event := finalizedTask()
	event.ModelID = modelID
	event.Input = []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	h.snapshotReader.seedFrom(event)

	service := modelservice.NewLocalService(server.URL, "chat-prepare", 1, 5*time.Second, time.Second)
	if err := service.BindModel(modelID, modelservice.LocalModelProvider, servedModel); err != nil {
		t.Fatal(err)
	}
	service.SetStreamInference(true)
	service.SetProfileResolver(staticProfileResolver(chainProfile(modelID, modelmanifest.Hash(manifest))))
	service.SetOutputDecodingSource(manifestBytesSource(manifest))
	h.worker.cfg.Model, h.worker.cfg.ModelServiceID = service, "chat-prepare"
	h.worker.cfg.TaskData = &observedTaskData{recordingTaskData: h.taskData}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := h.worker.HandleAssignmentFinalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	return collected
}

// TestPreparationBeforeTheEngineIsTraced covers the span that had no milestone
// at all: everything between the task being admitted and the generation request
// leaving this node. It is a run of chain reads and Builder stream opens, all
// serial, and on a node deployed away from the chain it has measured 6.7s --
// which had to be recovered by subtracting two different clocks, because
// nothing reported it.
func TestPreparationBeforeTheEngineIsTraced(t *testing.T) {
	collected := runTracedGeneration(t)
	line := collected.one(t, "infer_prepare_completed")
	for _, want := range []string{
		"total_ms=", "task_generation_ms=", "task_snapshot_ms=", "input_ms=", "output_stream_ms=", "builders=",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("infer_prepare_completed = %q, want it to carry %s", line, want)
		}
	}
}

// TestTaskFactsRereadsAreCounted makes the redundancy visible rather than
// leaving it to be rediscovered by reading the call graph. taskGeneration runs
// once in handleAssignmentFinalized and again in runInferenceAndPersistArtifacts
// with the same arguments, and each run re-reads immutable facts from the chain.
//
// The count is asserted exactly, so caching those facts has to come here and say
// so rather than silently changing what the milestone reports.
func TestTaskFactsRereadsAreCounted(t *testing.T) {
	line := runTracedGeneration(t).one(t, "infer_prepare_completed")
	if !strings.Contains(line, "task_generation_calls=2") {
		t.Fatalf("infer_prepare_completed = %q, want task_generation_calls=2", line)
	}
}

// TestFirstOutputLatenciesCarryBothClocks keeps the two first-output milestones
// from being read against the wrong start. since_infer_started_ms runs from the
// last instant before the request reaches the engine, so it deliberately
// excludes the preparation above -- and infer_completed publishes a field of the
// same name measured from before that preparation. Reading one as the other
// attributes the whole preparation to the engine, so both baselines are
// published side by side.
func TestFirstOutputLatenciesCarryBothClocks(t *testing.T) {
	collected := runTracedGeneration(t)
	for _, event := range []string{"output_first_delta", "output_first_frame"} {
		line := collected.one(t, event)
		for _, want := range []string{"since_infer_started_ms=", "since_prepare_started_ms="} {
			if !strings.Contains(line, want) {
				t.Fatalf("%s = %q, want it to carry %s", event, line, want)
			}
		}
	}
}
