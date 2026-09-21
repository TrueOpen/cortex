package modelservice

import (
	"context"
	"sync"
	"testing"
)

func TestRequestScopedStreamObserversAreIsolated(t *testing.T) {
	server, _ := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	service := NewLocalService(server.URL, "scoped-stream", 4, 0, 0)
	global := &recordingObserver{}
	service.SetInferStreamObserver(global)
	observers := []*recordingObserver{{}, {}}
	requests := []InferRequest{
		boundLocalInferFixture(t, InferRequest{RequestID: "request-a", TaskID: "task-a", JobID: "job-a", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")}),
		boundLocalInferFixture(t, InferRequest{RequestID: "request-b", TaskID: "task-b", JobID: "job-b", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")}),
	}
	var wait sync.WaitGroup
	errors := make(chan error, len(requests))
	for i, req := range requests {
		wait.Add(1)
		go func(i int, req InferRequest) {
			defer wait.Done()
			_, err := service.Infer(WithInferStreamObserver(context.Background(), observers[i]), req)
			errors <- err
		}(i, req)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(global.frames) != 0 {
		t.Fatal("request frames leaked into global observer")
	}
	for i, observer := range observers {
		if len(observer.frames) < 2 {
			t.Fatal("request observer missed streaming frames")
		}
		for _, frame := range observer.frames {
			if frame.RequestID != requests[i].RequestID || frame.TaskID != requests[i].TaskID {
				t.Fatalf("request observer received another task's frame: %+v", frame)
			}
		}
	}
}
