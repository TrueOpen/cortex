package worker

import (
	"context"
	"testing"
)

// InferResult has to carry back the output CID written to disk during inference.
//
// The daemon writes to the same write-once InferRecord.OutputCID from two places:
// the inference checkpoint writes descriptor.OutputCID, and the execution result
// writes it again once it comes back. Two different values are a permanent conflict
// - and the conflict bubbles all the way up to exit cortexd, after which a restart
// replays the same record and the node cannot come up.
//
// On the fake output path the two values necessarily differ: OutputRef is the
// address of the model artifact, OutputCID the address of the output package in the
// package store. So the result has to carry OutputCID separately.
func TestInferResultCarriesTheCheckpointedOutputCID(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)

	result, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}

	descriptor, err := New(h.worker.cfg).loadOutputDescriptor(context.Background(), event.TaskID)
	if err != nil {
		t.Fatalf("read back output descriptor: %v", err)
	}
	if descriptor.OutputCID == "" {
		t.Fatal("the descriptor has no OutputCID, so the test premise does not hold")
	}
	if result.OutputCID != descriptor.OutputCID {
		t.Fatalf("result.OutputCID = %q, the checkpoint wrote %q - two writers would collide on a write-once field",
			result.OutputCID, descriptor.OutputCID)
	}
}
