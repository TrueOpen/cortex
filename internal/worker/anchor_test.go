package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const workerTestAnchorRef = "anchor-commit-ref"

var workerTestAnchorCommit = []byte(`{"request_id":"cmpl-worker","roots":["ab"]}`)

// anchorModel records whether Infer was asked for the anchor commitment and,
// when serve is set, answers like an engine with the anchor sidecar.
type anchorModel struct {
	modelservice.Client
	serve    bool
	requests []modelservice.InferRequest
}

func (m *anchorModel) Infer(ctx context.Context, req modelservice.InferRequest) (modelservice.InferResponse, error) {
	m.requests = append(m.requests, req)
	resp, err := m.Client.Infer(ctx, req)
	if err == nil && req.RequireAnchorCommit && m.serve {
		resp.AnchorCommitRef = workerTestAnchorRef
	}
	return resp, err
}

func (m *anchorModel) FetchArtifact(ctx context.Context, req modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	if req.Ref == workerTestAnchorRef {
		return modelservice.Artifact{Ref: req.Ref, Data: append([]byte(nil), workerTestAnchorCommit...)}, nil
	}
	return m.Client.FetchArtifact(ctx, req)
}

func anchorHarness(t *testing.T, serve, requireAnchor bool) (harness, *anchorModel) {
	t.Helper()
	var model *anchorModel
	h := newHarnessWithConfig(t, func(cfg *Config) {
		model = &anchorModel{Client: cfg.Model, serve: serve}
		cfg.Model = model
	})
	enableEvidenceSchema(&h)
	if requireAnchor {
		h.worker.cfg.ProfileEvidenceRequirements = append(builderclient.WorkerEvidenceRequirementsV3(), builderclient.WorkerAnchorEvidenceRequirementV1())
	}
	return h, model
}

// Under a Profile requiring WORKER_ANCHOR_OPENING the Worker asks the model
// service for the commitment, publishes it as a third bundle and signs a
// receipt whose third commitment covers exactly those bytes.
func TestWorkerCommitsTheAnchorBundleWhenTheProfileRequiresIt(t *testing.T) {
	h, model := anchorHarness(t, true, true)
	event := finalizedTask()
	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.requests) != 1 || !model.requests[0].RequireAnchorCommit {
		t.Fatalf("infer requests %+v, want one asking for the anchor commitment", model.requests)
	}
	// The seed facts the engine binds its sampler to: the node's chain, the
	// task and the order's own seed, none of them chosen here.
	if got := model.requests[0]; h.worker.cfg.ChainID == "" || got.ChainID != h.worker.cfg.ChainID || got.TaskID != event.TaskID || got.Generation == nil {
		t.Fatalf("infer request chain %q task %q generation %v, want chain %q task %q and the order's generation",
			got.ChainID, got.TaskID, got.Generation, h.worker.cfg.ChainID, event.TaskID)
	}
	commitments := result.TaskDataReceipt.RequiredEvidenceCommitments
	if len(commitments) != 3 || commitments[2].EvidenceKind != nodewire.EvidenceKindWorkerAnchorOpening ||
		commitments[2].EncodedSizeBytes != uint64(len(workerTestAnchorCommit)) {
		t.Fatalf("receipt commitments %+v, want the anchor commitment third", commitments)
	}
	_, stored, err := h.persistence.WorkerBundle(context.Background(), event.TaskID, nodewire.EvidenceKindWorkerAnchorOpening)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored[builderclient.EvidenceArtifactAnchorCommit]) != string(workerTestAnchorCommit) {
		t.Fatalf("anchor bundle holds %q", stored[builderclient.EvidenceArtifactAnchorCommit])
	}
	uploadedAnchor := false
	for _, upload := range h.taskData.uploads {
		if upload.Key.EvidenceKind == nodewire.EvidenceKindWorkerAnchorOpening && upload.Key.ContentHash == codec.HashBytes(workerTestAnchorCommit).String() {
			uploadedAnchor = true
		}
	}
	if !uploadedAnchor {
		t.Fatal("the anchor_commit artifact was not uploaded")
	}
}

// A Profile that does not require kind 5 never asks for the commitment and
// signs the unchanged two-commitment receipt, whatever the engine offers.
func TestWorkerIgnoresAnchorsWhenTheProfileDoesNotRequireThem(t *testing.T) {
	h, model := anchorHarness(t, true, false)
	result, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if err != nil {
		t.Fatal(err)
	}
	if len(model.requests) != 1 || model.requests[0].RequireAnchorCommit {
		t.Fatalf("infer requests %+v, want none asking for the anchor commitment", model.requests)
	}
	if n := len(result.TaskDataReceipt.RequiredEvidenceCommitments); n != 2 {
		t.Fatalf("receipt carries %d commitments, want 2", n)
	}
	for _, upload := range h.taskData.uploads {
		if upload.Key.EvidenceKind == nodewire.EvidenceKindWorkerAnchorOpening {
			t.Fatal("an anchor object was uploaded for a Profile without kind 5")
		}
	}
}

// A required commitment the model service did not return fails the task
// before anything is uploaded or signed.
func TestWorkerFailsBeforeUploadWhenARequiredAnchorIsMissing(t *testing.T) {
	h, _ := anchorHarness(t, false, true)
	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) || !strings.Contains(err.Error(), "WORKER_ANCHOR_OPENING") {
		t.Fatalf("err = %v, want a missing WORKER_ANCHOR_OPENING refusal", err)
	}
	if len(h.taskData.uploads) != 0 {
		t.Fatalf("%d objects uploaded before the refusal", len(h.taskData.uploads))
	}
}
