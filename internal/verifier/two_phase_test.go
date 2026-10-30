package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

func countKind(kinds []string, kind string) int {
	n := 0
	for _, k := range kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// ADR-0023 decision 4 / CD §6.2 V12: before the commit no B-level material is
// requested, read or cached. On the fake transport the B level is the
// "position-values" artifact; it must be fetched by the reveal and only there.
func TestCommitHalfReadsNoBLevelMaterial(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	if n := countKind(h.model.fetchedKinds, "position-values"); n != 0 {
		t.Fatalf("the commit half fetched Worker position values %d times", n)
	}
	if countKind(h.model.fetchedKinds, "token-ids") != 1 {
		t.Fatalf("fetched kinds = %v, want the A-level token ids once", h.model.fetchedKinds)
	}
	revealLocally(t, h, state)
	if n := countKind(h.model.fetchedKinds, "position-values"); n != 1 {
		t.Fatalf("the reveal fetched position values %d times, want once", n)
	}
}

func TestCommitHalfRefusesBLevelMaterialHandedToIt(t *testing.T) {
	h := newHarness(t)
	state, values := confirmedTaskWithValues(t, h)
	state.ConfirmedWorkerValues = values
	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if !errors.Is(err, ErrBLevelBeforeCommit) {
		t.Fatalf("error = %v, want ErrBLevelBeforeCommit", err)
	}
	if h.model.VerifyCalls != 0 || len(h.tx.Requests()) != 0 {
		t.Fatal("a commit half holding B-level material still ran or submitted")
	}
}

// The reveal derives metrics from the leaves the commit bound, after a restart.
func TestRevealRebuildsMetricsFromTheCommittedLeavesAfterARestart(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	committed := verifyLocally(t, h, state)
	if !committed.MetricMaterial.Root.IsZero() {
		t.Fatal("the commit half produced a metric_root; metrics need the B level")
	}
	h.verifier = New(h.verifier.cfg)
	reveal := revealLocally(t, h, state)
	receipt := publishedResultReceipt(t, h)
	if !bytes.Equal(receipt.VerifierValueRoot, committed.MetricMaterial.VerifierValueRoot[:]) || !bytes.Equal(receipt.Salt, committed.Salt[:]) {
		t.Fatal("the reveal does not carry the committed verifier_value_root and salt")
	}
	if reveal.MetricMaterial.Root.IsZero() || !bytes.Equal(receipt.MetricRoot, reveal.MetricMaterial.Root[:]) {
		t.Fatalf("metric_root = %x, want the reveal's own non-zero root", receipt.MetricRoot)
	}
	if reveal.ResultDigest.IsZero() || len(reveal.ResultReveal) == 0 {
		t.Fatalf("reveal = %+v, want the result payload and its digest", reveal)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("prefills = %d, want the reveal to reuse the committed leaves", h.model.VerifyCalls)
	}
}

// A retried reveal reuses the material the first attempt persisted: the B
// level is not read twice.
func TestRevealRetryReusesThePersistedMaterial(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	publisher := h.verifier.cfg.EvidencePublisher
	h.verifier.cfg.EvidencePublisher = evidencePublisherStub{publish: func(TaskState, nodewire.ResultReceiptV3, []byte, []byte) error {
		return errors.New("builder down")
	}}
	if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); err == nil {
		t.Fatal("the reveal published through a failing publisher")
	}
	h.verifier.cfg.EvidencePublisher = publisher
	h.verifier = New(h.verifier.cfg)
	revealLocally(t, h, state)
	if n := countKind(h.model.fetchedKinds, "position-values"); n != 1 {
		t.Fatalf("position values fetched %d times across a retried reveal, want once", n)
	}
}

func TestConfirmedRevealChecksTheValueCommitment(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, h harness, s TaskState, values []byte) []byte
		want   string
	}{
		"baseline": {func(_ *testing.T, _ harness, _ TaskState, v []byte) []byte { return v }, ""},
		"tampered worker_values": {func(t *testing.T, h harness, s TaskState, v []byte) []byte {
			taskID, _ := hex.DecodeString(s.TaskID)
			accepted := fixtureTaskAcceptedTaskHash(s.TaskID)
			binding := nodewire.WorkerValueBindingV1{ChainID: h.verifier.cfg.ChainID, TaskID: taskID, AcceptedTaskHash: accepted[:],
				WorkerOperatorAddress: s.WorkerAddress, RequiredTopK: fixtureLockedProfile().Profile.RequiredTopK}
			leaves, err := nodewire.DecodeWorkerValues(binding, v)
			if err != nil {
				t.Fatal(err)
			}
			for i := range leaves {
				if leaves[i].Finite {
					leaves[i].LogprobFP1e6--
					break
				}
			}
			out, err := nodewire.EncodeWorkerValues(binding, leaves)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}, "commitment"},
		"missing value bundle": {func(*testing.T, harness, TaskState, []byte) []byte { return nil }, "incomplete"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			state, values := confirmedTaskWithValues(t, h)
			if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
				t.Fatalf("commit: %v", err)
			}
			revealState := state
			revealState.ConfirmedWorkerValues = tc.mutate(t, h, state, values)
			result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), revealState)
			if tc.want == "" {
				if err != nil || !result.Signed {
					t.Fatalf("baseline reveal = %+v, %v", result, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || result.Signed || len(*h.finalized) != 0 {
				t.Fatalf("reveal = %+v, %v; want a refusal containing %q before anything is signed", result, err, tc.want)
			}
		})
	}
}

// A Worker value whose token is not the committed generated token is illegal
// content that reproduced nothing the Verifier scored: WORKER_EVIDENCE_INVALID.
func TestRevealMarksAWorkerLeafNamingAnotherTokenInvalid(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	source, err := h.verifier.persistedReveal(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	leaves := append([]nodewire.PositionValueV1(nil), source.verifierLeaves...)
	leaves[0].TokenID++
	err = checkWorkerLeavesNameTheCommittedTokens(leaves, source.verifierLeaves)
	if !errors.Is(err, ErrWorkerEvidenceInvalid) {
		t.Fatalf("error = %v, want ErrWorkerEvidenceInvalid", err)
	}
	if err := checkWorkerLeavesNameTheCommittedTokens(source.verifierLeaves[1:], source.verifierLeaves); !errors.Is(err, ErrWorkerEvidenceInvalid) {
		t.Fatalf("a short leaf set = %v, want ErrWorkerEvidenceInvalid", err)
	}
	if err := checkWorkerLeavesNameTheCommittedTokens(source.verifierLeaves, source.verifierLeaves); err != nil {
		t.Fatalf("the committed leaves themselves = %v, want accepted", err)
	}
}
