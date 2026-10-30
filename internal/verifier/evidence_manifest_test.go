package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

type evidencePublisherStub struct {
	publish func(TaskState, nodewire.ResultReceiptV3, []byte, []byte) error
}

func (s evidencePublisherStub) PublishVerifierEvidence(_ context.Context, state TaskState, receipt nodewire.ResultReceiptV3, manifest, proof []byte) error {
	if s.publish != nil {
		return s.publish(state, receipt, manifest, proof)
	}
	return nil
}

func TestVerifierFinalizesExactCommittedEvidenceBeforePublishing(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	before := verifyLocally(t, h, state)
	called := false
	h.verifier.cfg.EvidencePublisher = evidencePublisherStub{publish: func(got TaskState, receipt nodewire.ResultReceiptV3, manifest, proof []byte) error {
		called = true
		if got.TaskID != state.TaskID {
			t.Fatal("evidence finalized for another task")
		}
		bundleHash := evidencebundle.Hash(manifest)
		if !bytes.Equal(receipt.VerifierValueRoot, before.MetricMaterial.VerifierValueRoot[:]) || codec.HashBytes(proof) != codec.Hash(receipt.AggregateProofHash) ||
			!bytes.Equal(receipt.VerifierEvidenceBundleHash, bundleHash[:]) || receipt.VerifierEvidenceManifestSizeBytes != uint64(len(manifest)) ||
			!bytes.Equal(receipt.Salt, before.Salt[:]) || receipt.SchemaVersion != nodewire.ResultReceiptSchemaVersionV3 {
			t.Fatal("published evidence differs from the committed bundle")
		}
		return nil
	}}
	h.verifier = New(h.verifier.cfg)
	revealLocally(t, h, state)
	if !called {
		t.Fatal("evidence publisher was not called after restart")
	}
}

func TestVerifierEvidencePublisherFailurePreventsResultPublication(t *testing.T) {
	for _, absent := range []bool{true, false} {
		t.Run(map[bool]string{true: "absent", false: "finalize rejected"}[absent], func(t *testing.T) {
			h := newHarness(t)
			state := h.validTask()
			state.OpenVerifyAccepted = true
			verifyLocally(t, h, state)
			h.verifier.cfg.EvidencePublisher = nil
			failure := errors.New("finalize rejected")
			if !absent {
				h.verifier.cfg.EvidencePublisher = evidencePublisherStub{publish: func(TaskState, nodewire.ResultReceiptV3, []byte, []byte) error { return failure }}
			}
			result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
			if err == nil || result.Signed {
				t.Fatalf("published without finalized evidence: result=%+v err=%v", result, err)
			}
			if !absent && !errors.Is(err, failure) {
				t.Fatalf("publisher failure lost: %v", err)
			}
		})
	}
}

func TestVerifierRestoreRejectsAlteredCommitMaterial(t *testing.T) {
	alter := func(t *testing.T, h harness, kind, field string) {
		t.Helper()
		for i := range h.persistence.evidence {
			record := &h.persistence.evidence[i]
			if record.Kind != kind {
				continue
			}
			var value map[string]any
			if err := json.Unmarshal(record.Data, &value); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "metric_summary":
				value["metric_material"].(map[string]any)["metric_summary"].(map[string]any)["finite_count"] = 100
			case "aggregate_proof", "metric_root":
				value["metric_material"].(map[string]any)[field] = hex.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
			case "evidence_manifest":
				raw, _ := hex.DecodeString(value[field].(string))
				value[field] = hex.EncodeToString(append(raw, '\n'))
			default:
				value[field] = hex.EncodeToString(bytes.Repeat([]byte{0x92}, 32))
			}
			var err error
			if record.Data, err = json.Marshal(value); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Written before the commit left this node.
	for _, field := range []string{"salt", "commit_hash", "verifier_value_root"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			state := h.validTask()
			state.OpenVerifyAccepted = true
			verifyLocally(t, h, state)
			alter(t, h, verifierFullResultRevealEvidenceKind, field)
			h.verifier = New(h.verifier.cfg)
			result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
			if !errors.Is(err, ErrResultReceiptInputUnavailable) || result.Signed {
				t.Fatalf("altered %s accepted: result=%+v err=%v", field, result, err)
			}
		})
	}
	// Written in REVEALING, before anything is published.
	for _, field := range []string{"result_reveal", "evidence_manifest", "aggregate_proof", "metric_root", "metric_summary"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			state := h.validTask()
			state.OpenVerifyAccepted = true
			verifyLocally(t, h, state)
			h.verifier.cfg.EvidencePublisher = evidencePublisherStub{publish: func(TaskState, nodewire.ResultReceiptV3, []byte, []byte) error {
				return errors.New("builder down")
			}}
			if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); err == nil {
				t.Fatal("the reveal published through a failing publisher")
			}
			alter(t, h, verifierRevealMaterialEvidenceKind, field)
			cfg := h.verifier.cfg
			cfg.EvidencePublisher = evidencePublisherStub{}
			h.verifier = New(cfg)
			result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
			if !errors.Is(err, ErrResultReceiptInputUnavailable) || result.Signed {
				t.Fatalf("altered %s accepted: result=%+v err=%v", field, result, err)
			}
		})
	}
}

func TestSelectedVerifierIndexPreservesAuthoritativeOrder(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.AssignedVerifiers = []string{fixtureOtherVerifierAddress, fixtureVerifierAddress, fixtureThirdVerifierAddress}
	index, err := selectedVerifierIndex(state, fixtureVerifierAddress)
	if err != nil || index != 1 {
		t.Fatalf("selected index = %d, %v", index, err)
	}
	verifyLocally(t, h, state)
	state.AssignedVerifiers[0], state.AssignedVerifiers[1] = state.AssignedVerifiers[1], state.AssignedVerifiers[0]
	if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); !errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("reordered assignment accepted on restore: %v", err)
	}
	for _, selected := range [][]string{nil, {fixtureOtherVerifierAddress}, {fixtureVerifierAddress, fixtureVerifierAddress}} {
		state.AssignedVerifiers = selected
		if _, err := selectedVerifierIndex(state, fixtureVerifierAddress); err == nil {
			t.Fatalf("invalid assignment accepted: %v", selected)
		}
	}
}

func TestVerifierMetricBindingUsesAcceptedTaskHashAndRound(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.VerifyRound = 2
	binding, bound, err := h.verifier.metricBinding(context.Background(), state, fixtureLockedProfile(), true)
	if err != nil || !bound {
		t.Fatalf("metric binding: %v", err)
	}
	taskID, _ := hash32FromHex("task_id", state.TaskID)
	facts := servedTaskFacts(state.TaskID)
	if binding.TaskID != taskID || binding.TaskHash != codec.Hash(facts.AcceptedTaskHash) || binding.VerifyRound != 2 || binding.TaskID == binding.TaskHash {
		t.Fatalf("metric binding loses task identity: %+v", binding)
	}
}
