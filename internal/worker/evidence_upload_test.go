package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestWorkerStagesCanonicalBundleBeforeFinalizingAvailability(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	events := []string{}
	h.taskData.events, h.persistence.events = &events, &events
	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	// Each bundle uploads its artifacts and then its manifest, value bundle
	// first: worker_values, manifest, generated_token_ids, input_token_ids,
	// manifest.
	if len(h.taskData.uploads) != 5 {
		t.Fatalf("uploads = %d, want three artifacts and two manifests", len(h.taskData.uploads))
	}
	receipt := result.TaskDataReceipt
	for bundle, spec := range []struct {
		manifestAt int
		kind       nodewire.EvidenceKind
		artifacts  []string
	}{
		{1, nodewire.EvidenceKindWorkerValueOpening, []string{"worker_values"}},
		{4, nodewire.EvidenceKindWorkerTokenOpening, []string{"generated_token_ids", "input_token_ids"}},
	} {
		manifestUpload := h.taskData.uploads[spec.manifestAt]
		manifest, err := evidencebundle.Decode(manifestUpload.Data)
		if err != nil {
			t.Fatal(err)
		}
		commitment := receipt.RequiredEvidenceCommitments[bundle]
		if manifestUpload.Key.Kind != builderclient.DataKindEvidenceManifest || manifestUpload.Key.EvidenceKind != spec.kind ||
			commitment.EvidenceKind != spec.kind || commitment.EvidenceHashOrRoot.String() != manifestUpload.Key.ContentHash {
			t.Fatalf("bundle %d manifest object commitment mismatch", bundle)
		}
		if commitment.EvidenceHashOrRoot == evidencebundle.Hash(manifestUpload.Data) || commitment.EncodedSizeBytes != manifest.TotalSize() {
			t.Fatalf("receipt does not commit bundle %d's artifacts", bundle)
		}
		if len(manifest.Artifacts) != len(spec.artifacts) {
			t.Fatalf("bundle %d artifacts = %+v", bundle, manifest.Artifacts)
		}
		_, stored, err := h.persistence.WorkerBundle(context.Background(), event.TaskID, spec.kind)
		if err != nil {
			t.Fatal(err)
		}
		for i, artifact := range manifest.Artifacts {
			if artifact.ID != spec.artifacts[i] {
				t.Fatalf("bundle %d artifacts not sorted: %+v", bundle, manifest.Artifacts)
			}
			upload := h.taskData.uploads[spec.manifestAt-len(spec.artifacts)+i]
			data := stored[artifact.ID]
			want := builderclient.EvidenceObjectKey(receipt.TaskHash, event.SessionID, event.TaskID, builderclient.DataKindEvidenceArtifact, codec.HashBytes(data).String(), builderclient.EvidenceProducerWorker, 1, workerTestOperatorAddress, spec.kind)
			if upload.Key != want || string(upload.Data) != string(data) {
				t.Fatalf("artifact %s scope or bytes differ", artifact.ID)
			}
		}
	}
	finalize := slicesIndex(events, "task-data:finalize")
	pending := slicesIndex(events, "outbox:pending")
	if finalize < 0 || pending <= finalize || len(h.persistence.confirmations) != 3 {
		t.Fatalf("finalize/availability events = %v", events)
	}
	for _, metadata := range h.taskData.TaskDataMetadata {
		if metadata.Readiness != builderclient.TaskDataReady {
			t.Fatal("finalized object not READY")
		}
	}
}

func TestWorkerRetainedConfirmationsSurviveBuilderKeyRotation(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint("unavailable=", unavailable), func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
				if unavailable {
					return BuilderEndpoint{}, fmt.Errorf("Builder offline after verified finalization")
				}
				return BuilderEndpoint{OperatorAddress: h.persistence.confirmations[0].BuilderOperator, Endpoint: "https://rotated.example", AuthorizationNonce: 2, CurrentHeight: 150, ServicePubkey: hex.EncodeToString(secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x62}, 32)).PubKey().SerializeCompressed())}, nil
			})
			if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if len(h.taskData.uploads) != 5 || len(h.taskData.relays) != 1 || len(h.persistence.confirmations) != 3 {
				t.Fatal("key rotation repeated finalized material")
			}
		})
	}
}

func TestWorkerExpiredRetainedConfirmationDoesNotReleaseAvailability(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	h.persistence.outbox = nil
	endpoint, err := h.worker.receivingBuilder(context.Background(), receivingBuilderRef(event))
	if err != nil {
		t.Fatal(err)
	}
	endpoint.CurrentHeight = 200
	h.serviceKeys.height = 200
	h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) { return endpoint, nil })
	h.taskData.retention = 300
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(h.taskData.uploads) != 10 || len(h.persistence.confirmations) != 6 || h.persistence.confirmations[3].RetentionUntilHeight != 300 {
		t.Fatal("expired storage was reused to release availability")
	}
}

func TestWorkerRetainedConfirmationNeedsCurrentHeightAndExpectedBuilder(t *testing.T) {
	for _, invalid := range []string{"expired while Builder offline", "height unavailable", "other Builder"} {
		t.Run(invalid, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
				return BuilderEndpoint{}, fmt.Errorf("Builder endpoint unavailable")
			})
			switch invalid {
			case "expired while Builder offline":
				h.serviceKeys.height = 200
			case "height unavailable":
				h.serviceKeys.err = fmt.Errorf("Keeper unavailable")
			case "other Builder":
				record := &h.persistence.confirmations[0]
				c := *record.Confirmation
				c.BuilderOperator = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
				digest, err := builderclient.StorageConfirmationSigningHash(c)
				if err != nil {
					t.Fatal(err)
				}
				c.Signature = compactTestSignature(h.taskData.builderPrivate, digest)
				record.Confirmation, record.BuilderOperator, record.MaterialDigest, record.Signature = &c, c.BuilderOperator, digest.String(), c.Signature
			}
			confirmed, err := h.worker.confirmedStorageObjects(context.Background(), event, result.TaskDataReceipt, h.persistence.confirmations)
			if confirmed {
				t.Fatal("invalid retained confirmation established current availability")
			}
			if invalid == "height unavailable" && err == nil {
				t.Fatal("missing committed height did not fail closed")
			}
		})
	}
}

func TestWorkerRecoveryRejectsBundleProfileOrArtifactTampering(t *testing.T) {
	for _, name := range []string{"schema", "profile size", "value manifest", "token manifest", "input token IDs", "generated token IDs", "worker values", "leaf count", "generated token count"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "schema":
				h.worker.cfg.EvidenceSchemaHash = strings.Repeat("99", 32)
			case "profile size":
				h.worker.cfg.ProfileEvidenceRequirements = append([]builderclient.InferEvidenceRequirement(nil), h.worker.cfg.ProfileEvidenceRequirements...)
				h.worker.cfg.ProfileEvidenceRequirements[0].MaxEncodedSizeBytes = 1
			case "leaf count", "generated token count":
				for i := range h.persistence.evidence {
					if h.persistence.evidence[i].Kind != "worker-output-descriptor" {
						continue
					}
					var descriptor outputDescriptor
					if err := json.Unmarshal(h.persistence.evidence[i].Data, &descriptor); err != nil {
						t.Fatal(err)
					}
					if name == "leaf count" {
						descriptor.OutputChunkLengths = append(descriptor.OutputChunkLengths, 0)
					} else {
						descriptor.GeneratedTokenCount++
					}
					h.persistence.evidence[i].Data, _ = json.Marshal(descriptor)
				}
			default:
				// Tamper with the published bundle in the store.
				kind, id := nodewire.EvidenceKindWorkerTokenOpening, ""
				switch name {
				case "value manifest":
					kind = nodewire.EvidenceKindWorkerValueOpening
				case "input token IDs":
					id = builderclient.EvidenceArtifactInputTokenIDs
				case "generated token IDs":
					id = builderclient.EvidenceArtifactGeneratedTokenIDs
				case "worker values":
					kind, id = nodewire.EvidenceKindWorkerValueOpening, builderclient.EvidenceArtifactWorkerValues
				}
				key := fmt.Sprintf("%s/%d", event.TaskID, kind)
				bundle := h.persistence.bundles[key]
				if id == "" {
					bundle.manifest = append(append([]byte(nil), bundle.manifest...), ' ')
				} else {
					bundle.artifacts[id] = append(append([]byte(nil), bundle.artifacts[id]...), 0)
				}
				h.persistence.bundles[key] = bundle
			}
			if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err == nil {
				t.Fatal("recovery accepted invalid retained bundle")
			}
			if len(h.taskData.uploads) != 5 {
				t.Fatal("invalid retained bundle reached upload")
			}
		})
	}
}

func TestWorkerRecoveryRequiresBothFullSignedConfirmations(t *testing.T) {
	for _, partial := range []string{"missing bundle", "missing output", "legacy", "wrong task hash", "wrong round", "wrong signature", "wrong nonce"} {
		t.Run(partial, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			switch partial {
			case "missing bundle":
				h.persistence.confirmations = h.persistence.confirmations[:1]
			case "missing output":
				h.persistence.confirmations = h.persistence.confirmations[1:]
			case "legacy":
				h.persistence.confirmations[0].Confirmation = nil
			default:
				record := &h.persistence.confirmations[1]
				c := *record.Confirmation
				c.Signature = append([]byte(nil), c.Signature...)
				switch partial {
				case "wrong task hash":
					c.Key.TaskHash = codec.HashBytes([]byte("other")).String()
				case "wrong round":
					c.Key.VerifyRound++
				case "wrong signature":
					c.Signature[0] ^= 1
				case "wrong nonce":
					c.ServiceAuthorizationNonce++
				}
				record.Confirmation = &c
			}
			if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if len(h.taskData.uploads) != 10 || len(h.taskData.relays) != 2 {
				t.Fatal("incomplete or invalid confirmation suppressed idempotent finalization")
			}
		})
	}
}
