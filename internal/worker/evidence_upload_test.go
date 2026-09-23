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
	if len(h.taskData.uploads) != 5 {
		t.Fatalf("uploads = %d, want four artifacts and manifest", len(h.taskData.uploads))
	}
	manifestUpload := h.taskData.uploads[4]
	manifest, err := evidencebundle.Decode(manifestUpload.Data)
	if err != nil {
		t.Fatal(err)
	}
	if manifestUpload.Key.Kind != builderclient.DataKindEvidenceManifest || result.TaskDataReceipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot.String() != manifestUpload.Key.ContentHash {
		t.Fatal("manifest object commitment mismatch")
	}
	if len(manifest.Artifacts) != 4 || manifest.Artifacts[0].ID != "checkpoint" || manifest.Artifacts[1].ID != "generated_token_ids" || manifest.Artifacts[2].ID != "input_token_ids" || manifest.Artifacts[3].ID != "trace" {
		t.Fatal("manifest artifacts not sorted")
	}
	for i, artifact := range manifest.Artifacts {
		upload := h.taskData.uploads[i]
		data, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, "worker-"+artifact.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := builderclient.EvidenceObjectKey(result.TaskDataReceipt.TaskHash, event.SessionID, event.TaskID, builderclient.DataKindEvidenceArtifact, codec.HashBytes(data).String(), builderclient.EvidenceProducerWorker, 1, workerTestOperatorAddress)
		if upload.Key != want || string(upload.Data) != string(data) {
			t.Fatalf("artifact %s scope or bytes differ", artifact.ID)
		}
	}
	commitment := result.TaskDataReceipt.RequiredEvidenceCommitments[0]
	if commitment.EvidenceHashOrRoot == evidencebundle.Hash(manifestUpload.Data) || commitment.EncodedSizeBytes != manifest.TotalSize() {
		t.Fatal("receipt does not commit the V2 artifact bundle")
	}
	finalize := slicesIndex(events, "task-data:finalize")
	pending := slicesIndex(events, "outbox:pending")
	if finalize < 0 || pending <= finalize || len(h.persistence.confirmations) != 2 {
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
			if len(h.taskData.uploads) != 5 || len(h.taskData.relays) != 1 || len(h.persistence.confirmations) != 2 {
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
	if len(h.taskData.uploads) != 10 || len(h.persistence.confirmations) != 4 || h.persistence.confirmations[2].RetentionUntilHeight != 300 {
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
	for _, name := range []string{"schema", "profile size", "artifact", "manifest", "input token IDs", "generated token IDs", "leaf count", "generated token count"} {
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
				kind := "worker-trace"
				switch name {
				case "manifest":
					kind = "worker-evidence-manifest"
				case "input token IDs":
					kind = "worker-input_token_ids"
				case "generated token IDs":
					kind = "worker-generated_token_ids"
				}
				for i := range h.persistence.evidence {
					if h.persistence.evidence[i].Kind == kind {
						h.persistence.evidence[i].Data = append(h.persistence.evidence[i].Data, ' ')
					}
				}
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
