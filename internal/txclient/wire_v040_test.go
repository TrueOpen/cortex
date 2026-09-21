package txclient

import (
	"encoding/json"
	"testing"

	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestResultV2DTOAgreesWithReleasedDescriptor(t *testing.T) {
	receipt := validSubmitVerifyResultMessage().Receipt
	receipt.VerifyRound = 2
	receipt.VerifierEvidenceManifestSizeBytes = 123
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var got taskv1.ResultReceiptV2
	if err := protojson.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 2 || got.VerifyRound != 2 || got.VerifierEvidenceManifestSizeBytes != 123 || len(got.Salt) != 32 {
		t.Fatalf("lost released fields: %v", &got)
	}
}

func TestInferV2DTOAgreesWithReleasedDescriptor(t *testing.T) {
	receipt := validSubmitInferReceiptMessage().Receipt
	receipt.OutputLeafCount = 9
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var got taskv1.InferReceiptV2
	if err := protojson.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 2 || got.OutputLeafCount != 9 || got.GeneratedTokenCount != 32 {
		t.Fatalf("lost released fields: %v", &got)
	}
}

func TestInferV2RejectsLegacySchemaAndMissingCounts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*InferReceiptMessage)
	}{
		{"legacy schema", func(r *InferReceiptMessage) { r.SchemaVersion = 1 }},
		{"missing output leaves", func(r *InferReceiptMessage) { r.OutputLeafCount = 0 }},
		{"empty output with multiple leaves", func(r *InferReceiptMessage) { r.OutputSizeBytes = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := validSubmitInferReceiptMessage()
			test.mutate(&message.Receipt)
			if _, err := MarshalMessage(MsgSubmitInferReceipt, message); err == nil {
				t.Fatal("accepted invalid infer receipt")
			}
		})
	}
}

func TestWireV041ProfileRejectsLegacyWorkerCommitmentAndFutureTaskTypes(t *testing.T) {
	profile := validRegisterModelProfileMessage().Profile
	profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence[0].CommitmentSchemaVersion = 1
	if err := ValidateModelProfileProjection(profile); err == nil {
		t.Fatal("accepted legacy Worker value commitment schema")
	}
	for _, taskType := range []string{"TASK_TYPE_EMBEDDING", "TASK_TYPE_CLASSIFICATION", "TASK_TYPE_IMAGE_GENERATION", "TASK_TYPE_MULTIMODAL"} {
		profile = validRegisterModelProfileMessage().Profile
		profile.TaskTypes = []string{taskType}
		if err := ValidateModelProfileProjection(profile); err == nil {
			t.Fatalf("accepted future task type %s", taskType)
		}
	}
}

func TestInferV2AcceptsEmptyOutputWithOneLeaf(t *testing.T) {
	message := validSubmitInferReceiptMessage()
	message.Receipt.OutputSizeBytes = 0
	message.Receipt.GeneratedTokenCount = 0
	message.Receipt.OutputLeafCount = 1
	if _, err := MarshalMessage(MsgSubmitInferReceipt, message); err != nil {
		t.Fatalf("empty-output receipt refused: %v", err)
	}
}
