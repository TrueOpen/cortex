package modelservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedFakeServicePersistsArtifactsAcrossInstances(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	producer, err := NewSharedFakeService("shared-model", root)
	if err != nil {
		t.Fatalf("NewSharedFakeService producer error = %v", err)
	}
	consumer, err := NewSharedFakeService("shared-model", root)
	if err != nil {
		t.Fatalf("NewSharedFakeService consumer error = %v", err)
	}

	infer, err := producer.Infer(ctx, InferRequest{ModelID: "model-a", Capability: CapabilityLLMTextV1, Input: []byte("prompt")})
	if err != nil {
		t.Fatalf("Infer returned error: %v", err)
	}
	artifact, err := consumer.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "shared-model", Ref: infer.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact returned error: %v", err)
	}
	if len(artifact.Data) == 0 {
		t.Fatal("shared artifact is empty")
	}

	ref, err := ParseArtifactRef(infer.OutputRef)
	if err != nil {
		t.Fatalf("ParseArtifactRef returned error: %v", err)
	}
	path := filepath.Join(root, "model-artifacts", ref.ArtifactID+".bin")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt shared artifact: %v", err)
	}
	if _, err := consumer.FetchArtifact(ctx, FetchArtifactRequest{Ref: infer.OutputRef}); !errors.Is(err, ErrArtifactSizeMismatch) && !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("FetchArtifact corrupted error = %v, want integrity error", err)
	}
}

func TestSharedFakeServiceUsesConfiguredIdentity(t *testing.T) {
	fake, err := NewSharedFakeService("configured-model", t.TempDir())
	if err != nil {
		t.Fatalf("NewSharedFakeService error = %v", err)
	}
	resp, err := fake.Health(context.Background(), HealthRequest{RequestID: "health-1"})
	if err != nil {
		t.Fatalf("Health error = %v", err)
	}
	if resp.ModelServiceID != "configured-model" {
		t.Fatalf("ModelServiceID = %q, want configured-model", resp.ModelServiceID)
	}
}

func TestParseArtifactRefRejectsUnsafeRefs(t *testing.T) {
	digest := sha256.Sum256([]byte("artifact"))
	valid := fmt.Sprintf("cortex-artifact://fake-model/%x?size=8", digest)

	ref, err := ParseArtifactRef(valid)
	if err != nil {
		t.Fatalf("valid artifact ref rejected: %v", err)
	}
	if ref.Scheme != ArtifactScheme {
		t.Fatalf("scheme = %q, want %q", ref.Scheme, ArtifactScheme)
	}
	if ref.DigestSHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("digest = %q, want %x", ref.DigestSHA256, digest)
	}
	if ref.SizeBytes != 8 {
		t.Fatalf("size = %d, want 8", ref.SizeBytes)
	}

	tests := map[string]string{
		"absolute path": "/var/tmp/artifact",
		"relative path": "model/output.bin",
		"parent path":   "cortex-artifact://fake-model/../output.bin",
		"http URL":      "https://provider.example/output.bin",
		"ipfs URL":      "ipfs://bafybeigdyrzt",
		"file URL":      "file:///tmp/output.bin",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseArtifactRef(raw); err == nil {
				t.Fatalf("ParseArtifactRef(%q) succeeded, want rejection", raw)
			}
		})
	}
}

func TestFakeFetchArtifactVerifiesDigestAndSize(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeService()
	infer, err := fake.Infer(ctx, InferRequest{
		ModelID:    "model-a",
		Capability: CapabilityLLMTextV1,
		Input:      []byte("prompt"),
	})
	if err != nil {
		t.Fatalf("Infer returned error: %v", err)
	}

	artifact, err := fake.FetchArtifact(ctx, FetchArtifactRequest{Ref: infer.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact returned error: %v", err)
	}
	if artifact.Ref != infer.OutputRef {
		t.Fatalf("artifact ref = %q, want %q", artifact.Ref, infer.OutputRef)
	}
	if len(artifact.Data) == 0 {
		t.Fatalf("artifact data is empty")
	}

	parsed, err := ParseArtifactRef(infer.OutputRef)
	if err != nil {
		t.Fatalf("ParseArtifactRef returned error: %v", err)
	}
	parsed.DigestSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("different")))
	if _, err := fake.FetchArtifact(ctx, FetchArtifactRequest{Ref: parsed.String()}); !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("FetchArtifact digest mismatch error = %v, want %v", err, ErrArtifactDigestMismatch)
	}

	parsed, err = ParseArtifactRef(infer.OutputRef)
	if err != nil {
		t.Fatalf("ParseArtifactRef returned error: %v", err)
	}
	parsed.SizeBytes++
	if _, err := fake.FetchArtifact(ctx, FetchArtifactRequest{Ref: parsed.String()}); !errors.Is(err, ErrArtifactSizeMismatch) {
		t.Fatalf("FetchArtifact size mismatch error = %v, want %v", err, ErrArtifactSizeMismatch)
	}
}

func TestFakeFetchArtifactRejectsWrongServiceIdentity(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeService()
	ref := fake.PutArtifactForTest([]byte("artifact"))
	parsed, err := ParseArtifactRef(ref)
	if err != nil {
		t.Fatalf("ParseArtifactRef returned error: %v", err)
	}
	parsed.ServiceID = "other-service"

	if _, err := fake.FetchArtifact(ctx, FetchArtifactRequest{Ref: parsed.String()}); !errors.Is(err, ErrInvalidArtifactRef) {
		t.Fatalf("FetchArtifact wrong ref service error = %v, want %v", err, ErrInvalidArtifactRef)
	}
	if _, err := fake.FetchArtifact(ctx, FetchArtifactRequest{
		ModelServiceID: "other-service",
		Ref:            ref,
	}); !errors.Is(err, ErrInvalidArtifactRef) {
		t.Fatalf("FetchArtifact wrong request service error = %v, want %v", err, ErrInvalidArtifactRef)
	}
}

func TestFakeFetchArtifactRejectsEmptyUnlessAllowed(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeService()
	emptyRef := fake.PutArtifactForTest(nil)

	if _, err := fake.FetchArtifact(ctx, FetchArtifactRequest{Ref: emptyRef}); !errors.Is(err, ErrEmptyArtifact) {
		t.Fatalf("FetchArtifact empty error = %v, want %v", err, ErrEmptyArtifact)
	}

	artifact, err := fake.FetchArtifact(ctx, FetchArtifactRequest{
		Ref:        emptyRef,
		AllowEmpty: true,
	})
	if err != nil {
		t.Fatalf("FetchArtifact with AllowEmpty returned error: %v", err)
	}
	if !bytes.Equal(artifact.Data, nil) {
		t.Fatalf("artifact data = %q, want empty", artifact.Data)
	}
}

func TestFakeRejectsBlackBoxCapabilityWithoutTraceOrCheckpoint(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeService()

	_, err := fake.Verify(ctx, VerifyRequest{
		ModelID:    "model-a",
		Capability: "black_box_text_v1",
		Sample:     []byte("sample"),
	})
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("Verify error = %v, want %v", err, ErrUnsupportedCapability)
	}
}

func TestFakeRejectsMissingCapability(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeService()

	_, err := fake.Infer(ctx, InferRequest{
		ModelID: "model-a",
		Input:   []byte("prompt"),
	})
	if !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("Infer missing capability error = %v, want %v", err, ErrUnsupportedCapability)
	}
}

// Handraise eligibility matches the configured chain model id against what the
// model service advertises. A fixed placeholder would make every handraise fail
// against real Keeper records, so the shared fake advertises what it is given.
func TestSharedFakeServiceAdvertisesConfiguredModelIDs(t *testing.T) {
	const chainModelID = "ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
	service, err := NewSharedFakeService("local-model-service", t.TempDir(), chainModelID)
	if err != nil {
		t.Fatalf("NewSharedFakeService returned error: %v", err)
	}
	resp, err := service.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "r1", ModelServiceID: "local-model-service"})
	if err != nil {
		t.Fatalf("ListCapabilities returned error: %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != chainModelID ||
		resp.Capabilities[0].Capability != CapabilityLLMTextV1 {
		t.Fatalf("capabilities = %#v, want the configured chain model id", resp.Capabilities)
	}

	// GetModelDetails must agree with what ListCapabilities advertised.
	// Claiming support and then reporting MODEL_NOT_FOUND is worse than not
	// advertising at all, because the mismatch only surfaces mid-task.
	details, err := service.GetModelDetails(context.Background(), GetModelDetailsRequest{RequestID: "d1", ModelID: chainModelID})
	if err != nil {
		t.Fatalf("GetModelDetails returned error: %v", err)
	}
	if details.Error != nil {
		t.Fatalf("GetModelDetails error = %#v, want details for the advertised model", details.Error)
	}
	unknown, err := service.GetModelDetails(context.Background(), GetModelDetailsRequest{RequestID: "d2", ModelID: "not-advertised"})
	if err != nil {
		t.Fatalf("GetModelDetails returned error: %v", err)
	}
	if unknown.Error == nil || unknown.Error.Code != "MODEL_NOT_FOUND" {
		t.Fatalf("GetModelDetails error = %#v, want MODEL_NOT_FOUND for an unadvertised model", unknown.Error)
	}

	// With no configured id the historical advertisement is preserved.
	legacy, err := NewSharedFakeService("local-model-service", t.TempDir())
	if err != nil {
		t.Fatalf("NewSharedFakeService returned error: %v", err)
	}
	resp, err = legacy.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "r2", ModelServiceID: "local-model-service"})
	if err != nil {
		t.Fatalf("ListCapabilities returned error: %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != FakeModelID {
		t.Fatalf("capabilities = %#v, want the default fake model id", resp.Capabilities)
	}
}
