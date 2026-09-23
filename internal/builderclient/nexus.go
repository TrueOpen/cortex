package builderclient

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
)

type Publisher interface {
	Publish(context.Context, PublishRequest) error
}

// NexusClient is what is left of Cortex's direct Nexus surface after the
// task-data plane took over every call: a bus publisher and the Worker's local
// output-package self-check. It holds no endpoint and no HTTP client, because
// nothing here talks to Nexus over HTTP any more — GetTaskDataMetadata,
// FetchTaskData, UploadTaskResultData and SubmitInferReceipt all go through
// ConnectTaskDataClient against the Builder endpoint the on-chain descriptor
// commits.
type NexusClient struct {
	publisher Publisher
}

func NewNexusClient(publisher Publisher) *NexusClient {
	return &NexusClient{publisher: publisher}
}

func (c *NexusClient) ValidateOutputPackage(_ context.Context, pkg OutputPackage) error {
	if pkg.Provenance == OutputPackageFromTaskData {
		return validateTaskDataOutputPackage(pkg)
	}
	if pkg.TaskID == "" || pkg.OutputRef == "" || pkg.PackageHash == (codec.Hash{}) {
		return fmt.Errorf("output package missing required fields")
	}
	if pkg.SessionID != "" {
		expected, err := CanonicalOutputPackageHash(pkg)
		if err != nil {
			return err
		}
		if expected != pkg.PackageHash {
			return fmt.Errorf("output package hash mismatch")
		}
		if len(pkg.WorkerSignature) == 0 {
			return fmt.Errorf("output package worker signature is required")
		}
	}
	material, err := DecodeInferReceiptMaterial(pkg.ReceiptPayload)
	if err != nil {
		return err
	}
	// Reported field by field: any one of these five mismatching means the receipt and
	// the output are not from the same inference, and one vague sentence would leave
	// diagnosis to guesswork.
	for _, field := range []struct {
		name           string
		inMaterial, in string
	}{
		{"task_id", material.TaskID, pkg.TaskID},
		{"output_ref", material.OutputRef, pkg.OutputRef},
		{"output_hash", hex.EncodeToString(material.OutputHash[:]), hex.EncodeToString(pkg.OutputHash[:])},
		{"package_hash", hex.EncodeToString(material.PackageHash[:]), hex.EncodeToString(pkg.PackageHash[:])},
		{"receipt_hash", hex.EncodeToString(material.ReceiptResultHash[:]), hex.EncodeToString(pkg.ReceiptHash[:])},
	} {
		if field.inMaterial != field.in {
			return fmt.Errorf("infer receipt material does not match output package: %s: receipt has %s, package has %s",
				field.name, field.inMaterial, field.in)
		}
	}
	return nil
}

// validateTaskDataOutputPackage checks what an OUTPUT object read off the
// task-data plane can be checked for. The refs, the canonical package
// re-encoding and the receipt material are all absent by construction, so
// demanding them here would refuse every real-transport confirmation; what is
// demanded instead is the binding those checks existed to establish -- the body
// present and hashing to the committed output hash.
func validateTaskDataOutputPackage(pkg OutputPackage) error {
	// No package hash. The frozen InferReceiptState carries none, and
	// cortex-detailed-design.md:1032 forbids Cortex from deriving a replacement, so the
	// output hash is the whole of what a task-data package commits to.
	if pkg.TaskID == "" || pkg.OutputHash == (codec.Hash{}) {
		return fmt.Errorf("task-data output package missing required fields")
	}
	got, err := codec.OutputMMRRootFromLengths(pkg.Output, pkg.OutputChunkLengths)
	if err != nil {
		return fmt.Errorf("task-data output chunk boundaries: %w", err)
	}
	if got != pkg.OutputHash {
		return fmt.Errorf("task-data output package body hashes to %s, not its output hash %s", got, pkg.OutputHash)
	}
	if pkg.ReceiptHash == (codec.Hash{}) || len(pkg.WorkerSignature) == 0 {
		return fmt.Errorf("task-data output package carries no signed infer receipt")
	}
	return nil
}

func (c *NexusClient) Publish(ctx context.Context, req PublishRequest) error {
	if c.publisher == nil {
		return fmt.Errorf("nexus publisher is required")
	}
	if req.Subject == "" || req.TaskID == "" {
		return fmt.Errorf("publish missing required fields")
	}
	return c.publisher.Publish(ctx, req)
}
