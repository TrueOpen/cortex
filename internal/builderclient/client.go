package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

type OutputPackage struct {
	SessionID         string     `json:"session_id,omitempty"`
	TaskID            string     `json:"task_id"`
	ModelID           string     `json:"model_id,omitempty"`
	ProfileVersion    string     `json:"profile_version,omitempty"`
	OutputRef         string     `json:"output_ref"`
	TokenIDsRef       string     `json:"token_ids_ref"`
	PositionValuesRef string     `json:"position_values_ref"`
	OutputHash        codec.Hash `json:"output_hash"`
	PackageHash       codec.Hash `json:"package_hash"`
	ReceiptHash       codec.Hash `json:"receipt_hash"`
	ReceiptPayload    []byte     `json:"receipt_payload"`
	WorkerSignature   []byte     `json:"worker_signature,omitempty"`
	// Output is the output body itself, present only when the package was
	// confirmed by reading the OUTPUT object off the task-data plane rather than
	// by loading a canonical package from a store the two nodes share. It is
	// never part of the canonical package encoding -- CanonicalOutputPackageHash
	// covers the refs, not the body -- so it carries no json tag and never
	// reaches the store.
	Output             []byte   `json:"-"`
	OutputChunkLengths []uint64 `json:"output_chunk_lengths,omitempty"`
	// SignedInferReceipt is the Worker-signed receipt the Builder handed back with
	// the OUTPUT metadata, present only on the task-data path. It is carried
	// because it is the only chain-bound description of the task's required
	// evidence commitments: its derived signing digest was checked against the
	// infer_receipt_hash Keeper accepted, so required_evidence_commitments came
	// through a value the chain settled on rather than a Builder assertion.
	//
	// Without it the evidence confirmation would have to read OUTPUT metadata a
	// second time -- another RPC and another single-use nonce -- to learn a fact
	// this read already established. Like Output it carries no json tag and never
	// reaches the store.
	SignedInferReceipt *SignedInferReceipt `json:"-"`
	// Provenance says how this package was obtained. The two ways prove
	// different things, so they cannot be validated by the same rules, and
	// sniffing (say, "OutputRef is empty") would make a malformed store package
	// silently take the weaker path. The zero value is the store package every
	// existing construction site builds.
	Provenance OutputPackageProvenance `json:"-"`
}

// OutputPackageProvenance discriminates the two ways a node can come to hold an
// output package.
type OutputPackageProvenance uint8

const (
	// OutputPackageFromStore is the canonical package read from a store the
	// Worker and the Verifier share, addressed by the chain-committed package
	// hash. It carries the three artifact refs, so the package hash and the
	// receipt material recompute from it.
	OutputPackageFromStore OutputPackageProvenance = iota
	// OutputPackageFromTaskData is the OUTPUT object read off the task-data
	// plane from the receiving Builder. It carries the body and no refs: the
	// refs are Worker-local model-service addresses that no wire transports, so
	// neither the package hash nor the receipt material can be recomputed from
	// it. What it does prove is stronger where it counts -- the bytes hash to
	// the output hash Keeper committed.
	OutputPackageFromTaskData
)

type InferReceiptMaterial struct {
	TaskID              string     `json:"task_id"`
	OutputRef           string     `json:"output_ref"`
	OutputHash          codec.Hash `json:"output_hash"`
	PackageHash         codec.Hash `json:"package_hash"`
	ReceiptResultHash   codec.Hash `json:"receipt_result_hash"`
	ActualOutputSummary string     `json:"actual_output_summary"`
}

func parseLowerHexHash(value string, field string) (codec.Hash, error) {
	if len(value) != 64 || value != strings.ToLower(value) {
		return codec.Hash{}, fmt.Errorf("%s must be a lowercase sha256 hex string", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return codec.Hash{}, fmt.Errorf("%s must be a lowercase sha256 hex string", field)
	}
	var out codec.Hash
	copy(out[:], decoded)
	return out, nil
}

type OutputPackageLoader interface {
	LoadOutputPackage(context.Context, string, codec.Hash) (OutputPackage, error)
}

type OutputPackageStore interface {
	OutputPackageLoader
	SaveOutputPackage(context.Context, OutputPackage) (OutputPackage, string, error)
}

func EncodeInferReceiptMaterial(material InferReceiptMaterial) ([]byte, error) {
	if material.TaskID == "" || material.OutputRef == "" || material.ReceiptResultHash == (codec.Hash{}) {
		return nil, fmt.Errorf("infer receipt material missing required fields")
	}
	var buf bytes.Buffer
	buf.WriteString("CORTEX_INFER_RECEIPT_MATERIAL_V1")
	writeCanonicalField(&buf, []byte(material.TaskID))
	writeCanonicalField(&buf, []byte(material.OutputRef))
	writeCanonicalField(&buf, material.OutputHash[:])
	writeCanonicalField(&buf, material.PackageHash[:])
	writeCanonicalField(&buf, material.ReceiptResultHash[:])
	writeCanonicalField(&buf, []byte(material.ActualOutputSummary))
	return buf.Bytes(), nil
}

func DecodeInferReceiptMaterial(data []byte) (InferReceiptMaterial, error) {
	var material InferReceiptMaterial
	if bytes.HasPrefix(data, []byte("CORTEX_INFER_RECEIPT_MATERIAL_V1")) {
		decoded, err := decodeCanonicalInferReceiptMaterial(data)
		if err != nil {
			return InferReceiptMaterial{}, err
		}
		return decoded, nil
	}
	if err := json.Unmarshal(data, &material); err != nil {
		return InferReceiptMaterial{}, err
	}
	if material.TaskID == "" || material.OutputRef == "" || material.ReceiptResultHash == (codec.Hash{}) {
		return InferReceiptMaterial{}, fmt.Errorf("infer receipt material missing required fields")
	}
	return material, nil
}

func writeCanonicalField(buf *bytes.Buffer, value []byte) {
	buf.Write(codec.Uint64Bytes(uint64(len(value))))
	buf.Write(value)
}

func decodeCanonicalInferReceiptMaterial(data []byte) (InferReceiptMaterial, error) {
	rest := data[len("CORTEX_INFER_RECEIPT_MATERIAL_V1"):]
	taskID, rest, err := readCanonicalField(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	outputRef, rest, err := readCanonicalField(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	outputHash, rest, err := readCanonicalHash(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	packageHash, rest, err := readCanonicalHash(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	receiptHash, rest, err := readCanonicalHash(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	summary, rest, err := readCanonicalField(rest)
	if err != nil {
		return InferReceiptMaterial{}, err
	}
	if len(rest) != 0 {
		return InferReceiptMaterial{}, fmt.Errorf("infer receipt material has trailing bytes")
	}
	material := InferReceiptMaterial{
		TaskID:              string(taskID),
		OutputRef:           string(outputRef),
		OutputHash:          outputHash,
		PackageHash:         packageHash,
		ReceiptResultHash:   receiptHash,
		ActualOutputSummary: string(summary),
	}
	if material.TaskID == "" || material.OutputRef == "" || material.ReceiptResultHash == (codec.Hash{}) {
		return InferReceiptMaterial{}, fmt.Errorf("infer receipt material missing required fields")
	}
	return material, nil
}

func readCanonicalHash(data []byte) (codec.Hash, []byte, error) {
	field, rest, err := readCanonicalField(data)
	if err != nil {
		return codec.Hash{}, nil, err
	}
	if len(field) != 32 {
		return codec.Hash{}, nil, fmt.Errorf("canonical hash length = %d, want 32", len(field))
	}
	var out codec.Hash
	copy(out[:], field)
	return out, rest, nil
}

func readCanonicalField(data []byte) ([]byte, []byte, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("canonical field length missing")
	}
	var size uint64
	for _, b := range data[:8] {
		size = (size << 8) | uint64(b)
	}
	if size > uint64(len(data)-8) {
		return nil, nil, fmt.Errorf("canonical field length exceeds payload")
	}
	start := 8
	end := start + int(size)
	return data[start:end], data[end:], nil
}

type PublishRequest struct {
	Subject string
	TaskID  string
	Payload []byte
	// DedupID is a stable per-logical-event identifier used for transport-level
	// deduplication. It must be the same for every emission of the same logical
	// event, even if the outer envelope is rebuilt with a fresh message_id/nonce.
	DedupID string
}

// TaskDataMetadata is the boundary metadata a Builder reports for one task-data
// object. SignedInferReceipt and AcceptedReceiptHash are OUTPUT-only: they are
// the target-state contract's replacement for the deleted OutputRef object, so
// they are the whole proof that the Builder holds the committed output. They are
// nil/empty for INPUT, where no receipt exists.
type TaskDataReadiness uint32

const (
	TaskDataStored TaskDataReadiness = 1
	TaskDataReady  TaskDataReadiness = 2
)

type EvidenceBundleSummary struct {
	EvidenceManifestHash   string // digest of the exact manifest bytes; metadata only
	EvidenceSchemaHash     string
	ArtifactCount          uint32
	ArtifactTotalSizeBytes uint64
	ManifestSizeBytes      uint64
}

type TaskDataMetadata struct {
	Key                TaskDataKey
	SizeBytes          uint64
	MediaType          string
	Readiness          TaskDataReadiness
	ChunkLengths       []uint32
	OutputLeafCount    uint64
	EvidenceBundle     *EvidenceBundleSummary
	RetainUntilHeight  uint64
	SignedInferReceipt *SignedInferReceipt
}

type TaskDataChunk struct {
	Offset uint64
	Data   []byte
	EOF    bool
}

// StorageConfirmation commits an INPUT, OUTPUT, or complete evidence bundle.
// SizeBytes is exact manifest size for bundles; artifacts have no confirmation.
type StorageConfirmation struct {
	SchemaVersion             uint32
	ChainID                   string
	BuilderOperator           string
	ServiceAuthorizationNonce uint64
	Key                       TaskDataKey
	SizeBytes                 uint64
	ArtifactTotalSizeBytes    uint64
	RetentionUntilHeight      uint64
	Signature                 []byte
}

type GetTaskDataMetadataRequest struct {
	Key  TaskDataKey
	Auth TaskDataRequestAuth
}

type FetchTaskDataRequest struct {
	Key   TaskDataKey
	Range *TaskDataRange
	Auth  TaskDataRequestAuth
}

type UploadTaskResultRequest struct {
	Key       TaskDataKey
	SizeBytes uint64
	MediaType string
	Auth      TaskDataRequestAuth
	Data      []byte
}

type FinalizeTaskResultRequest struct {
	TaskHash  string
	SessionID string
	TaskID    string
	Receipt   SignedInferReceipt
	// EvidenceKind names the one Worker bundle this finalize closes: the
	// A-level token bundle or the B-level value bundle.
	EvidenceKind nodewire.EvidenceKind
	Auth         TaskDataRequestAuth
}

type FinalizeTaskResultResponse struct {
	Idempotent                  bool
	OutputConfirmation          StorageConfirmation
	EvidenceBundleConfirmations []StorageConfirmation
}

type FinalizeVerifierEvidenceRequest struct {
	TaskHash         string
	SessionID        string
	TaskID           string
	VerifyRound      uint32
	VerifierOperator string
	Receipt          nodewire.ResultReceiptV3
	Auth             TaskDataRequestAuth
}

type FinalizeVerifierEvidenceResponse struct {
	Idempotent                 bool
	EvidenceBundleConfirmation StorageConfirmation
}

type SubmitInferReceiptRequest struct{ Receipt SignedInferReceipt }
type SubmitVerifyCommitRequest struct{ Commit nodewire.VerifyCommitV1 }
type SubmitVerifyResultRequest struct{ Receipt nodewire.ResultReceiptV3 }

// VerifyRelayAck reports receipt by the Builder, not chain acceptance.
type VerifyRelayAck struct {
	Idempotent        bool
	CommitKey         codec.Hash
	SigningDigest     codec.Hash
	ResultPayloadHash codec.Hash
}

type TaskDataClient interface {
	OpenTaskOutputStream(context.Context, string, OutputStreamRequest) (TaskOutputStream, error)
	GetTaskDataMetadata(context.Context, string, GetTaskDataMetadataRequest) (TaskDataMetadata, error)
	FetchTaskData(context.Context, string, FetchTaskDataRequest, func(TaskDataChunk) error) error
	UploadTaskResultObject(context.Context, string, UploadTaskResultRequest) (TaskDataMetadata, error)
	FinalizeTaskResult(context.Context, string, FinalizeTaskResultRequest) (FinalizeTaskResultResponse, error)
	FinalizeVerifierEvidence(context.Context, string, FinalizeVerifierEvidenceRequest) (FinalizeVerifierEvidenceResponse, error)
	SubmitInferReceipt(context.Context, string, SubmitInferReceiptRequest) error
	SubmitVerifyCommit(context.Context, string, SubmitVerifyCommitRequest) (VerifyRelayAck, error)
	SubmitVerifyResult(context.Context, string, SubmitVerifyResultRequest) (VerifyRelayAck, error)
}

type Client interface {
	ValidateOutputPackage(context.Context, OutputPackage) error
	Publish(context.Context, PublishRequest) error
}
