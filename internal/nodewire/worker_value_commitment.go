package nodewire

// The WORKER_VALUE_OPENING commitment is published in wire v0.4.1's
// registry/v1/domains.json and task/worker_value_commitment_v2.json fixture.

import (
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

// FinishReasonV1 is the closed successful termination set a Worker may commit.
// The numbers are the frozen task/v1/evidence.proto values and are what the
// preimage frames as uint32_be. An error or cancellation outcome has no value
// here at all: it cannot produce an accepted InferReceipt, so UNSPECIFIED is
// never written and is rejected before hashing.
type FinishReasonV1 int32

const (
	FinishReasonV1Unspecified       FinishReasonV1 = 0
	FinishReasonV1EosToken          FinishReasonV1 = 1
	FinishReasonV1StopSequence      FinishReasonV1 = 2
	FinishReasonV1MaxOutputTokens   FinishReasonV1 = 3
	FinishReasonV1MaxOutputDuration FinishReasonV1 = 4
)

// SuccessfulFinishReasonsV1 returns every value canonicalFinishReasonV1 accepts,
// in frozen numeric order. It lives beside the enum so a value added upstream is
// added in one place, and it exists because the commitment's finish_reason is a
// preimage field with no Verifier-readable source: it is neither a receipt field
// nor an on-chain column, so a consumer re-deriving the commitment has to
// resolve it against this closed set. Growing the set upstream without updating
// this list makes such a consumer refuse a valid commitment -- which is the safe
// direction, and is why the list is not open-coded at the callsite.
func SuccessfulFinishReasonsV1() []FinishReasonV1 {
	return []FinishReasonV1{
		FinishReasonV1EosToken,
		FinishReasonV1StopSequence,
		FinishReasonV1MaxOutputTokens,
		FinishReasonV1MaxOutputDuration,
	}
}

const (
	// WorkerValueCommitmentSchemaVersionV2 is the only commitment schema version
	// the frozen SubmitInferReceipt handler supports. It is not an alias of
	// InferReceiptSchemaVersionV2: it versions the evidence commitment behind one
	// element of the receipt, and the locked Profile carries it per requirement
	// (InferEvidenceRequirementV1.commitment_schema_version).
	WorkerValueCommitmentSchemaVersionV2 uint32 = 2
	// MaxEvidenceEncodedSizeBytesV1 is the contract ceiling on one evidence
	// element's encoded_size_bytes. Every locked Profile's max_encoded_size_bytes
	// is validated into 1..MaxEvidenceEncodedSizeBytesV1, so this is the loosest
	// bound any profile can grant and the tightest bound derivable without
	// reading one.
	MaxEvidenceEncodedSizeBytesV1 uint64 = 1 << 40
)

// WorkerValueCommitmentV2 is the canonical fixed-field commitment behind the
// single WORKER_VALUE_OPENING evidence item. Fields are in schema field-number
// order, which is also the frozen preimage order.
type WorkerValueCommitmentV2 struct {
	SchemaVersion              uint32
	ChainID                    string
	TaskID                     []byte // Hash32
	AcceptedTaskHash           []byte // Hash32
	WorkerOperatorAddress      string // canonical Bech32; framed as codec bytes
	GenerationParamsDigest     []byte // Hash32
	EvidenceSchemaHash         []byte // Hash32
	OutputHash                 []byte // Hash32
	OutputSizeBytes            uint64
	FinishReason               FinishReasonV1
	TraceRoot                  []byte // Hash32
	TraceEncodedSizeBytes      uint64
	CheckpointRoot             []byte // Hash32
	CheckpointEncodedSizeBytes uint64
	GeneratedTokenCount        uint64
	OutputLeafCount            uint64
	InputTokenIDsHash          []byte // Hash32
	GeneratedTokenIDsHash      []byte // Hash32
	InputTokenIDsSizeBytes     uint64
	GeneratedTokenIDsSizeBytes uint64
}

// WorkerValueCommitmentPreimage frames all twenty fields in schema order.
// The operator is decoded address bytes and finish_reason is uint32_be.
func WorkerValueCommitmentPreimage(value WorkerValueCommitmentV2) ([]byte, error) {
	fields, _, err := workerValueCommitmentFields(value)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainWorkerValueCommitmentV2, fields...)
}

// WorkerValueCommitment returns the evidence digest and the checked sum of the
// trace, checkpoint, input-token and generated-token artifact sizes. Keeper
// retains this digest opaquely; Nexus and Verifier recompute it from artifacts.
func WorkerValueCommitment(value WorkerValueCommitmentV2) (codec.Hash, uint64, error) {
	fields, encodedSizeBytes, err := workerValueCommitmentFields(value)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	digest, err := hfields.Digest(DomainWorkerValueCommitmentV2, fields...)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	return digest, encodedSizeBytes, nil
}

// Keep validation, field order and the four-artifact size sum shared by both
// preimage and digest derivation.
func workerValueCommitmentFields(value WorkerValueCommitmentV2) ([]hfields.Field, uint64, error) {
	if value.SchemaVersion != WorkerValueCommitmentSchemaVersionV2 {
		return nil, 0, fmt.Errorf("worker value schema_version must be %d", WorkerValueCommitmentSchemaVersionV2)
	}
	if value.ChainID == "" {
		return nil, 0, fmt.Errorf("chain_id must be non-empty")
	}
	chainID, err := canonicalUTF8Field("chain_id", value.ChainID)
	if err != nil {
		return nil, 0, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", value.WorkerOperatorAddress)
	if err != nil {
		return nil, 0, err
	}
	hashes := [...]struct {
		name  string
		value []byte
	}{
		{"task_id", value.TaskID},
		{"accepted_task_hash", value.AcceptedTaskHash},
		{"generation_params_digest", value.GenerationParamsDigest},
		{"evidence_schema_hash", value.EvidenceSchemaHash},
		{"output_hash", value.OutputHash},
		{"trace_root", value.TraceRoot},
		{"checkpoint_root", value.CheckpointRoot},
		{"input_token_ids_hash", value.InputTokenIDsHash},
		{"generated_token_ids_hash", value.GeneratedTokenIDsHash},
	}
	for _, hash := range hashes {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, 0, err
		}
	}
	if value.TraceEncodedSizeBytes == 0 || value.CheckpointEncodedSizeBytes == 0 {
		return nil, 0, fmt.Errorf("trace and checkpoint encoded sizes must be positive")
	}
	if value.OutputLeafCount == 0 {
		return nil, 0, fmt.Errorf("output_leaf_count must be positive")
	}
	for _, size := range []uint64{value.InputTokenIDsSizeBytes, value.GeneratedTokenIDsSizeBytes} {
		if size < 4 || size%4 != 0 || size > 4+4*MaxTokenIDCountV1 {
			return nil, 0, fmt.Errorf("token IDs size must encode a bounded uint32 count and uint32 IDs")
		}
	}
	if value.GeneratedTokenCount > MaxTokenIDCountV1 || value.GeneratedTokenIDsSizeBytes != 4+4*value.GeneratedTokenCount {
		return nil, 0, fmt.Errorf("generated token IDs size does not match generated_token_count")
	}
	var encodedSizeBytes uint64
	for _, size := range []uint64{value.TraceEncodedSizeBytes, value.CheckpointEncodedSizeBytes, value.InputTokenIDsSizeBytes, value.GeneratedTokenIDsSizeBytes} {
		if size > MaxEvidenceEncodedSizeBytesV1-encodedSizeBytes {
			return nil, 0, fmt.Errorf("combined evidence encoded size exceeds %d", MaxEvidenceEncodedSizeBytesV1)
		}
		encodedSizeBytes += size
	}
	finishReason, err := canonicalFinishReasonV1(value.FinishReason)
	if err != nil {
		return nil, 0, err
	}
	return []hfields.Field{
		hfields.Uint32(value.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(value.TaskID),
		hfields.Bytes(value.AcceptedTaskHash),
		hfields.Bytes(worker),
		hfields.Bytes(value.GenerationParamsDigest),
		hfields.Bytes(value.EvidenceSchemaHash),
		hfields.Bytes(value.OutputHash),
		hfields.Uint64(value.OutputSizeBytes),
		hfields.Uint32(finishReason),
		hfields.Bytes(value.TraceRoot),
		hfields.Uint64(value.TraceEncodedSizeBytes),
		hfields.Bytes(value.CheckpointRoot),
		hfields.Uint64(value.CheckpointEncodedSizeBytes),
		hfields.Uint64(value.GeneratedTokenCount),
		hfields.Uint64(value.OutputLeafCount),
		hfields.Bytes(value.InputTokenIDsHash),
		hfields.Bytes(value.GeneratedTokenIDsHash),
		hfields.Uint64(value.InputTokenIDsSizeBytes),
		hfields.Uint64(value.GeneratedTokenIDsSizeBytes),
	}, encodedSizeBytes, nil
}

// canonicalFinishReasonV1 rejects the unspecified value and every unsuccessful
// or unknown outcome. Node phrases the same check as "not a successful V1
// reason", and the wording is kept so an operator comparing the two logs sees
// one message.
func canonicalFinishReasonV1(reason FinishReasonV1) (uint32, error) {
	switch reason {
	case FinishReasonV1EosToken, FinishReasonV1StopSequence,
		FinishReasonV1MaxOutputTokens, FinishReasonV1MaxOutputDuration:
		return uint32(reason), nil
	default:
		return 0, fmt.Errorf("finish_reason %d is not a successful V1 reason", int32(reason))
	}
}
