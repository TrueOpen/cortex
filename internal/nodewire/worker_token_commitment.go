package nodewire

// The A-level WORKER_TOKEN_OPENING commitment of wire v0.3.0 (TrueOpen/wire#14,
// task/worker_token_commitment_v1.json). It is added beside the V2 commitment
// so the encoding can be checked against the published vector before the
// dependency is raised; nothing produces it yet.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainWorkerTokenCommitmentV1               = "TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1"
	WorkerTokenCommitmentSchemaVersionV1 uint32 = 1
)

// WorkerTokenCommitmentV1 binds the Worker's input and generated token-id
// artifacts, the output and the finish reason. Fields are in schema
// field-number order, which is also the frozen preimage order.
type WorkerTokenCommitmentV1 struct {
	SchemaVersion              uint32
	ChainID                    string
	TaskID                     []byte // Hash32
	AcceptedTaskHash           []byte // Hash32
	WorkerOperatorAddress      string // canonical Bech32; framed as address bytes
	GenerationParamsDigest     []byte // Hash32
	EvidenceSchemaHash         []byte // Hash32
	OutputHash                 []byte // Hash32
	OutputSizeBytes            uint64
	OutputLeafCount            uint64
	FinishReason               FinishReasonV1
	GeneratedTokenCount        uint64
	InputTokenIDsHash          []byte // Hash32
	GeneratedTokenIDsHash      []byte // Hash32
	InputTokenIDsSizeBytes     uint64
	GeneratedTokenIDsSizeBytes uint64
}

// WorkerTokenCommitmentPreimage frames all sixteen fields in schema order.
func WorkerTokenCommitmentPreimage(value WorkerTokenCommitmentV1) ([]byte, error) {
	fields, _, err := workerTokenCommitmentFields(value)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainWorkerTokenCommitmentV1, fields...)
}

// WorkerTokenCommitment returns the evidence digest and the checked sum of the
// two token-id artifact sizes, which is the element's encoded_size_bytes.
func WorkerTokenCommitment(value WorkerTokenCommitmentV1) (codec.Hash, uint64, error) {
	fields, encodedSizeBytes, err := workerTokenCommitmentFields(value)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	digest, err := hfields.Digest(DomainWorkerTokenCommitmentV1, fields...)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	return digest, encodedSizeBytes, nil
}

func workerTokenCommitmentFields(value WorkerTokenCommitmentV1) ([]hfields.Field, uint64, error) {
	if value.SchemaVersion != WorkerTokenCommitmentSchemaVersionV1 {
		return nil, 0, fmt.Errorf("worker token schema_version must be %d", WorkerTokenCommitmentSchemaVersionV1)
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
		{"input_token_ids_hash", value.InputTokenIDsHash},
		{"generated_token_ids_hash", value.GeneratedTokenIDsHash},
	}
	for _, hash := range hashes {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, 0, err
		}
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
	// Both sizes are bounded above, so the sum cannot overflow or exceed the
	// per-element ceiling.
	encodedSizeBytes := value.InputTokenIDsSizeBytes + value.GeneratedTokenIDsSizeBytes
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
		hfields.Uint64(value.OutputLeafCount),
		hfields.Uint32(finishReason),
		hfields.Uint64(value.GeneratedTokenCount),
		hfields.Bytes(value.InputTokenIDsHash),
		hfields.Bytes(value.GeneratedTokenIDsHash),
		hfields.Uint64(value.InputTokenIDsSizeBytes),
		hfields.Uint64(value.GeneratedTokenIDsSizeBytes),
	}, encodedSizeBytes, nil
}
