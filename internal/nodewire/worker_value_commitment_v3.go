package nodewire

// The B-level WORKER_VALUE_OPENING commitment of wire v0.3.0 (TrueOpen/wire#14,
// task/worker_value_commitment_v3.json). Trace and checkpoint are gone: the
// commitment binds only the Merkle root of the Worker's per-position values and
// the exact size of the worker_values artifact. Nothing produces it yet.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainWorkerValueCommitmentV3               = "TRUEOPEN_WORKER_VALUE_COMMITMENT_V3"
	WorkerValueCommitmentSchemaVersionV3 uint32 = 3
)

// WorkerValueCommitmentV3 is in schema field-number order, which is also the
// frozen preimage order.
type WorkerValueCommitmentV3 struct {
	SchemaVersion                uint32
	ChainID                      string
	TaskID                       []byte // Hash32
	AcceptedTaskHash             []byte // Hash32
	WorkerOperatorAddress        string // canonical Bech32; framed as address bytes
	EvidenceSchemaHash           []byte // Hash32
	WorkerValueRoot              []byte // Hash32
	WorkerValuesEncodedSizeBytes uint64
}

// WorkerValueCommitmentV3Preimage frames all eight fields in schema order.
func WorkerValueCommitmentV3Preimage(value WorkerValueCommitmentV3) ([]byte, error) {
	fields, err := workerValueCommitmentV3Fields(value)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainWorkerValueCommitmentV3, fields...)
}

// WorkerValueCommitmentV3Digest returns the evidence digest and the element's
// encoded_size_bytes, which is the worker_values artifact size.
func WorkerValueCommitmentV3Digest(value WorkerValueCommitmentV3) (codec.Hash, uint64, error) {
	fields, err := workerValueCommitmentV3Fields(value)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	digest, err := hfields.Digest(DomainWorkerValueCommitmentV3, fields...)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	return digest, value.WorkerValuesEncodedSizeBytes, nil
}

func workerValueCommitmentV3Fields(value WorkerValueCommitmentV3) ([]hfields.Field, error) {
	if value.SchemaVersion != WorkerValueCommitmentSchemaVersionV3 {
		return nil, fmt.Errorf("worker value schema_version must be %d", WorkerValueCommitmentSchemaVersionV3)
	}
	if value.ChainID == "" {
		return nil, fmt.Errorf("chain_id must be non-empty")
	}
	chainID, err := canonicalUTF8Field("chain_id", value.ChainID)
	if err != nil {
		return nil, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", value.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", value.TaskID},
		{"accepted_task_hash", value.AcceptedTaskHash},
		{"evidence_schema_hash", value.EvidenceSchemaHash},
		{"worker_value_root", value.WorkerValueRoot},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, err
		}
	}
	// The artifact always carries its u32 leaf count, so it is never shorter
	// than four bytes.
	if value.WorkerValuesEncodedSizeBytes < 4 || value.WorkerValuesEncodedSizeBytes > MaxEvidenceEncodedSizeBytesV1 {
		return nil, fmt.Errorf("worker_values_encoded_size_bytes must be in 4..%d", MaxEvidenceEncodedSizeBytesV1)
	}
	return []hfields.Field{
		hfields.Uint32(value.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(value.TaskID),
		hfields.Bytes(value.AcceptedTaskHash),
		hfields.Bytes(worker),
		hfields.Bytes(value.EvidenceSchemaHash),
		hfields.Bytes(value.WorkerValueRoot),
		hfields.Uint64(value.WorkerValuesEncodedSizeBytes),
	}, nil
}
