package nodewire

// The C-level WORKER_ANCHOR_OPENING commitment (ADR-0040). It binds the
// engine-side AnchorCommitV1 artifact (the anchor Merkle roots the engine
// produced at inference time, as served by its sidecar) to the task scope. The
// positions the chain samples are opened against that artifact; nothing else
// about the anchors enters the receipt.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainWorkerAnchorCommitmentV1               = "TRUEOPEN_WORKER_ANCHOR_COMMITMENT_V1"
	WorkerAnchorCommitmentSchemaVersionV1 uint32 = 1
)

// WorkerAnchorCommitmentV1 is in preimage order.
type WorkerAnchorCommitmentV1 struct {
	SchemaVersion         uint32
	ChainID               string
	TaskID                []byte // Hash32
	AcceptedTaskHash      []byte // Hash32
	WorkerOperatorAddress string // canonical Bech32; framed as address bytes
	EvidenceSchemaHash    []byte // Hash32
	AnchorCommitHash      []byte // Hash32: SHA-256 of the anchor_commit artifact bytes
	AnchorCommitSizeBytes uint64
}

// WorkerAnchorCommitmentV1Digest returns the evidence digest and the element's
// encoded_size_bytes, which is the anchor_commit artifact size.
func WorkerAnchorCommitmentV1Digest(value WorkerAnchorCommitmentV1) (codec.Hash, uint64, error) {
	if value.SchemaVersion != WorkerAnchorCommitmentSchemaVersionV1 {
		return codec.Hash{}, 0, fmt.Errorf("worker anchor schema_version must be %d", WorkerAnchorCommitmentSchemaVersionV1)
	}
	if value.ChainID == "" {
		return codec.Hash{}, 0, fmt.Errorf("chain_id must be non-empty")
	}
	chainID, err := canonicalUTF8Field("chain_id", value.ChainID)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", value.WorkerOperatorAddress)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", value.TaskID},
		{"accepted_task_hash", value.AcceptedTaskHash},
		{"evidence_schema_hash", value.EvidenceSchemaHash},
		{"anchor_commit_hash", value.AnchorCommitHash},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return codec.Hash{}, 0, err
		}
	}
	if value.AnchorCommitSizeBytes == 0 || value.AnchorCommitSizeBytes > MaxEvidenceEncodedSizeBytesV1 {
		return codec.Hash{}, 0, fmt.Errorf("anchor_commit_size_bytes must be in 1..%d", MaxEvidenceEncodedSizeBytesV1)
	}
	digest, err := hfields.Digest(DomainWorkerAnchorCommitmentV1,
		hfields.Uint32(value.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(value.TaskID),
		hfields.Bytes(value.AcceptedTaskHash),
		hfields.Bytes(worker),
		hfields.Bytes(value.EvidenceSchemaHash),
		hfields.Bytes(value.AnchorCommitHash),
		hfields.Uint64(value.AnchorCommitSizeBytes),
	)
	if err != nil {
		return codec.Hash{}, 0, err
	}
	return digest, value.AnchorCommitSizeBytes, nil
}
