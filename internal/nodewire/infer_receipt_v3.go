package nodewire

// InferReceiptV3 of wire v0.3.0 (TrueOpen/wire#14, task/infer_receipt_v3.json).
// It is added beside InferReceiptV2 so the encoding can be checked against the
// published vector before the dependency is raised; nothing produces it yet.

import (
	"bytes"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainInferReceiptV3               = "TRUEOPEN_INFER_RECEIPT_V3"
	InferReceiptSchemaVersionV3 uint32 = 3
)

// EvidenceKindWorkerTokenOpening is the A-level Worker evidence kind that v0.3.0
// adds. V2 derivations keep refusing it through canonicalEvidenceKind; only the
// V3 receipt accepts it.
const EvidenceKindWorkerTokenOpening EvidenceKind = 4

// InferReceiptV3 is in schema field-number order, which is also the frozen
// preimage order. ServiceSignature is excluded from the preimage.
//
// The four key commitments are ADR-0024's reserved encryption slots. Until
// encryption activates only PLAINTEXT is accepted, and every slot must be
// ZERO32; a receipt carrying anything else is refused rather than signed.
type InferReceiptV3 struct {
	SchemaVersion               uint32
	ChainID                     string
	TaskID                      []byte // Hash32
	TaskHash                    []byte // Hash32
	WorkerOperatorAddress       string // canonical Bech32; framed as address bytes
	ServiceAuthorizationNonce   uint64
	GenerationParamsDigest      []byte // Hash32
	OutputHash                  []byte // Hash32
	OutputSizeBytes             uint64
	RequiredEvidenceCommitments []EvidenceCommitmentV1
	ExpiryHeight                uint64
	ServiceSignature            []byte // excluded from the preimage
	GeneratedTokenCount         uint64
	OutputLeafCount             uint64
	OutputKeyCommitment         []byte // Hash32, ZERO32 in plaintext
	WorkerTokenKeyCommitment    []byte // Hash32, ZERO32 in plaintext
	WorkerValueKeyCommitment    []byte // Hash32, ZERO32 in plaintext
	CiphertextOutputRoot        []byte // Hash32, ZERO32 in plaintext
}

// InferEvidenceCommitmentsV3Hash derives evidence_commitments_hash for a V3
// receipt. The frame is the V2 one under the same domain; what changes is the
// list, which must be exactly the Worker value commitment (kind 1) followed by
// the Worker token commitment (kind 4).
func InferEvidenceCommitmentsV3Hash(items []EvidenceCommitmentV1) (codec.Hash, error) {
	fields, err := inferEvidenceCommitmentsV3Fields(items)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainInferEvidenceCommitmentsV1, fields...)
}

func inferEvidenceCommitmentsV3Fields(items []EvidenceCommitmentV1) ([]hfields.Field, error) {
	want := [...]EvidenceKind{EvidenceKindWorkerValueOpening, EvidenceKindWorkerTokenOpening}
	if len(items) != len(want) {
		return nil, fmt.Errorf("a V3 receipt carries exactly %d evidence commitments, got %d", len(want), len(items))
	}
	elements := []hfields.Field{hfields.Uint32(uint32(len(items)))}
	for index, item := range items {
		if item.EvidenceKind != want[index] {
			return nil, fmt.Errorf("required_evidence_commitments[%d] has kind %d, want %d", index, item.EvidenceKind, want[index])
		}
		hashOrRoot, err := canonicalHash32("evidence_hash_or_root", item.EvidenceHashOrRoot)
		if err != nil {
			return nil, fmt.Errorf("required_evidence_commitments[%d]: %w", index, err)
		}
		elements = append(elements, hfields.Frame(
			hfields.Uint32(uint32(item.EvidenceKind)),
			hfields.Bytes(hashOrRoot),
			hfields.Uint64(item.EncodedSizeBytes),
		))
	}
	return []hfields.Field{hfields.Uint32(uint32(len(items))), hfields.Frame(elements...)}, nil
}

// InferReceiptV3SigningPreimage frames the seventeen signed fields in schema
// order; the evidence list enters through its hash.
func InferReceiptV3SigningPreimage(receipt InferReceiptV3) ([]byte, error) {
	if receipt.SchemaVersion != InferReceiptSchemaVersionV3 {
		return nil, fmt.Errorf("infer receipt schema_version must be %d", InferReceiptSchemaVersionV3)
	}
	chainID, err := canonicalUTF8Field("chain_id", receipt.ChainID)
	if err != nil {
		return nil, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", receipt.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", receipt.TaskID},
		{"task_hash", receipt.TaskHash},
		{"generation_params_digest", receipt.GenerationParamsDigest},
		{"output_hash", receipt.OutputHash},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, err
		}
	}
	keyCommitments := [...]struct {
		name  string
		value []byte
	}{
		{"output_key_commitment", receipt.OutputKeyCommitment},
		{"worker_token_key_commitment", receipt.WorkerTokenKeyCommitment},
		{"worker_value_key_commitment", receipt.WorkerValueKeyCommitment},
		{"ciphertext_output_root", receipt.CiphertextOutputRoot},
	}
	for _, key := range keyCommitments {
		if err := requirePlaintextSlot(key.name, key.value); err != nil {
			return nil, err
		}
	}
	evidenceCommitmentsHash, err := InferEvidenceCommitmentsV3Hash(receipt.RequiredEvidenceCommitments)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainInferReceiptV3,
		hfields.Uint32(receipt.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(receipt.TaskID),
		hfields.Bytes(receipt.TaskHash),
		hfields.Bytes(worker),
		hfields.Uint64(receipt.ServiceAuthorizationNonce),
		hfields.Bytes(receipt.GenerationParamsDigest),
		hfields.Bytes(receipt.OutputHash),
		hfields.Uint64(receipt.OutputSizeBytes),
		hfields.Hash(evidenceCommitmentsHash),
		hfields.Uint64(receipt.ExpiryHeight),
		hfields.Uint64(receipt.GeneratedTokenCount),
		hfields.Uint64(receipt.OutputLeafCount),
		hfields.Bytes(receipt.OutputKeyCommitment),
		hfields.Bytes(receipt.WorkerTokenKeyCommitment),
		hfields.Bytes(receipt.WorkerValueKeyCommitment),
		hfields.Bytes(receipt.CiphertextOutputRoot),
	)
}

// InferReceiptV3SigningDigest is the V3 receipt digest: the value a Worker
// signs and the receipt's identity on chain.
func InferReceiptV3SigningDigest(receipt InferReceiptV3) (codec.Hash, error) {
	return digestOf(InferReceiptV3SigningPreimage(receipt))
}

// requirePlaintextSlot enforces the plaintext rule for one reserved encryption
// slot: exactly 32 raw bytes, all zero.
func requirePlaintextSlot(name string, value []byte) error {
	if _, err := canonicalHash32(name, value); err != nil {
		return err
	}
	if !bytes.Equal(value, make([]byte, len(value))) {
		return fmt.Errorf("%s must be ZERO32 while only PLAINTEXT is accepted", name)
	}
	return nil
}
