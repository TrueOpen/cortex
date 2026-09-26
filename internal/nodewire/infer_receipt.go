package nodewire

// InferReceiptV3 of wire v0.3.0 (task/infer_receipt_v3.json).

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

// RequireWorkerEvidenceCommitmentsV3 checks that a V3 receipt carries exactly
// the Worker value commitment (kind 1) followed by the Worker token commitment
// (kind 4). EvidenceCommitmentsHash then frames them like any other list.
func RequireWorkerEvidenceCommitmentsV3(items []EvidenceCommitmentV1) error {
	want := [...]EvidenceKind{EvidenceKindWorkerValueOpening, EvidenceKindWorkerTokenOpening}
	if len(items) != len(want) {
		return fmt.Errorf("a V3 receipt carries exactly %d evidence commitments, got %d", len(want), len(items))
	}
	for index, item := range items {
		if item.EvidenceKind != want[index] {
			return fmt.Errorf("required_evidence_commitments[%d] has kind %d, want %d", index, item.EvidenceKind, want[index])
		}
	}
	return nil
}

// InferReceiptSigningPreimage frames the seventeen signed fields in schema
// order; the evidence list enters through its hash.
func InferReceiptSigningPreimage(receipt InferReceiptV3) ([]byte, error) {
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
	if err := RequireWorkerEvidenceCommitmentsV3(receipt.RequiredEvidenceCommitments); err != nil {
		return nil, err
	}
	evidenceCommitmentsHash, err := EvidenceCommitmentsHash(receipt.RequiredEvidenceCommitments)
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

// InferReceiptSigningDigest is the receipt digest: the value a Worker
// signs and the receipt's identity on chain.
func InferReceiptSigningDigest(receipt InferReceiptV3) (codec.Hash, error) {
	return digestOf(InferReceiptSigningPreimage(receipt))
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
