package nodewire

// The Verifier result contracts of wire v0.3.0 (task/result_receipt_v3.json).
// The commit binds the Verifier's own value root instead of the reveal payload
// hash, so it can be locked before the Worker's values are readable.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainResultCommitmentV3             = "TRUEOPEN_RESULT_COMMITMENT_V3"
	DomainResultV3                       = "TRUEOPEN_RESULT_V3"
	DomainVerifierResultPayloadV2        = "TRUEOPEN_VERIFIER_RESULT_PAYLOAD_V2"
	ResultReceiptSchemaVersionV3  uint32 = 3
)

// ResultCommitmentV3 binds the Verifier value root to the task, round, verifier
// and a salt that must never be ZERO32.
type ResultCommitmentV3 struct {
	ChainID                 string
	TaskID                  []byte // Hash32
	TaskHash                []byte // Hash32
	VerifyRound             uint32
	VerifierOperatorAddress string // canonical Bech32; framed as address bytes
	VerifierValueRoot       []byte // Hash32
	Salt                    []byte // Hash32, non-zero
}

// ResultCommitmentHash derives commit_hash.
func ResultCommitmentHash(commitment ResultCommitmentV3) (codec.Hash, error) {
	chainID, err := canonicalUTF8Field("chain_id", commitment.ChainID)
	if err != nil {
		return codec.Hash{}, err
	}
	if chainID == "" {
		return codec.Hash{}, fmt.Errorf("chain_id must be non-empty")
	}
	for _, field := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", commitment.TaskID}, {"task_hash", commitment.TaskHash},
		{"verifier_value_root", commitment.VerifierValueRoot}, {"salt", commitment.Salt},
	} {
		if _, err := canonicalHash32(field.name, field.value); err != nil {
			return codec.Hash{}, err
		}
	}
	if err := requireNonZero32("salt", commitment.Salt); err != nil {
		return codec.Hash{}, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", commitment.VerifierOperatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainResultCommitmentV3,
		hfields.String(chainID), hfields.Bytes(commitment.TaskID), hfields.Bytes(commitment.TaskHash),
		hfields.Uint32(commitment.VerifyRound), hfields.Bytes(verifier),
		hfields.Bytes(commitment.VerifierValueRoot), hfields.Bytes(commitment.Salt))
}

// ResultPayloadHash derives result_payload_hash over the canonical V2 reveal
// payload. It is the reveal's integrity digest and no longer enters the commit.
func ResultPayloadHash(payload []byte) codec.Hash {
	return codec.HashV1(DomainVerifierResultPayloadV2, payload)
}

// ResultReceiptV3 is the V2 credential plus the Verifier value root, the metric
// leaf count and the reserved Verifier evidence key slot, in schema
// field-number order. Field 18 is ServiceSignature and is excluded from the
// preimage; field 19 is reserved upstream.
type ResultReceiptV3 struct {
	SchemaVersion                     uint32
	ChainID                           string
	TaskID                            []byte // Hash32
	VerifyRound                       uint32
	VerifierOperatorAddress           string // canonical Bech32; framed as address bytes
	ServiceAuthorizationNonce         uint64
	GenerationParamsDigest            []byte // Hash32
	MetricRoot                        []byte // Hash32
	MetricSummary                     MetricSummaryV1
	AggregateProofHash                []byte // Hash32
	VerifierEvidenceBundleHash        []byte // Hash32
	VerifierEvidenceManifestSizeBytes uint64
	Salt                              []byte // Hash32
	ExpiryHeight                      uint64
	VerifierValueRoot                 []byte // Hash32
	MetricLeafCount                   uint32
	VerifierEvidenceKeyCommitment     []byte // Hash32, ZERO32 in plaintext
	ServiceSignature                  []byte // excluded from the preimage
}

// ResultReceiptSigningPreimage frames the seventeen signed fields in schema
// order. MetricSummary is one nested field, as in V2.
func ResultReceiptSigningPreimage(receipt ResultReceiptV3) ([]byte, error) {
	if receipt.SchemaVersion != ResultReceiptSchemaVersionV3 {
		return nil, fmt.Errorf("result receipt schema_version must be %d", ResultReceiptSchemaVersionV3)
	}
	chainID, err := canonicalUTF8Field("chain_id", receipt.ChainID)
	if err != nil {
		return nil, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", receipt.VerifierOperatorAddress)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", receipt.TaskID},
		{"generation_params_digest", receipt.GenerationParamsDigest},
		{"metric_root", receipt.MetricRoot},
		{"aggregate_proof_hash", receipt.AggregateProofHash},
		{"verifier_evidence_bundle_hash", receipt.VerifierEvidenceBundleHash},
		{"salt", receipt.Salt},
		{"verifier_value_root", receipt.VerifierValueRoot},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, err
		}
	}
	if err := requireNonZero32("salt", receipt.Salt); err != nil {
		return nil, err
	}
	if err := requirePlaintextSlot("verifier_evidence_key_commitment", receipt.VerifierEvidenceKeyCommitment); err != nil {
		return nil, err
	}
	// The count is fixed by the summary, so a receipt that disagrees with its
	// own summary is refused before it is signed.
	leaves := uint64(receipt.MetricSummary.FiniteCount) + uint64(receipt.MetricSummary.MissingComparedCount)
	if uint64(receipt.MetricLeafCount) != leaves {
		return nil, fmt.Errorf("metric_leaf_count %d does not equal finite_count + missing_compared_count = %d",
			receipt.MetricLeafCount, leaves)
	}
	return hfields.Preimage(
		DomainResultV3,
		hfields.Uint32(receipt.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(receipt.TaskID),
		hfields.Uint32(receipt.VerifyRound),
		hfields.Bytes(verifier),
		hfields.Uint64(receipt.ServiceAuthorizationNonce),
		hfields.Bytes(receipt.GenerationParamsDigest),
		hfields.Bytes(receipt.MetricRoot),
		metricSummaryFrame(receipt.MetricSummary),
		hfields.Bytes(receipt.AggregateProofHash),
		hfields.Bytes(receipt.VerifierEvidenceBundleHash),
		hfields.Uint64(receipt.VerifierEvidenceManifestSizeBytes),
		hfields.Bytes(receipt.Salt),
		hfields.Uint64(receipt.ExpiryHeight),
		hfields.Bytes(receipt.VerifierValueRoot),
		hfields.Uint32(receipt.MetricLeafCount),
		hfields.Bytes(receipt.VerifierEvidenceKeyCommitment),
	)
}

// ResultReceiptSigningDigest is the V3 result credential digest.
func ResultReceiptSigningDigest(receipt ResultReceiptV3) (codec.Hash, error) {
	return digestOf(ResultReceiptSigningPreimage(receipt))
}

func requireNonZero32(name string, value []byte) error {
	for _, b := range value {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("%s must not be ZERO32", name)
}
