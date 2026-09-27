package builderclient

import (
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// InferReceiptFacts supplies the signed InferReceiptV3 fields of wire v0.3.0.
// The schema is fixed at 3; output_hash and output_leaf_count come from the same
// retained chunk stream, and evidence bounds come from the locked Profile. The
// four reserved encryption key slots are ZERO32 while only PLAINTEXT is accepted.
type InferReceiptFacts struct {
	ChainID string
	// TaskID is the canonical lowercase 64-hex Keeper task id.
	TaskID string
	// TaskHash is TaskCoreState.accepted_task_hash, canonical lowercase 64-hex.
	TaskHash string
	// WorkerOperatorAddress is canonical Bech32; the preimage frames its address
	// codec bytes, never the text.
	WorkerOperatorAddress string
	// ServiceAuthorizationNonce is the Worker's current CORTEX-domain service
	// authorization nonce as Keeper holds it.
	ServiceAuthorizationNonce uint64
	// GenerationParamsDigest is TaskAssignmentState.generation_params_digest,
	// canonical lowercase 64-hex.
	GenerationParamsDigest string
	OutputHash             codec.Hash
	OutputSizeBytes        uint64
	OutputLeafCount        uint64
	GeneratedTokenCount    uint64
	// RequiredEvidenceCommitments must be exactly the locked Verification
	// Profile's required evidence kind set, strictly ascending and unique: the
	// value and token commitments WorkerEvidenceCommitments derives.
	RequiredEvidenceCommitments []EvidenceCommitment
	// ProfileEvidenceRequirements is the locked Profile's
	// evidence_schema.required_infer_evidence, served by hub.v1.Query/Profile
	// as profile.verification_profile.evidence_schema.required_infer_evidence. It
	// is required, not optional: the frozen handler bounds every commitment by
	// requirement.max_encoded_size_bytes of that SPECIFIC Profile
	// (msg_server_receipt.go:307-309), which is per-Profile data no derivation can
	// supply.
	ProfileEvidenceRequirements []InferEvidenceRequirement
	ExpiryHeight                uint64
}

// ErrInferReceiptInputUnavailable marks the refusals below as missing protocol
// inputs rather than malformed caller data, so a caller can tell "Cortex cannot
// know this yet" apart from "this receipt is wrong". Every refusal names its own
// field, so a caller that wraps or logs the error can still tell which input was
// unavailable.
var ErrInferReceiptInputUnavailable = fmt.Errorf("frozen infer receipt input is unavailable")

// BuildInferReceipt assembles the unsigned frozen receipt and returns the digest
// the Worker's current service key must sign. The digest is both
// infer_receipt_signing_digest and infer_receipt_hash.
//
// task_hash must be TaskCoreState.accepted_task_hash and NOT order_digest: Node
// proves order_digest == sha256(order_envelope) while
// task_hash == H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V1", canonical TaskOrderV1), so
// relaying the order digest under this name produces a receipt the Keeper
// rejects at msg_server_receipt.go's core.AcceptedTaskHash comparison.
// generation_params_digest must equal TaskAssignmentState.generation_params_digest
// byte for byte. Neither is validated here, because InferReceiptSigningDigest
// below refuses an unset or all-zero value for both and one refusal is enough.
func BuildInferReceipt(facts InferReceiptFacts) (SignedInferReceipt, codec.Hash, error) {
	// required_evidence_commitments is checked against the locked Profile's real
	// requirement set and never against a derived stand-in. The kinds and count
	// of that set ARE derivable, but max_encoded_size_bytes is not: it is
	// per-Profile data, and the handler bounds encoded_size_bytes by that specific
	// Profile's value. Substituting the contract ceiling would let a caller that
	// never read the Profile sign a body the Keeper rejects on size, so the
	// requirement set is required input rather than a permissive default.
	if len(facts.ProfileEvidenceRequirements) == 0 {
		return SignedInferReceipt{}, codec.Hash{}, fmt.Errorf(
			"%w: required_evidence_commitments must be bounded by the locked Profile's "+
				"evidence_schema.required_infer_evidence, which hub.v1.Query/Profile serves as "+
				"profile.verification_profile.evidence_schema.required_infer_evidence; "+
				"the contract ceiling is not a substitute, because the handler "+
				"compares encoded_size_bytes against that Profile's own max_encoded_size_bytes",
			ErrInferReceiptInputUnavailable)
	}
	if err := ValidateProfileEvidenceCommitments(
		facts.ProfileEvidenceRequirements, facts.RequiredEvidenceCommitments,
	); err != nil {
		return SignedInferReceipt{}, codec.Hash{}, fmt.Errorf("build frozen infer receipt: %w", err)
	}
	receipt := SignedInferReceipt{
		SchemaVersion:               nodewire.InferReceiptSchemaVersionV3,
		ChainID:                     facts.ChainID,
		TaskID:                      facts.TaskID,
		TaskHash:                    facts.TaskHash,
		WorkerOperatorAddress:       facts.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   facts.ServiceAuthorizationNonce,
		GenerationParamsDigest:      facts.GenerationParamsDigest,
		OutputHash:                  hex.EncodeToString(facts.OutputHash[:]),
		OutputSizeBytes:             facts.OutputSizeBytes,
		OutputLeafCount:             facts.OutputLeafCount,
		GeneratedTokenCount:         facts.GeneratedTokenCount,
		RequiredEvidenceCommitments: append([]EvidenceCommitment(nil), facts.RequiredEvidenceCommitments...),
		ExpiryHeight:                facts.ExpiryHeight,
	}
	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		return SignedInferReceipt{}, codec.Hash{}, fmt.Errorf("build frozen infer receipt: %w", err)
	}
	return receipt, digest, nil
}
