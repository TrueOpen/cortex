package nodewire

// The successful finish reasons a Worker may commit, and the evidence size
// ceiling every commitment is bounded by.

import (
	"fmt"
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
	// FinishReasonV1UserStop is the Worker's assertion that the user stopped the
	// generation; it cannot be checked.
	FinishReasonV1UserStop FinishReasonV1 = 5
	// FinishReasonV1StopToken means the last generated token is one of the
	// order's stop_token_ids.
	FinishReasonV1StopToken FinishReasonV1 = 6
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
		FinishReasonV1UserStop,
		FinishReasonV1StopToken,
	}
}

const (
	// MaxEvidenceEncodedSizeBytesV1 is the contract ceiling on one evidence
	// element's encoded_size_bytes. Every locked Profile's max_encoded_size_bytes
	// is validated into 1..MaxEvidenceEncodedSizeBytesV1, so this is the loosest
	// bound any profile can grant and the tightest bound derivable without
	// reading one.
	MaxEvidenceEncodedSizeBytesV1 uint64 = 1 << 40
)

// canonicalFinishReasonV1 rejects the unspecified value and every unsuccessful
// or unknown outcome. Node phrases the same check as "not a successful V1
// reason", and the wording is kept so an operator comparing the two logs sees
// one message.
func canonicalFinishReasonV1(reason FinishReasonV1) (uint32, error) {
	switch reason {
	case FinishReasonV1EosToken, FinishReasonV1StopSequence,
		FinishReasonV1MaxOutputTokens, FinishReasonV1MaxOutputDuration,
		FinishReasonV1UserStop, FinishReasonV1StopToken:
		return uint32(reason), nil
	default:
		return 0, fmt.Errorf("finish_reason %d is not a successful V1 reason", int32(reason))
	}
}
