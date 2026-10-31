package nodewire

// The verifier handraise as wire signs it (task/task_domains_v1.json). The
// domain keeps its V1 name, but model_id is the raw Hash32 model identity and
// recipient_pubkey is appended as the last signed field. The per-task Worker
// handraise is retired with wire 916e393.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// VerifierHandraiseV1 is the verifier handraise wire. ServiceSignature is
// outside the preimage.
type VerifierHandraiseV1 struct {
	SchemaVersion             uint32
	ChainID                   string
	TaskID                    []byte // Hash32
	VerifyRound               uint32
	InferReceiptHash          []byte // Hash32
	OutputHash                []byte // Hash32
	ModelID                   []byte // Hash32
	ProfileVersion            uint32
	Member                    CandidateMemberRefV1
	Duty                      Duty
	ServiceAuthorizationNonce uint64
	ExpiryHeight              uint64
	RecipientPubkey           []byte // empty in plaintext
	ServiceSignature          []byte // excluded from the preimage
}

// VerifierHandraiseSigningPreimage frames the thirteen signed fields in
// order.
func VerifierHandraiseSigningPreimage(handraise VerifierHandraiseV1) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", handraise.ChainID)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"task_id", handraise.TaskID}, {"infer_receipt_hash", handraise.InferReceiptHash},
		{"output_hash", handraise.OutputHash}, {"model_id", handraise.ModelID},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, err
		}
	}
	member, err := candidateMemberRefFrame(handraise.Member)
	if err != nil {
		return nil, err
	}
	duty, err := canonicalDuty(handraise.Duty)
	if err != nil {
		return nil, err
	}
	if err := requireEmptyRecipient(handraise.RecipientPubkey); err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainVerifierHandraiseV1,
		hfields.Uint32(handraise.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(handraise.TaskID),
		hfields.Uint32(handraise.VerifyRound),
		hfields.Bytes(handraise.InferReceiptHash),
		hfields.Bytes(handraise.OutputHash),
		hfields.Bytes(handraise.ModelID),
		hfields.Uint32(handraise.ProfileVersion),
		member,
		hfields.Uint32(duty),
		hfields.Uint64(handraise.ServiceAuthorizationNonce),
		hfields.Uint64(handraise.ExpiryHeight),
		hfields.Bytes(handraise.RecipientPubkey),
	)
}

// VerifierHandraiseSigningDigest is the verifier handraise digest.
func VerifierHandraiseSigningDigest(handraise VerifierHandraiseV1) (codec.Hash, error) {
	return digestOf(VerifierHandraiseSigningPreimage(handraise))
}

func requireEmptyRecipient(pubkey []byte) error {
	if len(pubkey) != 0 {
		return fmt.Errorf("recipient_pubkey must be empty while only PLAINTEXT is accepted")
	}
	return nil
}
