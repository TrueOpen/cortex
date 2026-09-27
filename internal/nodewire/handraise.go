package nodewire

// Both handraises as wire v0.3.0 signs them (task/task_domains_v1.json). The
// domains keep their V1 names, but model_id is the raw Hash32 model identity
// and recipient_pubkey is appended as the last signed field.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// WorkerHandraiseV1 is the worker handraise wire. RecipientPubkey is a
// reserved encryption key slot and must be empty while only PLAINTEXT is
// accepted. ServiceSignature is outside the preimage.
type WorkerHandraiseV1 struct {
	SchemaVersion             uint32
	ChainID                   string
	TaskID                    []byte // Hash32
	TaskHash                  []byte // Hash32
	ModelID                   []byte // Hash32
	ProfileVersion            uint32
	Member                    CandidateMemberRefV1
	Duty                      Duty
	ServiceAuthorizationNonce uint64
	ExpiryHeight              uint64
	RecipientPubkey           []byte // empty in plaintext
	ServiceSignature          []byte // excluded from the preimage
}

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

// WorkerHandraiseSigningPreimage frames the eleven signed fields in order.
func WorkerHandraiseSigningPreimage(handraise WorkerHandraiseV1) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", handraise.ChainID)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{{"task_id", handraise.TaskID}, {"task_hash", handraise.TaskHash}, {"model_id", handraise.ModelID}} {
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
		DomainWorkerHandraiseV1,
		hfields.Uint32(handraise.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(handraise.TaskID),
		hfields.Bytes(handraise.TaskHash),
		hfields.Bytes(handraise.ModelID),
		hfields.Uint32(handraise.ProfileVersion),
		member,
		hfields.Uint32(duty),
		hfields.Uint64(handraise.ServiceAuthorizationNonce),
		hfields.Uint64(handraise.ExpiryHeight),
		hfields.Bytes(handraise.RecipientPubkey),
	)
}

// WorkerHandraiseSigningDigest is the worker handraise digest.
func WorkerHandraiseSigningDigest(handraise WorkerHandraiseV1) (codec.Hash, error) {
	return digestOf(WorkerHandraiseSigningPreimage(handraise))
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
