package nodewire

// The wire v0.3.0 shape of both handraises (TrueOpen/wire#14,
// task/task_domains_v1.json). The domains keep their V1 names, but model_id is
// now the raw Hash32 model identity and recipient_pubkey is appended as the
// last signed field. Added beside the V1 encoders; nothing produces them yet.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// WorkerHandraiseV030 is WorkerHandraiseV1 as wire v0.3.0 signs it.
// RecipientPubkey is ADR-0024's reserved key slot and must be empty while only
// PLAINTEXT is accepted.
type WorkerHandraiseV030 struct {
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

// VerifierHandraiseV030 is VerifierHandraiseV1 as wire v0.3.0 signs it.
type VerifierHandraiseV030 struct {
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

// WorkerHandraiseV030SigningPreimage frames the eleven signed fields in order.
func WorkerHandraiseV030SigningPreimage(handraise WorkerHandraiseV030) ([]byte, error) {
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

func WorkerHandraiseV030SigningDigest(handraise WorkerHandraiseV030) (codec.Hash, error) {
	return digestOf(WorkerHandraiseV030SigningPreimage(handraise))
}

// VerifierHandraiseV030SigningPreimage frames the thirteen signed fields in
// order.
func VerifierHandraiseV030SigningPreimage(handraise VerifierHandraiseV030) ([]byte, error) {
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

func VerifierHandraiseV030SigningDigest(handraise VerifierHandraiseV030) (codec.Hash, error) {
	return digestOf(VerifierHandraiseV030SigningPreimage(handraise))
}

func requireEmptyRecipient(pubkey []byte) error {
	if len(pubkey) != 0 {
		return fmt.Errorf("recipient_pubkey must be empty while only PLAINTEXT is accepted")
	}
	return nil
}
