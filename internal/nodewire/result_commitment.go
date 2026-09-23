package nodewire

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const DomainResultCommitmentV2 = "TRUEOPEN_RESULT_COMMITMENT_V2"
const DomainVerifierResultPayloadV1 = "TRUEOPEN_VERIFIER_RESULT_PAYLOAD_V1"

// ResultCommitmentV2 binds the unsalted canonical result payload to the task,
// round, verifier and independently supplied salt.
type ResultCommitmentV2 struct {
	ChainID                 string
	TaskID                  []byte
	TaskHash                []byte
	VerifyRound             uint32
	VerifierOperatorAddress string
	ResultPayloadHash       []byte
	Salt                    []byte
}

func ResultCommitmentHash(commitment ResultCommitmentV2) (codec.Hash, error) {
	chainID, err := canonicalUTF8Field("chain_id", commitment.ChainID)
	if err != nil {
		return codec.Hash{}, err
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", commitment.TaskID}, {"task_hash", commitment.TaskHash},
		{"result_payload_hash", commitment.ResultPayloadHash}, {"salt", commitment.Salt},
	} {
		if _, err := canonicalHash32(field.name, field.value); err != nil {
			return codec.Hash{}, err
		}
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", commitment.VerifierOperatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainResultCommitmentV2,
		hfields.String(chainID), hfields.Bytes(commitment.TaskID), hfields.Bytes(commitment.TaskHash),
		hfields.Uint32(commitment.VerifyRound), hfields.Bytes(verifier),
		hfields.Bytes(commitment.ResultPayloadHash), hfields.Bytes(commitment.Salt))
}

func ResultPayloadHash(payload []byte) codec.Hash {
	return codec.HashV1(DomainVerifierResultPayloadV1, payload)
}

func VerifyCommitKey(chainID string, taskID []byte, round uint32, verifier string) (codec.Hash, error) {
	chainID, err := canonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return codec.Hash{}, err
	}
	if _, err := canonicalHash32("task_id", taskID); err != nil {
		return codec.Hash{}, err
	}
	address, err := CanonicalOperatorAddressBytes("verifier_operator_address", verifier)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_COMMIT_KEY_V1", hfields.String(chainID), hfields.Bytes(taskID),
		hfields.Uint32(round), hfields.Bytes(address))
}
