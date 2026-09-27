package nodewire

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

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
