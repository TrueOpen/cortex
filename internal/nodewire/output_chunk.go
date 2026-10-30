package nodewire

import (
	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const DomainOutputChunkV1 = "TRUEOPEN_OUTPUT_CHUNK_V1"

func OutputChunkSigningPreimage(chainID string, taskHash, dispatchTicketHash []byte, seq uint64, mmrRoot []byte) ([]byte, error) {
	if _, err := canonicalUTF8Field("chain_id", chainID); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("task_hash", taskHash); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("dispatch_ticket_hash", dispatchTicketHash); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("mmr_root", mmrRoot); err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainOutputChunkV1, hfields.String(chainID), hfields.Bytes(taskHash), hfields.Bytes(dispatchTicketHash), hfields.Uint64(seq), hfields.Bytes(mmrRoot))
}

// OutputChunkSigningDigest validates the frame fields and returns wire's
// dispatch.OutputChunkDigest, the single implementation of the chunk scope.
func OutputChunkSigningDigest(chainID string, taskHash, dispatchTicketHash []byte, seq uint64, mmrRoot []byte) (codec.Hash, error) {
	if _, err := OutputChunkSigningPreimage(chainID, taskHash, dispatchTicketHash, seq, mmrRoot); err != nil {
		return codec.Hash{}, err
	}
	return codec.Hash(dispatch.OutputChunkDigest(chainID, [32]byte(taskHash), [32]byte(dispatchTicketHash), seq, [32]byte(mmrRoot))), nil
}
