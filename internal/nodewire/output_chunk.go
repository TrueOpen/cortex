package nodewire

import (
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

const DomainOutputChunkV1 = "TRUEOPEN_OUTPUT_CHUNK_V1"

func OutputChunkSigningPreimage(chainID string, taskHash []byte, seq uint64, mmrRoot []byte) ([]byte, error) {
	if _, err := canonicalUTF8Field("chain_id", chainID); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("task_hash", taskHash); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("mmr_root", mmrRoot); err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainOutputChunkV1, hfields.String(chainID), hfields.Bytes(taskHash), hfields.Uint64(seq), hfields.Bytes(mmrRoot))
}

func OutputChunkSigningDigest(chainID string, taskHash []byte, seq uint64, mmrRoot []byte) (codec.Hash, error) {
	return digestOf(OutputChunkSigningPreimage(chainID, taskHash, seq, mmrRoot))
}
