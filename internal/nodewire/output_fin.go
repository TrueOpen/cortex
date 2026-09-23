package nodewire

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const DomainOutputFinV1 = "TRUEOPEN_OUTPUT_FIN_V1"

// OutputFinSigningPreimage returns the H_FIELDS_V1 projection wire v0.2.0
// registers for TRUEOPEN_OUTPUT_FIN_V1 (TrueOpen/wire#35, #37). The
// signature authenticates terminal metadata; it does not enter the OUTPUT MMR.
func OutputFinSigningPreimage(chainID string, taskHash []byte, finalSeq uint64, outputMMRRoot []byte, finishReason FinishReasonV1) ([]byte, error) {
	if _, err := canonicalUTF8Field("chain_id", chainID); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("task_hash", taskHash); err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("output_mmr_root", outputMMRRoot); err != nil {
		return nil, err
	}
	reason, err := canonicalFinishReasonV1(finishReason)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainOutputFinV1,
		hfields.String(chainID),
		hfields.Bytes(taskHash),
		hfields.Uint64(finalSeq),
		hfields.Bytes(outputMMRRoot),
		hfields.Uint32(reason),
	)
}

func OutputFinSigningDigest(chainID string, taskHash []byte, finalSeq uint64, outputMMRRoot []byte, finishReason FinishReasonV1) (codec.Hash, error) {
	return digestOf(OutputFinSigningPreimage(chainID, taskHash, finalSeq, outputMMRRoot, finishReason))
}
