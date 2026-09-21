package nodewire

import (
	"encoding/binary"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

const (
	DomainInputTokenIDsV1     = "TRUEOPEN_INPUT_TOKEN_IDS_V1"
	DomainGeneratedTokenIDsV1 = "TRUEOPEN_GENERATED_TOKEN_IDS_V1"
	MaxTokenIDCountV1         = 8388607
)

// EncodeTokenIDs returns the raw artifact: u32_be(count) followed by one u32_be
// per token, preserving order and duplicates. The count occurs exactly once.
func EncodeTokenIDs(ids []uint32) ([]byte, error) {
	if len(ids) > MaxTokenIDCountV1 {
		return nil, fmt.Errorf("token count %d exceeds %d", len(ids), MaxTokenIDCountV1)
	}
	raw := make([]byte, 4+4*len(ids))
	binary.BigEndian.PutUint32(raw, uint32(len(ids)))
	for i, id := range ids {
		binary.BigEndian.PutUint32(raw[4+4*i:], id)
	}
	return raw, nil
}

// DecodeTokenIDs rejects truncated, trailing, and oversized artifacts before
// allocating the token vector.
func DecodeTokenIDs(raw []byte) ([]uint32, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("token IDs artifact lacks uint32 count")
	}
	count := binary.BigEndian.Uint32(raw)
	if count > MaxTokenIDCountV1 {
		return nil, fmt.Errorf("token count %d exceeds %d", count, MaxTokenIDCountV1)
	}
	if uint64(len(raw)) != 4+4*uint64(count) {
		return nil, fmt.Errorf("token IDs artifact size %d does not match count %d", len(raw), count)
	}
	ids := make([]uint32, int(count))
	for i := range ids {
		ids[i] = binary.BigEndian.Uint32(raw[4+4*i:])
	}
	return ids, nil
}

func InputTokenIDsHash(ids []uint32) (codec.Hash, error) {
	return tokenIDsHash(DomainInputTokenIDsV1, ids)
}

func GeneratedTokenIDsHash(ids []uint32) (codec.Hash, error) {
	return tokenIDsHash(DomainGeneratedTokenIDsV1, ids)
}

func tokenIDsHash(domain string, ids []uint32) (codec.Hash, error) {
	raw, err := EncodeTokenIDs(ids)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(domain, hfields.Bytes(raw))
}
