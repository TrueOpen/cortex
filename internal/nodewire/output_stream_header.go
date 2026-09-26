package nodewire

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// DomainOutputStreamHeaderV1 is the Worker's signature domain over
// OutputStreamHeaderV2 in wire v0.3.0 (TrueOpen/wire#14,
// task/output_stream_header_v1.json). The header is signed independently of the
// task-data request authentication. Nothing produces it yet.
const DomainOutputStreamHeaderV1 = "TRUEOPEN_OUTPUT_STREAM_HEADER_V1"

// OutputStreamHeaderV2 is the signed part of the Worker's output stream header.
// Until encryption activates, attempt is 0, stream_instance is 1, the recipient
// key is empty and both commitments are ZERO32; anything else is refused.
type OutputStreamHeaderV2 struct {
	ChainID             string
	TaskHash            []byte // Hash32
	Attempt             uint32
	StreamInstance      uint32
	UserRecipientPubkey []byte // empty in plaintext
	OutputKeyCommitment []byte // Hash32, ZERO32 in plaintext
	KeyPackageHash      []byte // Hash32, ZERO32 in plaintext
}

// OutputStreamHeaderSigningPreimage frames the seven signed fields in order.
func OutputStreamHeaderSigningPreimage(header OutputStreamHeaderV2) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", header.ChainID)
	if err != nil {
		return nil, err
	}
	if _, err := canonicalHash32("task_hash", header.TaskHash); err != nil {
		return nil, err
	}
	if header.Attempt != 0 || header.StreamInstance != 1 {
		return nil, fmt.Errorf("a plaintext output stream must use attempt 0 and stream_instance 1")
	}
	if err := requireEmptyRecipient(header.UserRecipientPubkey); err != nil {
		return nil, err
	}
	for _, slot := range [...]struct {
		name  string
		value []byte
	}{{"output_key_commitment", header.OutputKeyCommitment}, {"key_package_hash", header.KeyPackageHash}} {
		if err := requirePlaintextSlot(slot.name, slot.value); err != nil {
			return nil, err
		}
	}
	return hfields.Preimage(
		DomainOutputStreamHeaderV1,
		hfields.String(chainID),
		hfields.Bytes(header.TaskHash),
		hfields.Uint32(header.Attempt),
		hfields.Uint32(header.StreamInstance),
		hfields.Bytes(header.UserRecipientPubkey),
		hfields.Bytes(header.OutputKeyCommitment),
		hfields.Bytes(header.KeyPackageHash),
	)
}

// OutputStreamHeaderSigningDigest is the digest the Worker's service key signs.
func OutputStreamHeaderSigningDigest(header OutputStreamHeaderV2) (codec.Hash, error) {
	return digestOf(OutputStreamHeaderSigningPreimage(header))
}
