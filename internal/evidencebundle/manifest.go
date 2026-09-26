package evidencebundle

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/TrueOpen/cortex/internal/codec"
)

const Domain = "TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1"
const MaxManifestBytes = 32 << 20

// Declaration order is canonical UTF-8 key order.
type Artifact struct {
	ID          string `json:"artifact_id"`
	ContentHash string `json:"content_hash"`
	Size        string `json:"size_bytes"`
}

// Manifest is one evidence bundle's canonical JSON manifest. Every manifest
// names its evidence_kind: a Worker round has an A-level token bundle and a
// B-level value bundle, and a Verifier round one value bundle.
type Manifest struct {
	Artifacts          []Artifact `json:"artifacts"`
	ChainID            string     `json:"chain_id"`
	EvidenceKind       string     `json:"evidence_kind"`
	EvidenceSchemaHash string     `json:"evidence_schema_hash"`
	Version            uint32     `json:"manifest_version"`
	ProducerKind       string     `json:"producer_kind"`
	ProducerOperator   string     `json:"producer_operator"`
	TaskHash           string     `json:"task_hash"`
	TaskID             string     `json:"task_id"`
	VerifyRound        uint32     `json:"verify_round"`
}

func Hash(data []byte) codec.Hash { return codec.HashV1(Domain, data) }

func NewArtifact(id string, data []byte) Artifact {
	return Artifact{ID: id, ContentHash: codec.HashBytes(data).String(), Size: strconv.FormatUint(uint64(len(data)), 10)}
}

func (a Artifact) SizeBytes() (uint64, error) {
	n, err := strconv.ParseUint(a.Size, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != a.Size {
		return 0, fmt.Errorf("artifact size is not canonical uint64")
	}
	return n, nil
}

func (m Manifest) TotalSize() uint64 {
	var n uint64
	for _, a := range m.Artifacts {
		s, _ := a.SizeBytes()
		n += s
	}
	return n
}

func hash32(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
