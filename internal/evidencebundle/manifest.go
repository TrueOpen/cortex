package evidencebundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

const Domain = "TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1"
const MaxManifestBytes = 32 << 20

// Declaration order is canonical UTF-8 key order.
type Artifact struct {
	ID          string `json:"artifact_id"`
	ContentHash string `json:"content_hash"`
	Size        string `json:"size_bytes"`
}

type Manifest struct {
	Artifacts          []Artifact `json:"artifacts"`
	ChainID            string     `json:"chain_id"`
	EvidenceKind       string     `json:"evidence_kind,omitempty"`
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

func (m Manifest) Validate() error {
	if m.Version != 1 || m.ChainID == "" || !utf8.ValidString(m.ChainID) || m.VerifyRound == 0 || m.VerifyRound > 2 {
		return fmt.Errorf("invalid manifest scope")
	}
	if m.ProducerKind != "WORKER" && m.ProducerKind != "VERIFIER" || m.ProducerKind == "WORKER" && m.VerifyRound != 1 {
		return fmt.Errorf("invalid evidence producer/round")
	}
	if _, err := nodewire.CanonicalOperatorAddressBytes("producer_operator", m.ProducerOperator); err != nil {
		return err
	}
	for _, s := range []string{m.TaskHash, m.TaskID, m.EvidenceSchemaHash} {
		if !hash32(s) {
			return fmt.Errorf("invalid manifest scope hash")
		}
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 65534 {
		return fmt.Errorf("invalid manifest artifact count")
	}
	total := uint64(0)
	for i, a := range m.Artifacts {
		if a.ID == "" || len(a.ID) > 1024 || !utf8.ValidString(a.ID) || i > 0 && a.ID <= m.Artifacts[i-1].ID || !hash32(a.ContentHash) {
			return fmt.Errorf("invalid, unsorted or duplicate manifest artifact")
		}
		n, err := a.SizeBytes()
		if err != nil {
			return err
		}
		if n > math.MaxUint64-total {
			return fmt.Errorf("artifact total size overflows")
		}
		total += n
	}
	if m.ProducerKind == "VERIFIER" && (len(m.Artifacts) != 1 || m.Artifacts[0].ID != "aggregate_proof") {
		return fmt.Errorf("Verifier manifest requires exactly aggregate_proof")
	}
	if m.ProducerKind == "WORKER" {
		if m.EvidenceKind != "WORKER_VALUE_OPENING" || len(m.Artifacts) != 4 {
			return fmt.Errorf("Worker manifest requires WORKER_VALUE_OPENING and exactly four artifacts")
		}
		for i, id := range []string{"checkpoint", "generated_token_ids", "input_token_ids", "trace"} {
			if m.Artifacts[i].ID != id {
				return fmt.Errorf("Worker manifest artifact set mismatch")
			}
		}
	}
	return nil
}

func (m Manifest) Encode() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(m); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds byte limit")
	}
	return data, nil
}

func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return m, fmt.Errorf("invalid manifest byte size")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return m, fmt.Errorf("manifest has trailing JSON")
	}
	canonical, err := m.Encode()
	if err != nil {
		return m, err
	}
	if !bytes.Equal(canonical, data) {
		return m, fmt.Errorf("manifest is not exact canonical JSON")
	}
	return m, nil
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
