package evidencebundle

// The wire v0.3.0 manifest rules (task/canonical_json_v1.json): every manifest
// names its evidence_kind, and each kind's bundle holds exactly its own
// artifact set.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// Evidence kind tokens a V3 manifest carries.
const (
	KindWorkerValueOpening   = "WORKER_VALUE_OPENING"
	KindWorkerTokenOpening   = "WORKER_TOKEN_OPENING"
	KindVerifierValueOpening = "VERIFIER_VALUE_OPENING"
)

// ArtifactGenerationParams is the A-level artifact holding the task's exact
// canonical_generation_params_json. It is stored in the bundle but not counted
// in the A-level commitment's encoded_size_bytes.
const ArtifactGenerationParams = "generation_params"

// artifactsV3 is the exact artifact set of each bundle, in canonical order.
var artifactsV3 = map[string][]string{
	KindWorkerTokenOpening:   {"generated_token_ids", ArtifactGenerationParams, "input_token_ids"},
	KindWorkerValueOpening:   {"worker_values"},
	KindVerifierValueOpening: {"aggregate_proof"},
}

// Validate applies the scope and artifact rules plus the bundle rules: the evidence kind must match the producer, and the artifacts must be
// exactly that kind's set.
func (m Manifest) Validate() error {
	if m.Version != 1 || m.ChainID == "" || !utf8.ValidString(m.ChainID) {
		return fmt.Errorf("invalid manifest scope")
	}
	switch {
	case m.ProducerKind == "WORKER" && m.VerifyRound == 1 && (m.EvidenceKind == KindWorkerTokenOpening || m.EvidenceKind == KindWorkerValueOpening):
	case m.ProducerKind == "VERIFIER" && (m.VerifyRound == 1 || m.VerifyRound == 2) && m.EvidenceKind == KindVerifierValueOpening:
	default:
		return fmt.Errorf("evidence_kind %q does not match producer %q in round %d", m.EvidenceKind, m.ProducerKind, m.VerifyRound)
	}
	if _, err := nodewire.CanonicalOperatorAddressBytes("producer_operator", m.ProducerOperator); err != nil {
		return err
	}
	for _, s := range []string{m.TaskHash, m.TaskID, m.EvidenceSchemaHash} {
		if !hash32(s) {
			return fmt.Errorf("invalid manifest scope hash")
		}
	}
	want := artifactsV3[m.EvidenceKind]
	if len(m.Artifacts) != len(want) {
		return fmt.Errorf("%s manifest requires exactly %v", m.EvidenceKind, want)
	}
	total := uint64(0)
	for i, a := range m.Artifacts {
		if a.ID != want[i] || !hash32(a.ContentHash) {
			return fmt.Errorf("%s manifest requires exactly %v with Hash32 content", m.EvidenceKind, want)
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
	return nil
}

// Encode returns the canonical manifest bytes after Validate.
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

// Decode parses exact canonical manifest bytes.
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

// KindToken is the manifest spelling of an evidence kind, or "" for a kind
// that has no bundle.
func KindToken(kind nodewire.EvidenceKind) string {
	switch kind {
	case nodewire.EvidenceKindWorkerValueOpening:
		return KindWorkerValueOpening
	case nodewire.EvidenceKindWorkerTokenOpening:
		return KindWorkerTokenOpening
	case nodewire.EvidenceKindVerifierValueOpening:
		return KindVerifierValueOpening
	default:
		return ""
	}
}
