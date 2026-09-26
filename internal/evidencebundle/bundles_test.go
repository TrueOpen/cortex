package evidencebundle

import (
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// The three published manifests are decoded, re-encoded and hashed exactly as
// transmitted; a relay must hash what it received.
func TestManifestsV3ReproducePublishedVectors(t *testing.T) {
	data, err := wirevectors.File("task/canonical_json_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name        string `json:"name"`
			Domain      string `json:"domain"`
			PayloadUTF8 string `json:"payload_utf8"`
			DigestHex   string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]Manifest{}
	for _, v := range file.Vectors {
		if v.Domain != Domain {
			continue
		}
		m, err := Decode([]byte(v.PayloadUTF8))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got := Hash([]byte(v.PayloadUTF8)).String(); got != v.DigestHex {
			t.Fatalf("%s bundle hash = %s, published %s", v.Name, got, v.DigestHex)
		}
		kinds[m.EvidenceKind] = m
	}
	if len(kinds) != 3 {
		t.Fatalf("published manifests cover %d kinds, want 3", len(kinds))
	}

	// Each kind accepts only its exact artifact set.
	worker := kinds[KindWorkerValueOpening]
	if _, err := worker.Encode(); err != nil {
		t.Fatalf("Encode refused the published B-level Worker manifest: %v", err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"missing evidence kind":      func(m *Manifest) { m.EvidenceKind = "" },
		"Verifier kind on a Worker":  func(m *Manifest) { m.EvidenceKind = KindVerifierValueOpening },
		"Worker in round 2":          func(m *Manifest) { m.VerifyRound = 2 },
		"trace beside worker_values": func(m *Manifest) { m.Artifacts = append(m.Artifacts, NewArtifact("zz_trace", []byte("x"))) },
		"token ids in the value bundle": func(m *Manifest) {
			m.Artifacts = []Artifact{NewArtifact("input_token_ids", []byte{0, 0, 0, 0})}
		},
	} {
		bad := worker
		bad.Artifacts = append([]Artifact(nil), worker.Artifacts...)
		mutate(&bad)
		if _, err := bad.Encode(); err == nil {
			t.Errorf("%s: EncodeV3() error = nil", name)
		}
	}
	verifier := kinds[KindVerifierValueOpening]
	verifier.EvidenceKind = ""
	if _, err := verifier.Encode(); err == nil {
		t.Fatal("EncodeV3() accepted a Verifier manifest without evidence_kind")
	}
}
