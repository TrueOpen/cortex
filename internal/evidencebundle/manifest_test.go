package evidencebundle

import (
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func TestManifestMatchesWireV040Vector(t *testing.T) {
	data, err := wirevectors.File("task/canonical_json_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name, Domain string
			Payload      string `json:"payload_utf8"`
			Digest       string `json:"digest_hex"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Vectors {
		if v.Name != "evidence_bundle_manifest_v1" {
			continue
		}
		m, err := Decode([]byte(v.Payload))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != v.Payload || Hash(encoded).String() != v.Digest {
			t.Fatal("manifest does not reproduce published bytes/digest")
		}
		if _, err := Decode(append(encoded, '\n')); err == nil {
			t.Fatal("accepted noncanonical manifest newline")
		}
		return
	}
	t.Fatal("published manifest vector missing")
}
