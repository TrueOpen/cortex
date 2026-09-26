package identity

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

type modelIDFile struct {
	Vectors []struct {
		Name   string `json:"name"`
		Fields []struct {
			Name   string `json:"name"`
			UTF8   string `json:"utf8"`
			Bech32 string `json:"bech32"`
		} `json:"fields"`
		DigestHex string `json:"digest_hex"`
		Tamper    []struct {
			Name      string `json:"name"`
			DigestHex string `json:"digest_hex"`
		} `json:"tamper"`
	} `json:"vectors"`
	Negative []struct {
		Name  string         `json:"name"`
		Input map[string]any `json:"input"`
	} `json:"negative"`
}

func loadModelIDVectors(t *testing.T) modelIDFile {
	t.Helper()
	data, err := wirevectors.File("hub/model_id_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file modelIDFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestModelIDV1ReproducesPublishedVectors(t *testing.T) {
	file := loadModelIDVectors(t)
	if len(file.Vectors) != 5 {
		t.Fatalf("model_id_v1.json publishes %d vectors, want 5", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		want := []string{"chain_id", "provider", "repo_id", "proposer_address"}
		for i, f := range v.Fields {
			if f.Name != want[i] {
				t.Fatalf("%s field %d is %q, want %q", v.Name, i, f.Name, want[i])
			}
		}
		got, err := ModelIDV1(v.Fields[0].UTF8, v.Fields[1].UTF8, v.Fields[2].UTF8, v.Fields[3].Bech32)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if hex.EncodeToString(got[:]) != v.DigestHex {
			t.Fatalf("%s = %x, published %s", v.Name, got, v.DigestHex)
		}
		// A tamper row changes the encoding, never the value; none may land on
		// the base digest.
		for _, tamper := range v.Tamper {
			if tamper.DigestHex == v.DigestHex {
				t.Fatalf("%s tamper %s reproduces the base digest", v.Name, tamper.Name)
			}
		}
	}
}

// Each negative row names the single input that differs from P1; all of them
// must be refused before any identity is derived.
func TestModelIDV1RejectsPublishedNegatives(t *testing.T) {
	file := loadModelIDVectors(t)
	var p1 []string
	for _, v := range file.Vectors {
		if v.Name == "model_id_p1_reference" {
			p1 = []string{v.Fields[0].UTF8, v.Fields[1].UTF8, v.Fields[2].UTF8, v.Fields[3].Bech32}
		}
	}
	if p1 == nil {
		t.Fatal("no P1 reference vector")
	}
	if len(file.Negative) == 0 {
		t.Fatal("model_id_v1.json publishes no negative rows")
	}
	for _, row := range file.Negative {
		in := append([]string(nil), p1...)
		for key, value := range row.Input {
			switch key {
			case "chain_id":
				in[0] = value.(string)
			case "provider":
				in[1] = value.(string)
			case "repo_id":
				in[2] = value.(string)
			case "repo_id_hex":
				raw, err := hex.DecodeString(value.(string))
				if err != nil {
					t.Fatal(err)
				}
				in[2] = string(raw)
			case "repo_id_length_bytes":
				n := int(value.(float64))
				in[2] = "a/" + strings.Repeat("b", n-2)
			case "proposer_address":
				in[3] = value.(string)
			default:
				t.Fatalf("%s: unknown negative input %q", row.Name, key)
			}
		}
		if _, err := ModelIDV1(in[0], in[1], in[2], in[3]); err == nil {
			t.Errorf("%s: ModelIDV1() error = nil", row.Name)
		}
	}
	// 255 bytes is still accepted, so the length row fails for its length.
	if _, err := ModelIDV1(p1[0], p1[1], "a/"+strings.Repeat("b", 253), p1[3]); err != nil {
		t.Fatalf("a 255-byte repo_id was refused: %v", err)
	}
}
