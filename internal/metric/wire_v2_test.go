package metric

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

type metricWireField struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Value   json.RawMessage   `json:"value"`
	UTF8    string            `json:"utf8"`
	Hex     string            `json:"hex"`
	Present bool              `json:"present"`
	Fields  []metricWireField `json:"fields"`
}

func TestMetricV2MatchesReleasedLeafAndRootVectors(t *testing.T) {
	raw, err := wirevectors.File("task/metric_leaf_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name      string            `json:"name"`
			Fields    []metricWireField `json:"fields"`
			DigestHex string            `json:"digest_hex"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var first codec.Hash
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Name == "metric_root_v2_single_leaf" {
				got, err := Root([]codec.Hash{first})
				if err != nil || hex.EncodeToString(got[:]) != vector.DigestHex {
					t.Fatalf("root %x, want %s: %v", got, vector.DigestHex, err)
				}
				return
			}
			fields := map[string]metricWireField{}
			for _, f := range vector.Fields[1].Fields {
				fields[f.Name] = f
			}
			u := func(name string) int64 {
				var n int64
				if err := json.Unmarshal(fields[name].Value, &n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			h := func(name string) codec.Hash {
				b, err := hex.DecodeString(fields[name].Hex)
				if err != nil || len(b) != 32 {
					t.Fatalf("hash %s: %v", name, err)
				}
				var out codec.Hash
				copy(out[:], b)
				return out
			}
			o := func(name string) OptionalFP {
				f := fields[name]
				if !f.Present {
					return OptionalFP{}
				}
				var n uint32
				if err := json.Unmarshal(f.Fields[0].Value, &n); err != nil {
					t.Fatal(err)
				}
				return PresentFP(float64(n) / FixedPointScale)
			}
			b := Binding{ChainID: fields["chain_id"].UTF8, TaskID: h("task_id"), TaskHash: h("task_hash"), VerifyRound: uint32(u("verify_round")), ModelID: fields["model_id"].UTF8,
				ProfileVersion: uint32(u("profile_version")), JudgmentFunctionVersion: fields["judgment_function_version"].UTF8, CanonicalEncodingVersion: fields["canonical_encoding_version"].UTF8,
				EvidenceSchemaHash: h("evidence_schema_hash"), MetricAggregateProofVersion: fields["metric_aggregate_proof_version"].UTF8, TokenizerHash: h("tokenizer_hash"), GenerationParamsDigest: h("generation_params_digest"),
				RequiredTopK: uint32(u("required_top_k")), Spec: Spec{ComparedTopK: uint32(u("required_top_k"))}}
			var finite, missing bool
			if err := json.Unmarshal(fields["finite_flag"].Value, &finite); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fields["missing_flag"].Value, &missing); err != nil {
				t.Fatal(err)
			}
			s := Sample{OutputPosition: uint32(u("output_position")), EmittedTokenID: uint32(u("emitted_token_id")), WorkerLogprob: float64(u("worker_logprob_fp_1e6")) / FixedPointScale,
				VerifierLogprob: float64(u("verifier_logprob_fp_1e6")) / FixedPointScale, WorkerRank: uint32(u("worker_rank")), VerifierRank: uint32(u("verifier_rank")), TopKJaccard: o("topk_jaccard_fp_1e6"), UnionJS: o("union_js_fp_1e6"), Finite: finite, Missing: missing}
			got, err := LeafHash(b, s)
			if err != nil || hex.EncodeToString(got[:]) != vector.DigestHex {
				t.Fatalf("leaf %x, want %s: %v", got, vector.DigestHex, err)
			}
			if first.IsZero() {
				first = got
			}
		})
	}
}
