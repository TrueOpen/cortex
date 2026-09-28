package metric

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// v3Node is one field of a V3 metric vector. Values stay raw JSON: logprobs
// and rank_delta are negative, flags are booleans.
type v3Node struct {
	Name    string          `json:"name"`
	Value   json.RawMessage `json:"value"`
	UTF8    string          `json:"utf8"`
	Hex     string          `json:"hex"`
	Present *bool           `json:"present"`
	Fields  []v3Node        `json:"fields"`
}

type v3Vector struct {
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Fields      []v3Node `json:"fields"`
	DigestHex   string   `json:"digest_hex"`
	PreimageHex string   `json:"preimage_hex"`
	RootHex     string   `json:"root_hex"`
	LeavesHex   []string `json:"leaves_hex"`
}

// aggregateProofVectorName is the one vector in result_metric_v3.json that is
// neither a metric leaf nor the metric root.
const aggregateProofVectorName = "metric_aggregate_proof_v1"

// findV3Vector returns the named vector, failing when wire stops publishing it.
// A vector that quietly disappears would otherwise turn its test into a no-op.
func findV3Vector(t *testing.T, path, name string) v3Vector {
	t.Helper()
	for _, vector := range loadV3Vectors(t, path) {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("wire %s publishes no vector named %q in %s", wirevectors.WireVersion, name, path)
	return v3Vector{}
}

func loadV3Vectors(t *testing.T, path string) []v3Vector {
	t.Helper()
	data, err := wirevectors.File(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []v3Vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Vectors
}

// v3Leaf reads one published leaf positionally, asserting each field name.
type v3Leaf struct {
	t      *testing.T
	fields []v3Node
	next   int
}

func (r *v3Leaf) take(name string) v3Node {
	r.t.Helper()
	if r.next >= len(r.fields) || r.fields[r.next].Name != name {
		r.t.Fatalf("leaf field %d is not %q", r.next, name)
	}
	r.next++
	return r.fields[r.next-1]
}

func (r *v3Leaf) int(name string) int64 {
	r.t.Helper()
	v, err := strconv.ParseInt(string(r.take(name).Value), 10, 64)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return v
}

func (r *v3Leaf) hash(name string) codec.Hash {
	r.t.Helper()
	raw, err := hex.DecodeString(r.take(name).Hex)
	if err != nil || len(raw) != 32 {
		r.t.Fatalf("%s is not a Hash32", name)
	}
	var h codec.Hash
	copy(h[:], raw)
	return h
}

func (r *v3Leaf) flag(name string) bool {
	r.t.Helper()
	var v bool
	if err := json.Unmarshal(r.take(name).Value, &v); err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return v
}

func (r *v3Leaf) optional(name string) OptionalFP1e6 {
	r.t.Helper()
	node := r.take(name)
	if node.Present == nil || !*node.Present {
		return OptionalFP1e6{}
	}
	v, err := strconv.ParseUint(string(node.Fields[0].Value), 10, 32)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return OptionalFP1e6{Value: uint32(v), Present: true}
}

// parseLeafV3 returns the binding and sample a published leaf encodes, plus
// the derived abs diff and rank delta it publishes for them.
func parseLeafV3(t *testing.T, vector v3Vector) (BindingV3, SampleV3, int64, int64) {
	t.Helper()
	if vector.Domain != DomainLeafV3 || len(vector.Fields) != 2 || string(vector.Fields[0].Value) != "1" {
		t.Fatalf("%s is not a version-1 V3 metric leaf", vector.Name)
	}
	r := &v3Leaf{t: t, fields: vector.Fields[1].Fields}
	if len(r.fields) != 26 {
		t.Fatalf("%s has %d leaf fields, want 26", vector.Name, len(r.fields))
	}
	var b BindingV3
	var s SampleV3
	b.ChainID = r.take("chain_id").UTF8
	b.TaskID = r.hash("task_id")
	b.TaskHash = r.hash("task_hash")
	b.VerifyRound = uint32(r.int("verify_round"))
	b.ModelID = r.hash("model_id")
	b.ProfileVersion = uint32(r.int("profile_version"))
	b.JudgmentFunctionVersion = r.take("judgment_function_version").UTF8
	b.CanonicalEncodingVersion = r.take("canonical_encoding_version").UTF8
	b.EvidenceSchemaHash = r.hash("evidence_schema_hash")
	b.MetricAggregateProofVersion = r.take("metric_aggregate_proof_version").UTF8
	b.TokenizerHash = r.hash("tokenizer_hash")
	b.GenerationParamsDigest = r.hash("generation_params_digest")
	s.OutputPosition = uint32(r.int("output_position"))
	s.EmittedTokenID = uint32(r.int("emitted_token_id"))
	b.RequiredTopK = uint32(r.int("required_top_k"))
	s.WorkerLogprobFP1e6 = r.int("worker_logprob_fp_1e6")
	s.VerifierLogprobFP1e6 = r.int("verifier_logprob_fp_1e6")
	absDiff := r.int("abs_logprob_diff_fp_1e6")
	s.WorkerRank = uint32(r.int("worker_rank"))
	s.VerifierRank = uint32(r.int("verifier_rank"))
	rankDelta := r.int("rank_delta")
	s.TopKJaccardFP1e6 = r.optional("topk_jaccard_fp_1e6")
	s.UnionJSFP1e6 = r.optional("union_js_fp_1e6")
	s.Missing = r.flag("missing_flag")
	s.Finite = r.flag("finite_flag")
	b.VerifierValueRoot = r.hash("verifier_value_root")
	return b, s, absDiff, rankDelta
}

func TestLeafV3ReproducesPublishedVectors(t *testing.T) {
	for _, path := range []string{"task/metric_leaf_v3.json", "task/result_metric_v3.json"} {
		var leaves []codec.Hash
		var root v3Vector
		for _, vector := range loadV3Vectors(t, path) {
			if vector.Domain == DomainRootV3 {
				root = vector
				continue
			}
			// result_metric_v3.json also publishes the aggregate proof, which is
			// neither a leaf nor the root: it is a bare FRAME_V1 blob with no
			// domain at all, committed to by a plain SHA-256, and it has its own
			// end-to-end check in aggregateproof_wire_test.go.
			//
			// Skipping is keyed on the empty domain rather than on "not a leaf",
			// so a leaf whose domain drifts still reaches parseLeafV3 and fails
			// there. The name is asserted too: a future domain-less vector is a
			// new artifact this loop has not been taught about, and silently
			// dropping it would leave it unchecked by anything.
			if vector.Domain == "" {
				if vector.Name != aggregateProofVectorName {
					t.Fatalf("%s carries domain-less vector %q, which nothing in this package checks", path, vector.Name)
				}
				continue
			}
			binding, sample, _, _ := parseLeafV3(t, vector)
			leaf, err := LeafHashV3(binding, sample)
			if err != nil {
				t.Fatalf("%s %s: %v", path, vector.Name, err)
			}
			if hex.EncodeToString(leaf[:]) != vector.DigestHex {
				t.Fatalf("%s %s = %x, published %s", path, vector.Name, leaf, vector.DigestHex)
			}
			leaves = append(leaves, leaf)
		}
		// metric_leaf_v3.json roots a single leaf; result_metric_v3.json roots
		// all three of its leaves.
		rootLeaves := leaves
		if len(root.LeavesHex) < len(leaves) {
			rootLeaves = leaves[:len(root.LeavesHex)]
		}
		got, err := RootV3(rootLeaves)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != root.RootHex {
			t.Fatalf("%s metric_root = %x, published %s", path, got, root.RootHex)
		}
	}
}

// The derived fields are computed, not passed in, so they must match what the
// vectors publish for the same inputs, including effective_rank for rank 0:
// a rank outside the required top-k counts as K+1. Both leaf files are read,
// and metric_leaf_v3_worker_rank_outside_top_k must be among them.
func TestLeafV3DerivesAbsDiffAndEffectiveRankDelta(t *testing.T) {
	outsideTopK := false
	for _, path := range []string{"task/metric_leaf_v3.json", "task/result_metric_v3.json"} {
		for _, vector := range loadV3Vectors(t, path) {
			if vector.Domain != DomainLeafV3 {
				continue
			}
			binding, sample, absDiff, rankDelta := parseLeafV3(t, vector)
			if vector.Name == "metric_leaf_v3_worker_rank_outside_top_k" {
				outsideTopK = true
				if sample.WorkerRank != 0 || rankDelta != int64(sample.VerifierRank)-int64(binding.RequiredTopK+1) {
					t.Fatalf("%s: worker rank %d, rank delta %d; want rank 0 counted as K+1", vector.Name, sample.WorkerRank, rankDelta)
				}
			}
			for _, wantRank := range []struct{ worker, verifier uint32 }{{0, 1}, {2, 0}} {
				if !sample.Finite {
					break
				}
				moved := sample
				moved.WorkerRank, moved.VerifierRank = wantRank.worker, wantRank.verifier
				a, err := LeafHashV3(binding, moved)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := LeafHashV3(binding, sample)
				if a == b {
					t.Fatalf("%s: moving a rank out of the top-k did not change the leaf", vector.Name)
				}
			}
			diff := sample.WorkerLogprobFP1e6 - sample.VerifierLogprobFP1e6
			if diff < 0 {
				diff = -diff
			}
			if diff != absDiff || (sample.Finite && rankDelta != sample.rankDelta(binding.RequiredTopK)) {
				t.Fatalf("%s publishes abs diff %d / rank delta %d that the inputs do not imply", vector.Name, absDiff, rankDelta)
			}
		}
	}
	if !outsideTopK {
		t.Fatal("metric_leaf_v3_worker_rank_outside_top_k was not read")
	}
}

func TestLeafV3RejectsIllegalLeaves(t *testing.T) {
	var binding BindingV3
	var normal, missing SampleV3
	for _, vector := range loadV3Vectors(t, "task/result_metric_v3.json") {
		if vector.Domain != DomainLeafV3 {
			continue
		}
		b, s, _, _ := parseLeafV3(t, vector)
		binding = b
		if s.Missing {
			missing = s
		} else {
			normal = s
		}
	}
	for name, bad := range map[string]SampleV3{
		"missing and finite":     func() SampleV3 { s := missing; s.Finite = true; return s }(),
		"missing with a logprob": func() SampleV3 { s := missing; s.VerifierLogprobFP1e6 = -1; return s }(),
		"missing with a ratio":   func() SampleV3 { s := missing; s.UnionJSFP1e6 = OptionalFP1e6{Present: true}; return s }(),
		"rank beyond K":          func() SampleV3 { s := normal; s.WorkerRank = binding.RequiredTopK + 1; return s }(),
		"ratio above one": func() SampleV3 {
			s := normal
			s.TopKJaccardFP1e6 = OptionalFP1e6{Value: FixedPointScale + 1, Present: true}
			return s
		}(),
	} {
		if _, err := LeafHashV3(binding, bad); err == nil {
			t.Errorf("%s: LeafHashV3() error = nil", name)
		}
	}
	noRoot := binding
	noRoot.VerifierValueRoot = codec.Hash{}
	if _, err := LeafHashV3(noRoot, normal); err == nil {
		t.Fatal("LeafHashV3() accepted a binding without verifier_value_root")
	}
	if _, err := LeafHashesV3(binding, []SampleV3{missing}); err == nil {
		t.Fatal("LeafHashesV3() accepted a set that does not start at output_position 0")
	}
}
