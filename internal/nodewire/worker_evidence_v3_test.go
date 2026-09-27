package nodewire_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// The v0.3.0 vectors are not released yet; wirevectors serves them from the
// pinned TrueOpen/wire#14 commit after checking that commit's manifest.

type commitmentFileV3 struct {
	Vectors []struct {
		goldenVector
		ExpectedEncodedSizeBytes uint64 `json:"expected_encoded_size_bytes"`
	} `json:"vectors"`
}

func loadCommitmentVector(t *testing.T, path, domain string) (goldenVector, uint64) {
	t.Helper()
	data, err := wirevectors.PrereleaseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file commitmentFileV3
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(file.Vectors) != 1 || file.Vectors[0].Domain != domain || file.Vectors[0].Framing != "H_FIELDS_V1" {
		t.Fatalf("%s must publish exactly one H_FIELDS_V1 vector for %s", path, domain)
	}
	return file.Vectors[0].goldenVector, file.Vectors[0].ExpectedEncodedSizeBytes
}

func checkPublished(t *testing.T, vector goldenVector, preimage []byte, digest codec.Hash) {
	t.Helper()
	if got := hex.EncodeToString(preimage); got != vector.PreimageHex {
		t.Fatalf("%s preimage differs from the published encoding", vector.Name)
	}
	if sha256.Sum256(preimage) != digest {
		t.Fatalf("%s digest is not SHA-256 over its preimage", vector.Name)
	}
	if got := hex.EncodeToString(digest[:]); got != vector.DigestHex {
		t.Fatalf("%s digest = %s, published %s", vector.Name, got, vector.DigestHex)
	}
}

func TestWorkerTokenCommitmentReproducesPublishedVector(t *testing.T) {
	v, wantSize := loadCommitmentVector(t, "task/worker_token_commitment_v1.json", nodewire.DomainWorkerTokenCommitmentV1)
	value := nodewire.WorkerTokenCommitmentV1{
		SchemaVersion:              uint32(fieldUint(t, v, 0, "schema_version")),
		ChainID:                    fieldString(t, v, 1, "chain_id"),
		TaskID:                     fieldBytes(t, v, 2, "task_id"),
		AcceptedTaskHash:           fieldBytes(t, v, 3, "accepted_task_hash"),
		WorkerOperatorAddress:      fieldBech32(t, v, 4, "worker_operator_address"),
		GenerationParamsDigest:     fieldBytes(t, v, 5, "generation_params_digest"),
		EvidenceSchemaHash:         fieldBytes(t, v, 6, "evidence_schema_hash"),
		OutputHash:                 fieldBytes(t, v, 7, "output_hash"),
		OutputSizeBytes:            fieldUint(t, v, 8, "output_size_bytes"),
		OutputLeafCount:            fieldUint(t, v, 9, "output_leaf_count"),
		FinishReason:               nodewire.FinishReasonV1(fieldUint(t, v, 10, "finish_reason")),
		GeneratedTokenCount:        fieldUint(t, v, 11, "generated_token_count"),
		InputTokenIDsHash:          fieldBytes(t, v, 12, "input_token_ids_hash"),
		GeneratedTokenIDsHash:      fieldBytes(t, v, 13, "generated_token_ids_hash"),
		InputTokenIDsSizeBytes:     fieldUint(t, v, 14, "input_token_ids_size_bytes"),
		GeneratedTokenIDsSizeBytes: fieldUint(t, v, 15, "generated_token_ids_size_bytes"),
	}
	if len(v.Fields) != 16 {
		t.Fatalf("published vector has %d fields, want 16", len(v.Fields))
	}
	preimage, err := nodewire.WorkerTokenCommitmentPreimage(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, size, err := nodewire.WorkerTokenCommitment(value)
	if err != nil {
		t.Fatal(err)
	}
	checkPublished(t, v, preimage, digest)
	if size != wantSize {
		t.Fatalf("encoded_size_bytes = %d, published %d", size, wantSize)
	}

	for name, mutate := range map[string]func(*nodewire.WorkerTokenCommitmentV1){
		"wrong schema version":      func(c *nodewire.WorkerTokenCommitmentV1) { c.SchemaVersion = 2 },
		"unspecified finish reason": func(c *nodewire.WorkerTokenCommitmentV1) { c.FinishReason = 0 },
		"short task id":             func(c *nodewire.WorkerTokenCommitmentV1) { c.TaskID = c.TaskID[:31] },
		"zero output leaves":        func(c *nodewire.WorkerTokenCommitmentV1) { c.OutputLeafCount = 0 },
		"size disagrees with count": func(c *nodewire.WorkerTokenCommitmentV1) { c.GeneratedTokenCount++ },
	} {
		bad := value
		mutate(&bad)
		if _, _, err := nodewire.WorkerTokenCommitment(bad); err == nil {
			t.Errorf("%s: WorkerTokenCommitment() error = nil", name)
		}
	}
}

func TestWorkerValueCommitmentV3ReproducesPublishedVector(t *testing.T) {
	v, wantSize := loadCommitmentVector(t, "task/worker_value_commitment_v3.json", nodewire.DomainWorkerValueCommitmentV3)
	value := nodewire.WorkerValueCommitmentV3{
		SchemaVersion:                uint32(fieldUint(t, v, 0, "schema_version")),
		ChainID:                      fieldString(t, v, 1, "chain_id"),
		TaskID:                       fieldBytes(t, v, 2, "task_id"),
		AcceptedTaskHash:             fieldBytes(t, v, 3, "accepted_task_hash"),
		WorkerOperatorAddress:        fieldBech32(t, v, 4, "worker_operator_address"),
		EvidenceSchemaHash:           fieldBytes(t, v, 5, "evidence_schema_hash"),
		WorkerValueRoot:              fieldBytes(t, v, 6, "worker_value_root"),
		WorkerValuesEncodedSizeBytes: fieldUint(t, v, 7, "worker_values_encoded_size_bytes"),
	}
	if len(v.Fields) != 8 {
		t.Fatalf("published vector has %d fields, want 8", len(v.Fields))
	}
	preimage, err := nodewire.WorkerValueCommitmentV3Preimage(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, size, err := nodewire.WorkerValueCommitmentV3Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	checkPublished(t, v, preimage, digest)
	if size != wantSize {
		t.Fatalf("encoded_size_bytes = %d, published %d", size, wantSize)
	}

	// The root and size are the ones the Worker value tree vector publishes, so
	// the two files describe the same artifact.
	tree := loadValueTree(t, "task/worker_value_leaf_v1.json")
	if hex.EncodeToString(value.WorkerValueRoot) != tree.root.RootHex || size != tree.root.WorkerValuesEncodedSizeBytes {
		t.Fatal("the V3 commitment vector does not commit to the published Worker value tree")
	}

	for name, mutate := range map[string]func(*nodewire.WorkerValueCommitmentV3){
		"V2 schema version":   func(c *nodewire.WorkerValueCommitmentV3) { c.SchemaVersion = 2 },
		"short root":          func(c *nodewire.WorkerValueCommitmentV3) { c.WorkerValueRoot = c.WorkerValueRoot[:31] },
		"size below count":    func(c *nodewire.WorkerValueCommitmentV3) { c.WorkerValuesEncodedSizeBytes = 3 },
		"empty chain id":      func(c *nodewire.WorkerValueCommitmentV3) { c.ChainID = "" },
		"non-bech32 operator": func(c *nodewire.WorkerValueCommitmentV3) { c.WorkerOperatorAddress = "worker" },
	} {
		bad := value
		mutate(&bad)
		if _, _, err := nodewire.WorkerValueCommitmentV3Digest(bad); err == nil {
			t.Errorf("%s: WorkerValueCommitmentV3Digest() error = nil", name)
		}
	}
}

// valueNode is one field of a value-tree vector. Values stay raw JSON because
// leaf logprobs are negative int64s, which goldenField cannot hold, and flags
// are JSON booleans.
type valueNode struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Value  json.RawMessage `json:"value"`
	UTF8   string          `json:"utf8"`
	Hex    string          `json:"hex"`
	Bech32 string          `json:"bech32"`
	Fields []valueNode     `json:"fields"`
}

type valueVector struct {
	Name                         string      `json:"name"`
	Domain                       string      `json:"domain"`
	Framing                      string      `json:"framing"`
	Fields                       []valueNode `json:"fields"`
	PreimageHex                  string      `json:"preimage_hex"`
	DigestHex                    string      `json:"digest_hex"`
	RootHex                      string      `json:"root_hex"`
	LeavesHex                    []string    `json:"leaves_hex"`
	WorkerValuesEncodedSizeBytes uint64      `json:"worker_values_encoded_size_bytes"`
}

type valueTree struct {
	leaves []valueVector // leaf vectors, in file order
	topK   []valueVector // verifier top-k set vectors, in file order
	root   valueVector
}

func loadValueTree(t *testing.T, path string) valueTree {
	t.Helper()
	data, err := wirevectors.PrereleaseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []valueVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var tree valueTree
	for _, vector := range file.Vectors {
		switch {
		case strings.HasSuffix(vector.Domain, "_ROOT_V1"):
			tree.root = vector
		case vector.Domain == nodewire.DomainVerifierTopKV1:
			tree.topK = append(tree.topK, vector)
		default:
			tree.leaves = append(tree.leaves, vector)
		}
	}
	if tree.root.RootHex == "" || len(tree.leaves) == 0 {
		t.Fatalf("%s publishes no tree", path)
	}
	return tree
}

// sub returns the field at index, asserting its published name.
func sub(t *testing.T, fields []valueNode, index int, name string) valueNode {
	t.Helper()
	if index >= len(fields) || fields[index].Name != name {
		t.Fatalf("field %d is not %q", index, name)
	}
	return fields[index]
}

func (n valueNode) u32(t *testing.T) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(string(n.Value), 10, 32)
	if err != nil {
		t.Fatalf("%s: %v", n.Name, err)
	}
	return uint32(v)
}

func (n valueNode) i64(t *testing.T) int64 {
	t.Helper()
	v, err := strconv.ParseInt(string(n.Value), 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", n.Name, err)
	}
	return v
}

func (n valueNode) flag(t *testing.T) bool {
	t.Helper()
	var v bool
	if err := json.Unmarshal(n.Value, &v); err != nil {
		t.Fatalf("%s is not a bool", n.Name)
	}
	return v
}

func (n valueNode) bytes(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(n.Hex)
	if err != nil {
		t.Fatalf("%s: %v", n.Name, err)
	}
	return raw
}

func (n valueNode) topK(t *testing.T) []nodewire.TopKEntryV1 {
	t.Helper()
	count := sub(t, n.Fields, 0, "count").u32(t)
	if int(count) != len(n.Fields)-1 {
		t.Fatalf("%s count %d does not match %d entries", n.Name, count, len(n.Fields)-1)
	}
	entries := make([]nodewire.TopKEntryV1, 0, count)
	for i := range int(count) {
		entry := sub(t, n.Fields, 1+i, "entry")
		entries = append(entries, nodewire.TopKEntryV1{
			TokenID:      sub(t, entry.Fields, 0, "token_id").u32(t),
			LogprobFP1e6: sub(t, entry.Fields, 1, "logprob_fp_1e6").i64(t),
		})
	}
	return entries
}

// requiredTopKOf is the published vectors' required_top_k: the size of every
// normal leaf's top-k list.
const requiredTopKOf = 2

func workerTreeFixture(t *testing.T) (nodewire.WorkerValueBindingV1, []nodewire.PositionValueV1, valueTree) {
	t.Helper()
	tree := loadValueTree(t, "task/worker_value_leaf_v1.json")
	var binding nodewire.WorkerValueBindingV1
	values := make([]nodewire.PositionValueV1, 0, len(tree.leaves))
	for i, leaf := range tree.leaves {
		if leaf.Domain != nodewire.DomainWorkerValueLeafV1 || sub(t, leaf.Fields, 0, "leaf_version").u32(t) != nodewire.ValueLeafVersionV1 {
			t.Fatalf("leaf %d is not a version-1 Worker value leaf", i)
		}
		f := sub(t, leaf.Fields, 1, "worker_value_leaf_bytes").Fields
		if len(f) != 11 {
			t.Fatalf("leaf %d has %d fields, want 11", i, len(f))
		}
		leafBinding := nodewire.WorkerValueBindingV1{
			ChainID:               sub(t, f, 0, "chain_id").UTF8,
			TaskID:                sub(t, f, 1, "task_id").bytes(t),
			AcceptedTaskHash:      sub(t, f, 2, "accepted_task_hash").bytes(t),
			WorkerOperatorAddress: sub(t, f, 3, "worker_operator_address").Bech32,
			RequiredTopK:          requiredTopKOf,
		}
		if i == 0 {
			binding = leafBinding
		} else if !reflect.DeepEqual(binding, leafBinding) {
			t.Fatalf("leaf %d carries a different binding", i)
		}
		values = append(values, nodewire.PositionValueV1{
			Position:     sub(t, f, 4, "position").u32(t),
			TokenID:      sub(t, f, 5, "token_id").u32(t),
			LogprobFP1e6: sub(t, f, 6, "worker_logprob_fp_1e6").i64(t),
			Rank:         sub(t, f, 7, "worker_rank").u32(t),
			TopK:         sub(t, f, 8, "topk_entries").topK(t),
			Missing:      sub(t, f, 9, "missing_flag").flag(t),
			Finite:       sub(t, f, 10, "finite_flag").flag(t),
		})
	}
	return binding, values, tree
}

func TestWorkerValueTreeReproducesPublishedVectors(t *testing.T) {
	binding, values, tree := workerTreeFixture(t)
	for i, value := range values {
		digest, err := nodewire.WorkerValueLeafHash(binding, value)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		leafBytes, err := nodewire.WorkerValueLeafBytes(binding, value)
		if err != nil {
			t.Fatal(err)
		}
		// The preimage is the domain, the leaf version and then the leaf bytes
		// as one framed field, so it must end with exactly those bytes.
		preimage, err := hex.DecodeString(tree.leaves[i].PreimageHex)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(preimage), string(leafBytes)) || codec.HashBytes(preimage) != digest {
			t.Fatalf("leaf %d preimage differs from the published encoding", i)
		}
		if got := hex.EncodeToString(digest[:]); got != tree.leaves[i].DigestHex || got != tree.root.LeavesHex[i] {
			t.Fatalf("leaf %d digest = %s, published %s", i, got, tree.leaves[i].DigestHex)
		}
	}
	root, err := nodewire.WorkerValueRoot(binding, values)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(root[:]); got != tree.root.RootHex {
		t.Fatalf("worker_value_root = %s, published %s", got, tree.root.RootHex)
	}
	raw, err := nodewire.EncodeWorkerValues(binding, values)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(raw)) != tree.root.WorkerValuesEncodedSizeBytes {
		t.Fatalf("worker_values is %d bytes, published %d", len(raw), tree.root.WorkerValuesEncodedSizeBytes)
	}
	decoded, err := nodewire.DecodeWorkerValues(binding, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, values) {
		t.Fatal("DecodeWorkerValues does not round-trip the published values")
	}
}

func TestWorkerValueLeafRejectsIllegalValues(t *testing.T) {
	binding, values, _ := workerTreeFixture(t)
	normal, missing := values[0], values[2]
	for name, bad := range map[string]nodewire.PositionValueV1{
		"missing and finite":     func() nodewire.PositionValueV1 { v := missing; v.Finite = true; return v }(),
		"missing with a logprob": func() nodewire.PositionValueV1 { v := missing; v.LogprobFP1e6 = -1; return v }(),
		"non-finite with a rank": func() nodewire.PositionValueV1 { v := missing; v.Missing = false; v.Rank = 1; return v }(),
		"missing with top-k":     func() nodewire.PositionValueV1 { v := missing; v.TopK = normal.TopK; return v }(),
		"top-k shorter than K":   func() nodewire.PositionValueV1 { v := normal; v.TopK = v.TopK[:1]; return v }(),
		"top-k repeats a token": func() nodewire.PositionValueV1 {
			v := normal
			v.TopK = []nodewire.TopKEntryV1{v.TopK[0], v.TopK[0]}
			return v
		}(),
		"rank beyond K": func() nodewire.PositionValueV1 { v := normal; v.Rank = requiredTopKOf + 1; return v }(),
	} {
		if _, err := nodewire.WorkerValueLeafHash(binding, bad); err == nil {
			t.Errorf("%s: WorkerValueLeafHash() error = nil", name)
		}
	}
	// A non-finite value is a legal third state, distinct from missing.
	nonFinite := missing
	nonFinite.Missing = false
	if _, err := nodewire.WorkerValueLeafHash(binding, nonFinite); err != nil {
		t.Fatalf("non-finite value refused: %v", err)
	}
	// Reordering the top-k is not an error, but it must commit to a different
	// leaf: the list is the engine's rank order, not a set.
	swapped := normal
	swapped.TopK = []nodewire.TopKEntryV1{normal.TopK[1], normal.TopK[0]}
	a, _ := nodewire.WorkerValueLeafHash(binding, normal)
	b, err := nodewire.WorkerValueLeafHash(binding, swapped)
	if err != nil || a == b {
		t.Fatalf("reordered top-k produced the same leaf (err %v)", err)
	}
	for name, bad := range map[string][]nodewire.PositionValueV1{
		"gap":       {values[0], values[2]},
		"duplicate": {values[0], values[0]},
		"reordered": {values[1], values[0]},
	} {
		if _, err := nodewire.WorkerValueRoot(binding, bad); err == nil {
			t.Errorf("%s positions: WorkerValueRoot() error = nil", name)
		}
	}
}

func TestDecodeWorkerValuesIsStrict(t *testing.T) {
	binding, values, _ := workerTreeFixture(t)
	raw, err := nodewire.EncodeWorkerValues(binding, values)
	if err != nil {
		t.Fatal(err)
	}
	otherTask := binding
	otherTask.TaskID = append([]byte(nil), binding.TaskID...)
	otherTask.TaskID[0] ^= 1
	fewer := append([]byte(nil), raw...)
	fewer[3]-- // claims two leaves, carries three
	for name, tc := range map[string]struct {
		binding nodewire.WorkerValueBindingV1
		raw     []byte
	}{
		"another task's binding": {otherTask, raw},
		"trailing byte":          {binding, append(append([]byte(nil), raw...), 0)},
		"truncated":              {binding, raw[:len(raw)-1]},
		"count below leaves":     {binding, fewer},
		"no count":               {binding, raw[:3]},
	} {
		if _, err := nodewire.DecodeWorkerValues(tc.binding, tc.raw); err == nil {
			t.Errorf("%s: DecodeWorkerValues() error = nil", name)
		}
	}
	empty, err := nodewire.EncodeWorkerValues(binding, nil)
	if err != nil || hex.EncodeToString(empty) != "00000000" {
		t.Fatalf("empty worker_values = %x, %v", empty, err)
	}
}

func TestVerifierValueTreeReproducesPublishedVectors(t *testing.T) {
	tree := loadValueTree(t, "task/verifier_value_leaf_v1.json")
	if len(tree.topK) != len(tree.leaves) {
		t.Fatalf("%d top-k vectors for %d leaves", len(tree.topK), len(tree.leaves))
	}
	var binding nodewire.VerifierValueBindingV1
	values := make([]nodewire.PositionValueV1, 0, len(tree.leaves))
	for i, leaf := range tree.leaves {
		topK := sub(t, tree.topK[i].Fields, 0, "topk_entries").topK(t)
		topKHash, err := nodewire.VerifierTopKSetHash(topK)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(topKHash[:]); got != tree.topK[i].DigestHex {
			t.Fatalf("top-k set %d = %s, published %s", i, got, tree.topK[i].DigestHex)
		}
		if leaf.Domain != nodewire.DomainVerifierValueLeafV1 || sub(t, leaf.Fields, 0, "leaf_version").u32(t) != nodewire.ValueLeafVersionV1 {
			t.Fatalf("leaf %d is not a version-1 Verifier value leaf", i)
		}
		f := sub(t, leaf.Fields, 1, "verifier_value_leaf_bytes").Fields
		if len(f) != 12 {
			t.Fatalf("leaf %d has %d fields, want 12", i, len(f))
		}
		operator, err := nodewire.CanonicalOperatorAddressString("trueopen", sub(t, f, 4, "verifier_operator_address").bytes(t))
		if err != nil {
			t.Fatal(err)
		}
		binding = nodewire.VerifierValueBindingV1{
			ChainID:                 sub(t, f, 0, "chain_id").UTF8,
			TaskID:                  sub(t, f, 1, "task_id").bytes(t),
			TaskHash:                sub(t, f, 2, "task_hash").bytes(t),
			VerifyRound:             sub(t, f, 3, "verify_round").u32(t),
			VerifierOperatorAddress: operator,
			RequiredTopK:            requiredTopKOf,
		}
		if hex.EncodeToString(topKHash[:]) != sub(t, f, 9, "verifier_topk_set_hash").Hex {
			t.Fatalf("leaf %d does not carry its published top-k set hash", i)
		}
		value := nodewire.PositionValueV1{
			Position:     sub(t, f, 5, "output_position").u32(t),
			TokenID:      sub(t, f, 6, "emitted_token_id").u32(t),
			LogprobFP1e6: sub(t, f, 7, "verifier_logprob_fp_1e6").i64(t),
			Rank:         sub(t, f, 8, "verifier_rank").u32(t),
			TopK:         topK,
			Missing:      sub(t, f, 10, "missing_flag").flag(t),
			Finite:       sub(t, f, 11, "finite_flag").flag(t),
		}
		digest, err := nodewire.VerifierValueLeafHash(binding, value)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		if got := hex.EncodeToString(digest[:]); got != leaf.DigestHex {
			t.Fatalf("verifier leaf %d = %s, published %s", i, got, leaf.DigestHex)
		}
		values = append(values, value)
	}
	root, err := nodewire.VerifierValueRoot(binding, values)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(root[:]); got != tree.root.RootHex {
		t.Fatalf("verifier_value_root = %s, published %s", got, tree.root.RootHex)
	}
	round0 := binding
	round0.VerifyRound = 0
	if _, err := nodewire.VerifierValueRoot(round0, values); err == nil {
		t.Fatal("VerifierValueRoot() accepted verify_round 0")
	}
}
