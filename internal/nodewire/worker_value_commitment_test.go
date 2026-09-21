package nodewire_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

// wirevectors.File verifies the published Worker commitment fixture against
// the pinned release manifest.
const workerValueCommitmentFixturePath = "task/worker_value_commitment_v2.json"

// workerValueCommitmentVector is the vector's name inside the fixture. wire
// publishes it in the same envelope as the Task stage domains - a schema stamp
// plus a vectors array - so it is read through the same goldenVector decoder
// rather than a second bespoke struct.
const workerValueCommitmentVector = "worker_value_commitment_v2"

// workerValueCommitmentFixtureV2 is the published vector's two expected
// outputs. The digest doubles as evidence_hash_or_root: the vector's digest_hex
// IS the derived value, so there is no separate expected field upstream.
type workerValueCommitmentFixtureV2 struct {
	ExpectedEvidenceHashOrRoot string
	ExpectedEncodedSizeBytes   uint64
}

// workerValueCommitmentFile is the published file's shape: the same schema stamp
// and vectors array as the Task stage domains, plus this domain's one extra
// derived output.
type workerValueCommitmentFile struct {
	Schema  string `json:"schema"`
	Vectors []struct {
		goldenVector
		ExpectedEncodedSizeBytes uint64 `json:"expected_encoded_size_bytes"`
	} `json:"vectors"`
}

// TestWorkerValueCommitmentReproducesNodeGoldenVector is the whole reason this
// derivation may be trusted. The frozen SubmitInferReceipt handler does not
// recompute evidence_hash_or_root, so nothing on chain would notice a wrong
// value today; this vector is the only thing that does.
func TestWorkerValueCommitmentReproducesNodeGoldenVector(t *testing.T) {
	// The fixture loader has already verified the file against wire's release
	// manifest, so there is no separate provenance assertion here.
	value, fixture := workerValueCommitmentFixture(t)
	digest, encodedSize, err := nodewire.WorkerValueCommitment(value)
	if err != nil {
		t.Fatalf("WorkerValueCommitment: %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got != fixture.ExpectedEvidenceHashOrRoot {
		t.Fatalf("digest = %s, published v0.4.1 digest = %s", got, fixture.ExpectedEvidenceHashOrRoot)
	}
	raw, err := wirevectors.File(workerValueCommitmentFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var published workerValueCommitmentFile
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(published.Vectors[0].PreimageHex)
	if err != nil {
		t.Fatal(err)
	}
	if codec.HashBytes(want) != digest {
		t.Fatal("current 20-field formula differs from published encoding")
	}
	if encodedSize != fixture.ExpectedEncodedSizeBytes {
		t.Fatalf("encoded_size_bytes = %d, want Node's vector %d", encodedSize, fixture.ExpectedEncodedSizeBytes)
	}
	// The published digest and the published preimage must be the same bytes, so
	// a consumer that reproduces one reproduces the other.
	preimage, err := nodewire.WorkerValueCommitmentPreimage(value)
	if err != nil {
		t.Fatalf("WorkerValueCommitmentPreimage: %v", err)
	}
	if sha256.Sum256(preimage) != digest {
		t.Fatal("the digest is not SHA-256 over the preimage this package publishes")
	}
	if hex.EncodeToString(preimage) != published.Vectors[0].PreimageHex {
		t.Fatal("preimage differs from published encoding")
	}
	// The domain must be the framed first field, not a bare literal spliced in
	// somewhere else in the preimage.
	if !strings.HasPrefix(string(preimage[8:]), nodewire.DomainWorkerValueCommitmentV2) {
		t.Fatalf("preimage does not open with the framed domain %q", nodewire.DomainWorkerValueCommitmentV2)
	}
}

// TestWorkerValueCommitmentBindsEveryField runs Node's own twelve mutations
// (x/task/types/worker_value_commitment_test.go:22-42) plus the two the
// upstream list cannot express in place: the chain id is the only string field,
// and the operator address is the only one whose framed bytes are not what the
// struct holds.
func TestWorkerValueCommitmentBindsEveryField(t *testing.T) {
	base, _ := workerValueCommitmentFixture(t)
	baseDigest, _, err := nodewire.WorkerValueCommitment(base)
	if err != nil {
		t.Fatalf("WorkerValueCommitment: %v", err)
	}
	for _, tc := range []struct {
		field  string
		mutate func(*nodewire.WorkerValueCommitmentV2)
	}{
		{"chain_id", func(v *nodewire.WorkerValueCommitmentV2) { v.ChainID += "-changed" }},
		{"task_id", func(v *nodewire.WorkerValueCommitmentV2) { v.TaskID[0]++ }},
		{"accepted_task_hash", func(v *nodewire.WorkerValueCommitmentV2) { v.AcceptedTaskHash[0]++ }},
		{"worker_operator_address", func(v *nodewire.WorkerValueCommitmentV2) {
			v.WorkerOperatorAddress = otherWorkerValueCommitmentAddress
		}},
		{"generation_params_digest", func(v *nodewire.WorkerValueCommitmentV2) { v.GenerationParamsDigest[0]++ }},
		{"evidence_schema_hash", func(v *nodewire.WorkerValueCommitmentV2) { v.EvidenceSchemaHash[0]++ }},
		{"output_hash", func(v *nodewire.WorkerValueCommitmentV2) { v.OutputHash[0]++ }},
		{"output_size_bytes", func(v *nodewire.WorkerValueCommitmentV2) { v.OutputSizeBytes++ }},
		{"finish_reason", func(v *nodewire.WorkerValueCommitmentV2) {
			v.FinishReason = nodewire.FinishReasonV1StopSequence
		}},
		{"trace_root", func(v *nodewire.WorkerValueCommitmentV2) { v.TraceRoot[0]++ }},
		{"trace_encoded_size_bytes", func(v *nodewire.WorkerValueCommitmentV2) { v.TraceEncodedSizeBytes++ }},
		{"checkpoint_root", func(v *nodewire.WorkerValueCommitmentV2) { v.CheckpointRoot[0]++ }},
		{"checkpoint_encoded_size_bytes", func(v *nodewire.WorkerValueCommitmentV2) { v.CheckpointEncodedSizeBytes++ }},
		{"generated_token_count", func(v *nodewire.WorkerValueCommitmentV2) { v.GeneratedTokenCount++; v.GeneratedTokenIDsSizeBytes += 4 }},
		{"output_leaf_count", func(v *nodewire.WorkerValueCommitmentV2) { v.OutputLeafCount++ }},
		{"input_token_ids_hash", func(v *nodewire.WorkerValueCommitmentV2) { v.InputTokenIDsHash[0]++ }},
		{"generated_token_ids_hash", func(v *nodewire.WorkerValueCommitmentV2) { v.GeneratedTokenIDsHash[0]++ }},
		{"input_token_ids_size_bytes", func(v *nodewire.WorkerValueCommitmentV2) { v.InputTokenIDsSizeBytes += 4 }},
	} {
		changed, _ := workerValueCommitmentFixture(t)
		tc.mutate(&changed)
		changedDigest, _, err := nodewire.WorkerValueCommitment(changed)
		if err != nil {
			t.Fatalf("%s: WorkerValueCommitment: %v", tc.field, err)
		}
		if changedDigest == baseDigest {
			t.Fatalf("%s does not reach the commitment digest", tc.field)
		}
	}
}

// TestWorkerValueCommitmentDetectsAFieldReorder is the check a per-field bit
// flip cannot make. Eight of the fourteen fields are Hash32 and three are
// uint64, so a refactor that swaps two same-width neighbours produces a frame of
// exactly the same length and passes every length assertion. Swapping the values
// of two such pairs must move the digest, which is only true if the frame keeps
// them positionally distinct.
func TestWorkerValueCommitmentDetectsAFieldReorder(t *testing.T) {
	base, _ := workerValueCommitmentFixture(t)
	baseDigest, _, err := nodewire.WorkerValueCommitment(base)
	if err != nil {
		t.Fatalf("WorkerValueCommitment: %v", err)
	}
	for _, tc := range []struct {
		name string
		swap func(*nodewire.WorkerValueCommitmentV2)
	}{
		{"accepted_task_hash and generation_params_digest", func(v *nodewire.WorkerValueCommitmentV2) {
			v.AcceptedTaskHash, v.GenerationParamsDigest = v.GenerationParamsDigest, v.AcceptedTaskHash
		}},
		{"evidence_schema_hash and output_hash", func(v *nodewire.WorkerValueCommitmentV2) {
			v.EvidenceSchemaHash, v.OutputHash = v.OutputHash, v.EvidenceSchemaHash
		}},
		{"trace_root and checkpoint_root", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceRoot, v.CheckpointRoot = v.CheckpointRoot, v.TraceRoot
		}},
		{"trace and checkpoint encoded sizes", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceEncodedSizeBytes, v.CheckpointEncodedSizeBytes = v.CheckpointEncodedSizeBytes, v.TraceEncodedSizeBytes
		}},
	} {
		swapped, _ := workerValueCommitmentFixture(t)
		tc.swap(&swapped)
		swappedDigest, swappedSize, err := nodewire.WorkerValueCommitment(swapped)
		if err != nil {
			t.Fatalf("%s: WorkerValueCommitment: %v", tc.name, err)
		}
		if swappedDigest == baseDigest {
			t.Fatalf("swapping %s leaves the digest unchanged, so the frame does not order them", tc.name)
		}
		if swappedSize != 40 {
			t.Fatalf("%s: encoded_size_bytes = %d, want the sum to stay commutative at 40", tc.name, swappedSize)
		}
	}
}

// TestWorkerValueCommitmentRejectsWhatNodeRejects mirrors
// x/task/types/worker_value_commitment_test.go:44-61 plus the two
// structural rejections its fixture cannot express. Refusing more than Node
// would refuse a digest the chain accepts, and refusing less would invent one it
// cannot, so this pins the boundary in both directions.
func TestWorkerValueCommitmentRejectsWhatNodeRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*nodewire.WorkerValueCommitmentV2)
		message string
	}{
		{"unsuccessful finish reason", func(v *nodewire.WorkerValueCommitmentV2) {
			v.FinishReason = nodewire.FinishReasonV1Unspecified
		}, "not a successful V1 reason"},
		{"unknown finish reason", func(v *nodewire.WorkerValueCommitmentV2) {
			v.FinishReason = nodewire.FinishReasonV1MaxOutputDuration + 1
		}, "not a successful V1 reason"},
		{"encoded size overflow", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceEncodedSizeBytes, v.CheckpointEncodedSizeBytes = math.MaxUint64, 1
		}, "combined evidence"},
		{"encoded size above the contract ceiling", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceEncodedSizeBytes, v.CheckpointEncodedSizeBytes = nodewire.MaxEvidenceEncodedSizeBytesV1, 1
		}, "combined evidence"},
		{"zero checkpoint size", func(v *nodewire.WorkerValueCommitmentV2) {
			v.CheckpointEncodedSizeBytes = 0
		}, "encoded sizes must be positive"},
		{"zero trace size", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceEncodedSizeBytes = 0
		}, "encoded sizes must be positive"},
		{"zero output leaf count", func(v *nodewire.WorkerValueCommitmentV2) {
			v.OutputLeafCount = 0
		}, "output_leaf_count must be positive"},
		{"zero input token artifact size", func(v *nodewire.WorkerValueCommitmentV2) {
			v.InputTokenIDsSizeBytes = 0
		}, "token IDs size"},
		{"generated count mismatch", func(v *nodewire.WorkerValueCommitmentV2) {
			v.GeneratedTokenCount++
		}, "generated token IDs size"},
		{"short input token hash", func(v *nodewire.WorkerValueCommitmentV2) {
			v.InputTokenIDsHash = nil
		}, "input_token_ids_hash"},
		{"short generated token hash", func(v *nodewire.WorkerValueCommitmentV2) {
			v.GeneratedTokenIDsHash = nil
		}, "generated_token_ids_hash"},
		{"wrong schema version", func(v *nodewire.WorkerValueCommitmentV2) {
			v.SchemaVersion = nodewire.WorkerValueCommitmentSchemaVersionV2 + 1
		}, "schema_version must be 2"},
		{"empty chain id", func(v *nodewire.WorkerValueCommitmentV2) { v.ChainID = "" }, "chain_id must be non-empty"},
		{"short trace root", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TraceRoot = v.TraceRoot[:31]
		}, "trace_root must be exactly 32 raw bytes"},
		{"hex text task id", func(v *nodewire.WorkerValueCommitmentV2) {
			v.TaskID = []byte(hex.EncodeToString(v.TaskID))
		}, "task_id must be exactly 32 raw bytes"},
		{"non-Bech32 worker address", func(v *nodewire.WorkerValueCommitmentV2) {
			v.WorkerOperatorAddress = "not-an-address"
		}, "worker_operator_address"},
	} {
		value, _ := workerValueCommitmentFixture(t)
		tc.mutate(&value)
		digest, size, err := nodewire.WorkerValueCommitment(value)
		if err == nil {
			t.Fatalf("%s produced digest %x and size %d instead of a refusal", tc.name, digest, size)
		}
		if !strings.Contains(err.Error(), tc.message) {
			t.Fatalf("%s error = %v, want it to contain %q", tc.name, err, tc.message)
		}
		// A refused derivation must hand back nothing usable: a caller that
		// ignores err must not find a plausible 32 bytes or a plausible size.
		if digest != (codec.Hash{}) || size != 0 {
			t.Fatalf("%s returned digest %x and size %d alongside its error", tc.name, digest, size)
		}
	}
}

// otherWorkerValueCommitmentAddress is a second canonical Bech32 address with
// the same human-readable prefix as the fixture's. The prefix is presentation
// and is never framed, so a mutation test needs two addresses that differ in
// their codec bytes rather than in their text.
const otherWorkerValueCommitmentAddress = "trueopen1kxet8d94k6mm3wd6hw7tm04lcrqu9s7yxckkka"

func workerValueCommitmentFixture(t *testing.T) (nodewire.WorkerValueCommitmentV2, workerValueCommitmentFixtureV2) {
	t.Helper()
	data, err := wirevectors.File(workerValueCommitmentFixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", workerValueCommitmentFixturePath, err)
	}
	// Provenance is the file's own digest against wire's release manifest, so a
	// refresh that drops in an unverified vector fails before any comparison.
	var file workerValueCommitmentFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode %s: %v", workerValueCommitmentFixturePath, err)
	}
	if len(file.Vectors) != 1 || file.Vectors[0].Name != workerValueCommitmentVector {
		t.Fatalf("%s must publish exactly the %s vector", workerValueCommitmentFixturePath,
			workerValueCommitmentVector)
	}
	vector := file.Vectors[0]
	if vector.Domain != nodewire.DomainWorkerValueCommitmentV2 || vector.Framing != "H_FIELDS_V1" {
		t.Fatalf("%s declares domain %q framing %q", workerValueCommitmentVector, vector.Domain, vector.Framing)
	}
	// Read positionally through the shared accessors, which assert each field's
	// published name and type. Reading by name would let an upstream reorder
	// pass silently, and field order is what the framing commits.
	return nodewire.WorkerValueCommitmentV2{
			SchemaVersion:              uint32(fieldUint(t, vector.goldenVector, 0, "schema_version")),
			ChainID:                    fieldString(t, vector.goldenVector, 1, "chain_id"),
			TaskID:                     fieldBytes(t, vector.goldenVector, 2, "task_id"),
			AcceptedTaskHash:           fieldBytes(t, vector.goldenVector, 3, "accepted_task_hash"),
			WorkerOperatorAddress:      fieldBech32(t, vector.goldenVector, 4, "worker_operator_address"),
			GenerationParamsDigest:     fieldBytes(t, vector.goldenVector, 5, "generation_params_digest"),
			EvidenceSchemaHash:         fieldBytes(t, vector.goldenVector, 6, "evidence_schema_hash"),
			OutputHash:                 fieldBytes(t, vector.goldenVector, 7, "output_hash"),
			OutputSizeBytes:            fieldUint(t, vector.goldenVector, 8, "output_size_bytes"),
			FinishReason:               nodewire.FinishReasonV1(fieldUint(t, vector.goldenVector, 9, "finish_reason")),
			TraceRoot:                  fieldBytes(t, vector.goldenVector, 10, "trace_root"),
			TraceEncodedSizeBytes:      fieldUint(t, vector.goldenVector, 11, "trace_encoded_size_bytes"),
			CheckpointRoot:             fieldBytes(t, vector.goldenVector, 12, "checkpoint_root"),
			CheckpointEncodedSizeBytes: fieldUint(t, vector.goldenVector, 13, "checkpoint_encoded_size_bytes"),
			GeneratedTokenCount:        fieldUint(t, vector.goldenVector, 14, "generated_token_count"),
			OutputLeafCount:            fieldUint(t, vector.goldenVector, 15, "output_leaf_count"),
			InputTokenIDsHash:          fieldBytes(t, vector.goldenVector, 16, "input_token_ids_hash"),
			GeneratedTokenIDsHash:      fieldBytes(t, vector.goldenVector, 17, "generated_token_ids_hash"),
			InputTokenIDsSizeBytes:     fieldUint(t, vector.goldenVector, 18, "input_token_ids_size_bytes"),
			GeneratedTokenIDsSizeBytes: fieldUint(t, vector.goldenVector, 19, "generated_token_ids_size_bytes"),
		}, workerValueCommitmentFixtureV2{
			ExpectedEvidenceHashOrRoot: vector.DigestHex,
			ExpectedEncodedSizeBytes:   vector.ExpectedEncodedSizeBytes,
		}
}
