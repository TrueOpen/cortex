package builderclient

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func completeWorkerValueEvidenceFacts() WorkerValueEvidenceFacts {
	return WorkerValueEvidenceFacts{
		ChainID:                    "trueopen-task-1",
		TaskID:                     strings.Repeat("11", 32),
		AcceptedTaskHash:           strings.Repeat("22", 32),
		WorkerOperatorAddress:      "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		GenerationParamsDigest:     strings.Repeat("33", 32),
		EvidenceSchemaHash:         strings.Repeat("44", 32),
		OutputHash:                 codec.HashBytes([]byte("output")),
		OutputSizeBytes:            1536,
		OutputLeafCount:            1,
		GeneratedTokenCount:        3,
		InputTokenIDsHash:          codec.HashBytes([]byte("input tokens")),
		GeneratedTokenIDsHash:      codec.HashBytes([]byte("generated tokens")),
		InputTokenIDsSizeBytes:     8,
		GeneratedTokenIDsSizeBytes: 16,
		FinishReason:               nodewire.FinishReasonV1EosToken,
		TraceRoot:                  codec.HashBytes([]byte("trace")),
		TraceEncodedSizeBytes:      3072,
		CheckpointRoot:             codec.HashBytes([]byte("checkpoint")),
		CheckpointEncodedSizeBytes: 1024,
	}
}

// The commitment Cortex emits must satisfy every precondition the frozen handler
// applies, and its size must be the derivation's own sum rather than anything the
// caller computed. Deriving it and then validating it against the requirement set
// is the whole contract, so it is asserted as one flow.
func TestWorkerValueEvidenceCommitmentSatisfiesTheHandler(t *testing.T) {
	facts := completeWorkerValueEvidenceFacts()
	commitment, err := WorkerValueEvidenceCommitment(facts)
	if err != nil {
		t.Fatalf("WorkerValueEvidenceCommitment: %v", err)
	}
	if commitment.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening {
		t.Fatalf("evidence_kind = %d, want EVIDENCE_KIND_WORKER_VALUE_OPENING", commitment.EvidenceKind)
	}
	if commitment.EncodedSizeBytes != facts.TraceEncodedSizeBytes+facts.CheckpointEncodedSizeBytes+facts.InputTokenIDsSizeBytes+facts.GeneratedTokenIDsSizeBytes {
		t.Fatalf("encoded_size_bytes = %d, want the trace plus checkpoint sum %d",
			commitment.EncodedSizeBytes, facts.TraceEncodedSizeBytes+facts.CheckpointEncodedSizeBytes)
	}
	// The root is the TRUEOPEN_WORKER_VALUE_COMMITMENT_V1 digest, not any artifact
	// hash that went into it.
	for name, hash := range map[string]codec.Hash{
		"output_hash": facts.OutputHash, "trace_root": facts.TraceRoot, "checkpoint_root": facts.CheckpointRoot,
	} {
		if commitment.EvidenceHashOrRoot == hash {
			t.Fatalf("evidence_hash_or_root is the bare %s, not the commitment digest", name)
		}
	}
	if err := ValidateProfileEvidenceCommitments(
		WorkerValueEvidenceRequirementsV2(), []EvidenceCommitment{commitment},
	); err != nil {
		t.Fatalf("the derived commitment fails a handler precondition: %v", err)
	}
	// The digest must be exactly what internal/nodewire publishes for the same
	// inputs, so the two can never drift.
	want, wantSize, err := nodewire.WorkerValueCommitment(nodewire.WorkerValueCommitmentV2{
		SchemaVersion:              nodewire.WorkerValueCommitmentSchemaVersionV2,
		ChainID:                    facts.ChainID,
		TaskID:                     mustHex32(t, facts.TaskID),
		AcceptedTaskHash:           mustHex32(t, facts.AcceptedTaskHash),
		WorkerOperatorAddress:      facts.WorkerOperatorAddress,
		GenerationParamsDigest:     mustHex32(t, facts.GenerationParamsDigest),
		EvidenceSchemaHash:         mustHex32(t, facts.EvidenceSchemaHash),
		OutputHash:                 facts.OutputHash[:],
		OutputSizeBytes:            facts.OutputSizeBytes,
		OutputLeafCount:            facts.OutputLeafCount,
		GeneratedTokenCount:        facts.GeneratedTokenCount,
		InputTokenIDsHash:          facts.InputTokenIDsHash[:],
		GeneratedTokenIDsHash:      facts.GeneratedTokenIDsHash[:],
		InputTokenIDsSizeBytes:     facts.InputTokenIDsSizeBytes,
		GeneratedTokenIDsSizeBytes: facts.GeneratedTokenIDsSizeBytes,
		FinishReason:               facts.FinishReason,
		TraceRoot:                  facts.TraceRoot[:],
		TraceEncodedSizeBytes:      facts.TraceEncodedSizeBytes,
		CheckpointRoot:             facts.CheckpointRoot[:],
		CheckpointEncodedSizeBytes: facts.CheckpointEncodedSizeBytes,
	})
	if err != nil {
		t.Fatalf("nodewire.WorkerValueCommitment: %v", err)
	}
	if commitment.EvidenceHashOrRoot != want || commitment.EncodedSizeBytes != wantSize {
		t.Fatalf("commitment = %x/%d, want the nodewire derivation %x/%d",
			commitment.EvidenceHashOrRoot, commitment.EncodedSizeBytes, want, wantSize)
	}
}

// Every Hash32 input is bound into the digest, so a wrong value anywhere produces
// a different commitment. The handler never recomputes this digest, so nothing on
// chain would catch a field that quietly stopped reaching it.
func TestWorkerValueEvidenceCommitmentBindsEveryInput(t *testing.T) {
	base, err := WorkerValueEvidenceCommitment(completeWorkerValueEvidenceFacts())
	if err != nil {
		t.Fatalf("WorkerValueEvidenceCommitment: %v", err)
	}
	for _, tc := range []struct {
		field  string
		mutate func(*WorkerValueEvidenceFacts)
	}{
		{"chain_id", func(f *WorkerValueEvidenceFacts) { f.ChainID += "-other" }},
		{"task_id", func(f *WorkerValueEvidenceFacts) { f.TaskID = strings.Repeat("1a", 32) }},
		{"accepted_task_hash", func(f *WorkerValueEvidenceFacts) { f.AcceptedTaskHash = strings.Repeat("2a", 32) }},
		{"generation_params_digest", func(f *WorkerValueEvidenceFacts) {
			f.GenerationParamsDigest = strings.Repeat("3a", 32)
		}},
		{"evidence_schema_hash", func(f *WorkerValueEvidenceFacts) { f.EvidenceSchemaHash = strings.Repeat("4a", 32) }},
		{"output_hash", func(f *WorkerValueEvidenceFacts) { f.OutputHash = codec.HashBytes([]byte("other output")) }},
		{"output_size_bytes", func(f *WorkerValueEvidenceFacts) { f.OutputSizeBytes++ }},
		{"output_leaf_count", func(f *WorkerValueEvidenceFacts) { f.OutputLeafCount++ }},
		{"input_token_ids_hash", func(f *WorkerValueEvidenceFacts) { f.InputTokenIDsHash[0] ^= 1 }},
		{"generated_token_ids_hash", func(f *WorkerValueEvidenceFacts) { f.GeneratedTokenIDsHash[0] ^= 1 }},
		{"input_token_ids_size", func(f *WorkerValueEvidenceFacts) { f.InputTokenIDsSizeBytes += 4 }},
		{"generated_token_count", func(f *WorkerValueEvidenceFacts) { f.GeneratedTokenCount++; f.GeneratedTokenIDsSizeBytes += 4 }},
		{"finish_reason", func(f *WorkerValueEvidenceFacts) { f.FinishReason = nodewire.FinishReasonV1MaxOutputTokens }},
		{"trace_root", func(f *WorkerValueEvidenceFacts) { f.TraceRoot = codec.HashBytes([]byte("other trace")) }},
		{"checkpoint_root", func(f *WorkerValueEvidenceFacts) {
			f.CheckpointRoot = codec.HashBytes([]byte("other checkpoint"))
		}},
	} {
		facts := completeWorkerValueEvidenceFacts()
		tc.mutate(&facts)
		changed, err := WorkerValueEvidenceCommitment(facts)
		if err != nil {
			t.Fatalf("%s: WorkerValueEvidenceCommitment: %v", tc.field, err)
		}
		if changed.EvidenceHashOrRoot == base.EvidenceHashOrRoot {
			t.Fatalf("%s does not reach the commitment digest", tc.field)
		}
	}
	// Swapping the two artifact roots must move the digest too: they are the same
	// width, so a frame that lost their order would produce identical bytes.
	swapped := completeWorkerValueEvidenceFacts()
	swapped.TraceRoot, swapped.CheckpointRoot = swapped.CheckpointRoot, swapped.TraceRoot
	changed, err := WorkerValueEvidenceCommitment(swapped)
	if err != nil {
		t.Fatalf("WorkerValueEvidenceCommitment: %v", err)
	}
	if changed.EvidenceHashOrRoot == base.EvidenceHashOrRoot {
		t.Fatal("swapping trace_root and checkpoint_root leaves the digest unchanged")
	}
}

// A missing or all-zero input must be refused, not folded into a well-formed
// digest. The consensus reads and finish_reason are protocol gaps and carry the
// unavailable-input sentinel so a caller can tell them from a Cortex bug; an
// all-zero artifact root is a local bug and does not.
func TestWorkerValueEvidenceCommitmentRefusesUnusableInputs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mutate      func(*WorkerValueEvidenceFacts)
		contains    string
		unavailable bool
	}{
		{"unset accepted_task_hash", func(f *WorkerValueEvidenceFacts) { f.AcceptedTaskHash = "" },
			"TaskCoreState.accepted_task_hash", true},
		{"all-zero accepted_task_hash", func(f *WorkerValueEvidenceFacts) {
			f.AcceptedTaskHash = strings.Repeat("00", 32)
		}, "TaskCoreState.accepted_task_hash", true},
		{"all-zero generation_params_digest", func(f *WorkerValueEvidenceFacts) {
			f.GenerationParamsDigest = strings.Repeat("00", 32)
		}, "TaskAssignmentState.generation_params_digest", true},
		{"unset evidence_schema_hash", func(f *WorkerValueEvidenceFacts) { f.EvidenceSchemaHash = "" },
			"hub.v1.Query/Profile", true},
		{"all-zero evidence_schema_hash", func(f *WorkerValueEvidenceFacts) {
			f.EvidenceSchemaHash = strings.Repeat("00", 32)
		}, "hub.v1.Query/Profile", true},
		{"all-zero task_id", func(f *WorkerValueEvidenceFacts) { f.TaskID = strings.Repeat("00", 32) },
			"task_id", true},
		{"unspecified finish_reason", func(f *WorkerValueEvidenceFacts) {
			f.FinishReason = nodewire.FinishReasonV1Unspecified
		}, "finish_reason", true},
		{"uppercase hex", func(f *WorkerValueEvidenceFacts) { f.AcceptedTaskHash = strings.Repeat("2A", 32) },
			"lowercase 32-byte hex", false},
		{"short hex", func(f *WorkerValueEvidenceFacts) { f.EvidenceSchemaHash = strings.Repeat("44", 31) },
			"lowercase 32-byte hex", false},
		{"all-zero trace_root", func(f *WorkerValueEvidenceFacts) { f.TraceRoot = codec.Hash{} },
			"trace_root must not be 32 zero bytes", false},
		{"all-zero checkpoint_root", func(f *WorkerValueEvidenceFacts) { f.CheckpointRoot = codec.Hash{} },
			"checkpoint_root must not be 32 zero bytes", false},
		{"all-zero output_hash", func(f *WorkerValueEvidenceFacts) { f.OutputHash = codec.Hash{} },
			"output_hash must not be 32 zero bytes", false},
		{"zero trace size", func(f *WorkerValueEvidenceFacts) { f.TraceEncodedSizeBytes = 0 },
			"encoded sizes must be positive", false},
		{"zero checkpoint size", func(f *WorkerValueEvidenceFacts) { f.CheckpointEncodedSizeBytes = 0 },
			"encoded sizes must be positive", false},
		{"zero output leaves", func(f *WorkerValueEvidenceFacts) { f.OutputLeafCount = 0 },
			"output_leaf_count must be positive", false},
		{"empty chain_id", func(f *WorkerValueEvidenceFacts) { f.ChainID = "" },
			"chain_id must be non-empty", false},
		{"non-Bech32 worker", func(f *WorkerValueEvidenceFacts) { f.WorkerOperatorAddress = "worker-1" },
			"worker_operator_address", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := completeWorkerValueEvidenceFacts()
			tc.mutate(&facts)
			commitment, err := WorkerValueEvidenceCommitment(facts)
			if err == nil {
				t.Fatalf("accepted %s and produced %#v", tc.name, commitment)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %v, want it to name %q", err, tc.contains)
			}
			if errors.Is(err, ErrInferReceiptInputUnavailable) != tc.unavailable {
				t.Fatalf("error = %v, ErrInferReceiptInputUnavailable = %t, want %t",
					err, !tc.unavailable, tc.unavailable)
			}
			if commitment != (EvidenceCommitment{}) {
				t.Fatalf("refused derivation still returned %#v", commitment)
			}
		})
	}
}

// WorkerValueEvidenceRequirementsV2 is a derived constant, not a guess: V1
// admits exactly one WORKER_VALUE_OPENING requirement at commitment schema
// version 1, bounded by the contract ceiling.
func TestWorkerValueEvidenceRequirementsV2IsTheOnlyV1RequirementSet(t *testing.T) {
	requirements := WorkerValueEvidenceRequirementsV2()
	if len(requirements) != 1 {
		t.Fatalf("requirements = %#v, want exactly one element", requirements)
	}
	if requirements[0] != (InferEvidenceRequirement{
		EvidenceKind:            nodewire.EvidenceKindWorkerValueOpening,
		CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2,
		MaxEncodedSizeBytes:     nodewire.MaxEvidenceEncodedSizeBytesV1,
	}) {
		t.Fatalf("requirement = %#v", requirements[0])
	}
	// The returned slice must not be shared: a caller that edits it must not
	// change what the next caller validates against.
	requirements[0].MaxEncodedSizeBytes = 1
	if WorkerValueEvidenceRequirementsV2()[0].MaxEncodedSizeBytes != nodewire.MaxEvidenceEncodedSizeBytesV1 {
		t.Fatal("WorkerValueEvidenceRequirementsV2 returns shared mutable state")
	}
}

func mustHex32(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(codec.Hash{}) {
		t.Fatalf("%q is not 32 hex-encoded bytes: %v", value, err)
	}
	return decoded
}
