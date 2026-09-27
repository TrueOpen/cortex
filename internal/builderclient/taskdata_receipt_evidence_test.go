package builderclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

func completeWorkerEvidenceFacts() WorkerEvidenceFacts {
	return WorkerEvidenceFacts{
		ChainID:                      "trueopen-task-1",
		TaskID:                       strings.Repeat("11", 32),
		AcceptedTaskHash:             strings.Repeat("22", 32),
		WorkerOperatorAddress:        "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		GenerationParamsDigest:       strings.Repeat("33", 32),
		EvidenceSchemaHash:           strings.Repeat("44", 32),
		OutputHash:                   codec.HashBytes([]byte("output")),
		OutputSizeBytes:              1536,
		OutputLeafCount:              1,
		GeneratedTokenCount:          3,
		InputTokenIDsHash:            codec.HashBytes([]byte("input tokens")),
		GeneratedTokenIDsHash:        codec.HashBytes([]byte("generated tokens")),
		InputTokenIDsSizeBytes:       8,
		GeneratedTokenIDsSizeBytes:   16,
		FinishReason:                 nodewire.FinishReasonV1EosToken,
		WorkerValueRoot:              codec.HashBytes([]byte("worker values")),
		WorkerValuesEncodedSizeBytes: 4096,
	}
}

// Both commitments come back in receipt order and satisfy the V3 requirement
// shape, with each size the derivation's own.
func TestWorkerEvidenceCommitmentsSatisfyTheV3Shape(t *testing.T) {
	facts := completeWorkerEvidenceFacts()
	commitments, err := WorkerEvidenceCommitments(facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(commitments) != 2 || commitments[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening ||
		commitments[1].EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening {
		t.Fatalf("commitments = %+v, want [value, token]", commitments)
	}
	if commitments[0].EncodedSizeBytes != facts.WorkerValuesEncodedSizeBytes {
		t.Fatalf("value encoded_size_bytes = %d, want %d", commitments[0].EncodedSizeBytes, facts.WorkerValuesEncodedSizeBytes)
	}
	if commitments[1].EncodedSizeBytes != facts.InputTokenIDsSizeBytes+facts.GeneratedTokenIDsSizeBytes {
		t.Fatalf("token encoded_size_bytes = %d, want the token-id sum", commitments[1].EncodedSizeBytes)
	}
	if commitments[0].EvidenceHashOrRoot == facts.WorkerValueRoot {
		t.Fatal("the value commitment is the bare worker_value_root, not its typed digest")
	}
	if err := ValidateProfileEvidenceCommitments(WorkerEvidenceRequirementsV3(), commitments); err != nil {
		t.Fatalf("ValidateProfileEvidenceCommitments: %v", err)
	}
}

// Every input moves exactly the commitment it belongs to: value inputs move the
// value commitment only, token inputs the token commitment only, and the shared
// scope moves both.
func TestWorkerEvidenceCommitmentsBindEveryInput(t *testing.T) {
	base, err := WorkerEvidenceCommitments(completeWorkerEvidenceFacts())
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("55", 32)
	for name, tc := range map[string]struct {
		mutate       func(*WorkerEvidenceFacts)
		value, token bool
	}{
		"chain_id":             {func(f *WorkerEvidenceFacts) { f.ChainID += "-x" }, true, true},
		"task_id":              {func(f *WorkerEvidenceFacts) { f.TaskID = other }, true, true},
		"accepted_task_hash":   {func(f *WorkerEvidenceFacts) { f.AcceptedTaskHash = other }, true, true},
		"evidence_schema_hash": {func(f *WorkerEvidenceFacts) { f.EvidenceSchemaHash = other }, true, true},
		"worker_operator_address": {func(f *WorkerEvidenceFacts) {
			f.WorkerOperatorAddress = "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k"
		}, true, true},
		"worker_value_root":          {func(f *WorkerEvidenceFacts) { f.WorkerValueRoot = codec.HashBytes([]byte("other")) }, true, false},
		"worker_values_size":         {func(f *WorkerEvidenceFacts) { f.WorkerValuesEncodedSizeBytes++ }, true, false},
		"generation_params_digest":   {func(f *WorkerEvidenceFacts) { f.GenerationParamsDigest = other }, false, true},
		"output_hash":                {func(f *WorkerEvidenceFacts) { f.OutputHash = codec.HashBytes([]byte("other")) }, false, true},
		"output_size_bytes":          {func(f *WorkerEvidenceFacts) { f.OutputSizeBytes++ }, false, true},
		"output_leaf_count":          {func(f *WorkerEvidenceFacts) { f.OutputLeafCount++ }, false, true},
		"finish_reason":              {func(f *WorkerEvidenceFacts) { f.FinishReason = nodewire.FinishReasonV1StopToken }, false, true},
		"generated tokens":           {func(f *WorkerEvidenceFacts) { f.GeneratedTokenCount++; f.GeneratedTokenIDsSizeBytes += 4 }, false, true},
		"input_token_ids_hash":       {func(f *WorkerEvidenceFacts) { f.InputTokenIDsHash = codec.HashBytes([]byte("other")) }, false, true},
		"generated_token_ids_hash":   {func(f *WorkerEvidenceFacts) { f.GeneratedTokenIDsHash = codec.HashBytes([]byte("other")) }, false, true},
		"input_token_ids_size_bytes": {func(f *WorkerEvidenceFacts) { f.InputTokenIDsSizeBytes += 4 }, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			facts := completeWorkerEvidenceFacts()
			tc.mutate(&facts)
			got, err := WorkerEvidenceCommitments(facts)
			if err != nil {
				t.Fatal(err)
			}
			if moved := got[0] != base[0]; moved != tc.value {
				t.Fatalf("value commitment moved = %v, want %v", moved, tc.value)
			}
			if moved := got[1] != base[1]; moved != tc.token {
				t.Fatalf("token commitment moved = %v, want %v", moved, tc.token)
			}
		})
	}
}

func TestWorkerEvidenceCommitmentsRefuseUnusableInputs(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate      func(*WorkerEvidenceFacts)
		unavailable bool
	}{
		"missing accepted_task_hash":    {func(f *WorkerEvidenceFacts) { f.AcceptedTaskHash = "" }, true},
		"zero evidence_schema_hash":     {func(f *WorkerEvidenceFacts) { f.EvidenceSchemaHash = strings.Repeat("00", 32) }, true},
		"missing generation digest":     {func(f *WorkerEvidenceFacts) { f.GenerationParamsDigest = "" }, true},
		"unspecified finish_reason":     {func(f *WorkerEvidenceFacts) { f.FinishReason = nodewire.FinishReasonV1Unspecified }, true},
		"uppercase task_id":             {func(f *WorkerEvidenceFacts) { f.TaskID = strings.ToUpper(strings.Repeat("ab", 32)) }, false},
		"zero worker_value_root":        {func(f *WorkerEvidenceFacts) { f.WorkerValueRoot = codec.Hash{} }, false},
		"zero generated_token_ids_hash": {func(f *WorkerEvidenceFacts) { f.GeneratedTokenIDsHash = codec.Hash{} }, false},
		"empty output with two leaves":  {func(f *WorkerEvidenceFacts) { f.OutputSizeBytes, f.OutputLeafCount = 0, 2 }, false},
	} {
		t.Run(name, func(t *testing.T) {
			facts := completeWorkerEvidenceFacts()
			tc.mutate(&facts)
			_, err := WorkerEvidenceCommitments(facts)
			if err == nil {
				t.Fatal("WorkerEvidenceCommitments() error = nil")
			}
			if got := errors.Is(err, ErrInferReceiptInputUnavailable); got != tc.unavailable {
				t.Fatalf("errors.Is(ErrInferReceiptInputUnavailable) = %v, want %v: %v", got, tc.unavailable, err)
			}
		})
	}
}

// A Verifier recovers finish_reason by search, and confirms both bundles against
// the receipt; a tampered artifact or a swapped commitment is final.
func TestConfirmWorkerEvidenceRecoversFinishReasonAndRefusesTampering(t *testing.T) {
	for _, reason := range nodewire.SuccessfulFinishReasonsV1() {
		facts := completeWorkerEvidenceFacts()
		facts.FinishReason = reason
		committed, err := WorkerEvidenceCommitments(facts)
		if err != nil {
			t.Fatal(err)
		}
		facts.FinishReason = nodewire.FinishReasonV1Unspecified
		got, err := ConfirmWorkerEvidence(facts, committed)
		if err != nil || got != reason {
			t.Fatalf("ConfirmWorkerEvidence = %d, %v; want %d", got, err, reason)
		}
	}
	facts := completeWorkerEvidenceFacts()
	committed, err := WorkerEvidenceCommitments(facts)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*WorkerEvidenceFacts, []EvidenceCommitment) []EvidenceCommitment{
		"tampered worker_values": func(f *WorkerEvidenceFacts, c []EvidenceCommitment) []EvidenceCommitment {
			f.WorkerValueRoot = codec.HashBytes([]byte("tampered"))
			return c
		},
		"tampered generated token ids": func(f *WorkerEvidenceFacts, c []EvidenceCommitment) []EvidenceCommitment {
			f.GeneratedTokenIDsHash = codec.HashBytes([]byte("tampered"))
			return c
		},
		"swapped commitments": func(_ *WorkerEvidenceFacts, c []EvidenceCommitment) []EvidenceCommitment {
			return []EvidenceCommitment{c[1], c[0]}
		},
		"committed size differs": func(_ *WorkerEvidenceFacts, c []EvidenceCommitment) []EvidenceCommitment {
			out := append([]EvidenceCommitment(nil), c...)
			out[0].EncodedSizeBytes++
			return out
		},
		"one commitment": func(_ *WorkerEvidenceFacts, c []EvidenceCommitment) []EvidenceCommitment { return c[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			if _, err := ConfirmWorkerEvidence(f, mutate(&f, committed)); err == nil {
				t.Fatal("ConfirmWorkerEvidence() error = nil")
			}
		})
	}
}

func TestWorkerEvidenceRequirementsV3IsTheOnlyRequirementSet(t *testing.T) {
	requirements := WorkerEvidenceRequirementsV3()
	if len(requirements) != 2 ||
		requirements[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening || requirements[0].CommitmentSchemaVersion != nodewire.WorkerValueCommitmentSchemaVersionV3 ||
		requirements[1].EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening || requirements[1].CommitmentSchemaVersion != nodewire.WorkerTokenCommitmentSchemaVersionV1 {
		t.Fatalf("requirements = %+v", requirements)
	}
	commitments, err := WorkerEvidenceCommitments(completeWorkerEvidenceFacts())
	if err != nil {
		t.Fatal(err)
	}
	legacy := append([]InferEvidenceRequirement(nil), requirements...)
	legacy[0].CommitmentSchemaVersion = 2
	if err := ValidateProfileEvidenceCommitments(legacy, commitments); err == nil {
		t.Fatal("a schema-2 value requirement was accepted")
	}
}
