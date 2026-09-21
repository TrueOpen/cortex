package modelservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// The classification is only worth anything if it survives the wrapping every
// caller does. worker.go wraps with "model generation evidence: %w", the task
// runner reads the class several frames later, and a class that only answered
// at the raising site would be read as unclassified there -- which is the
// default, which is "retry the model", which is the loop this exists to stop.
func TestFaultClassSurvivesWrapping(t *testing.T) {
	base := Deterministic(FaultCodeTokenBudgetExceeded, errors.New("boom"), FaultUint("max_output_tokens", 512))
	wrapped := fmt.Errorf("model generation evidence: %w", fmt.Errorf("infer: %w", base))

	if got := ClassOf(wrapped); got != FaultDeterministic {
		t.Fatalf("ClassOf through two wrappings = %v, want %v", got, FaultDeterministic)
	}
	if got := FaultCode(wrapped); got != FaultCodeTokenBudgetExceeded {
		t.Fatalf("FaultCode through two wrappings = %q, want %q", got, FaultCodeTokenBudgetExceeded)
	}
	if !IsDeterministic(wrapped) || IsRetryable(wrapped) || IsRegenerationForbidden(wrapped) {
		t.Fatalf("predicates disagree with the class for %v", wrapped)
	}
	fields := FaultFields(wrapped)
	if len(fields) != 1 || fields[0].Key != "max_output_tokens" || fields[0].Value != "512" {
		t.Fatalf("FaultFields = %#v, want the single measurement it was raised with", fields)
	}
}

// retryableError predates the classification and is produced on the HTTP and
// gRPC paths. It must read as transient rather than as unclassified, or a
// 503 from vLLM would stop a task the way a contract violation does.
func TestRetryableErrorReadsAsTransient(t *testing.T) {
	err := fmt.Errorf("post: %w", retryableError{err: errors.New("connection refused")})
	if got := ClassOf(err); got != FaultTransient {
		t.Fatalf("ClassOf = %v, want %v", got, FaultTransient)
	}
	if !IsRetryable(err) {
		t.Fatalf("IsRetryable(%v) = false", err)
	}
}

// An unmarked error keeps the previous behaviour. Nothing may infer "stop
// calling the model" from silence.
func TestUnmarkedErrorStaysUnclassified(t *testing.T) {
	err := errors.New("something went wrong")
	if got := ClassOf(err); got != FaultUnclassified {
		t.Fatalf("ClassOf = %v, want %v", got, FaultUnclassified)
	}
	if IsRetryable(err) || IsDeterministic(err) || IsRegenerationForbidden(err) {
		t.Fatalf("an unmarked error answered a class predicate")
	}
	if FaultSummary(err) != "" {
		t.Fatalf("FaultSummary of an unmarked error = %q, want empty", FaultSummary(err))
	}
}

// The failure that took down the devnet Worker: three different facts shared one
// sentence, so the operator log could not say which of them fired. Each now has
// its own code and carries the numbers that decided it.
func TestGenerationEvidenceSeparatesOverLimitFromCountMismatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*traceEnvelope)
		wantCode   string
		wantFields map[string]string
	}{
		{
			name: "generated more tokens than the order authorised",
			mutate: func(env *traceEnvelope) {
				env.OutTokens = append(env.OutTokens, tokenLogprob{TokenID: 7, Logprob: -0.5})
				env.GeneratedTokenCount = len(env.OutTokens)
				env.GeneratedTokenIDsHash = hashGeneratedTokenIDs(env.OutTokens)
			},
			wantCode: FaultCodeTokenBudgetExceeded,
			wantFields: map[string]string{
				"generated_token_count": "3",
				"max_output_tokens":     "2",
				"out_tokens":            "3",
			},
		},
		{
			name: "count disagrees with the per-token evidence beside it",
			mutate: func(env *traceEnvelope) {
				env.GeneratedTokenCount = 1
			},
			wantCode: FaultCodeTokenEvidenceCountMismatch,
			wantFields: map[string]string{
				"generated_token_count": "1",
				"out_tokens":            "2",
				"max_output_tokens":     "2",
			},
		},
		{
			name:       "negative count",
			mutate:     func(env *traceEnvelope) { env.GeneratedTokenCount = -1 },
			wantCode:   FaultCodeTokenCountNegative,
			wantFields: map[string]string{"generated_token_count": "-1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation, digest, env := generationEvidenceFixture(t)
			tc.mutate(&env)
			trace, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal trace: %v", err)
			}
			// The checkpoint is rebuilt from the mutated trace so that it agrees
			// with it: a stale checkpoint would fail its own check too, and the
			// subtest would no longer be measuring the token check it names.
			_, _, err = ValidateGenerationEvidence(generation, digest, []byte(env.Output), trace, checkpointFor(t, env))
			if err == nil {
				t.Fatalf("ValidateGenerationEvidence accepted the mutated evidence")
			}
			if got := FaultCode(err); got != tc.wantCode {
				t.Fatalf("FaultCode = %q, want %q (error: %v)", got, tc.wantCode, err)
			}
			if !IsDeterministic(err) {
				t.Fatalf("class = %v, want deterministic: re-running the model cannot change a verdict about bytes already held", ClassOf(err))
			}
			fields := map[string]string{}
			for _, field := range FaultFields(err) {
				fields[field.Key] = field.Value
			}
			for key, want := range tc.wantFields {
				if fields[key] != want {
					t.Fatalf("field %s = %q, want %q; all fields: %#v", key, fields[key], want, fields)
				}
			}
		})
	}
}

// The refusal text reaches the operator log and a durable halt reason. Nothing
// the user or the model wrote may travel with it.
func TestGenerationEvidenceRefusalCarriesNoModelText(t *testing.T) {
	const secret = "PROMPT-CONTENT-THAT-MUST-NOT-LEAK"
	generation, digest, env := generationEvidenceFixture(t)
	env.Output = secret
	env.GeneratedTokenCount = 1
	trace, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	_, _, err = ValidateGenerationEvidence(generation, digest, []byte(secret), trace, checkpointFor(t, env))
	if err == nil {
		t.Fatalf("ValidateGenerationEvidence accepted the mutated evidence")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the refusal quoted model output: %v", err)
	}
	for _, field := range FaultFields(err) {
		if strings.Contains(field.Value, secret) {
			t.Fatalf("fault field %s quoted model output", field.Key)
		}
	}
}

// generationEvidenceFixture builds a generation context and a trace envelope
// that validate against each other, so each subtest can break exactly one thing.
func generationEvidenceFixture(t *testing.T) (*nodewire.GenerationContext, []byte, traceEnvelope) {
	t.Helper()
	generation := &nodewire.GenerationContext{
		ModelID: "trueopen-model-1", ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: nodewire.GenerationParamsV1{
			SchemaVersion: 1, MaxOutputTokens: 2, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, TopK: 40, Seed: 8675309,
				RepetitionPenaltyPPM: 1050000,
			},
		},
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatalf("generation digest: %v", err)
	}
	outTokens := []tokenLogprob{{TokenID: 11, Logprob: -0.1}, {TokenID: 12, Logprob: -0.2}}
	env := traceEnvelope{
		Generation:            generation,
		ModelID:               generation.ModelID,
		ProfileVersion:        strconv.FormatUint(uint64(generation.ProfileVersion), 10),
		Output:                "hi",
		InputTokenIDs:         []int{1, 2, 3},
		InputTokenIDsHash:     hashTokenIDs([]int{1, 2, 3}),
		GeneratedTokenIDsHash: hashGeneratedTokenIDs(outTokens),
		GeneratedTokenCount:   len(outTokens),
		FinishReason:          "length",
		OutTokens:             outTokens,
	}
	// Sanity: the unmutated fixture must pass, or a subtest could be measuring
	// the fixture rather than its own mutation.
	trace, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	if _, _, err := ValidateGenerationEvidence(generation, digest[:], []byte(env.Output), trace, checkpointFor(t, env)); err != nil {
		t.Fatalf("the unmutated fixture does not validate: %v", err)
	}
	return generation, digest[:], env
}

// checkpointFor is the trace envelope without its per-token evidence, which is
// exactly what buildInferResultFromCompletion writes beside the trace.
func checkpointFor(t *testing.T, env traceEnvelope) []byte {
	t.Helper()
	checkpoint := env
	checkpoint.OutTokens = nil
	data, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	return data
}
