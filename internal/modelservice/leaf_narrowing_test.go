package modelservice

import (
	"math"
	"strings"
	"testing"
)

// A token id or rank that does not fit the metric leaf's uint32 field is a
// transport fault, and it must stop the verify rather than be clamped.
//
// Clamping to zero was the previous behaviour and it is unrecoverable: token id
// 0 is a legal token and rank 0 is the wire's "no rank reported" spelling, so
// the clamped leaf looks entirely ordinary. It gets hashed into metric_root,
// signed, committed to and put on chain, and the corruption only surfaces at a
// VERIFIER_VALUE_OPENING that can never be satisfied - because the true value
// was destroyed here and nothing else recorded it.
func TestOutOfRangeTokenIDOrRankIsRefusedNotClamped(t *testing.T) {
	for name, trace := range map[string][]tokenLogprob{
		"negative token id":  {{TokenID: -1, Logprob: -0.1, Rank: 1}},
		"oversized token id": {{TokenID: math.MaxUint32 + 1, Logprob: -0.1, Rank: 1}},
		"negative rank":      {{TokenID: 10, Logprob: -0.1, Rank: -3}},
	} {
		t.Run(name, func(t *testing.T) {
			recomputed := []map[string]logprobEntry{{"10": {Logprob: -0.11, Rank: 1}}}
			_, _, err := computeSingleSampleMetrics(trace, 0, recomputed, 2, missingLogprob)
			if err == nil {
				t.Fatalf("%s was accepted; it would have been clamped into a plausible-looking leaf", name)
			}
			if !strings.Contains(err.Error(), "clamping") {
				t.Fatalf("error does not explain why it refuses instead of clamping: %v", err)
			}
		})
	}
}

// Token id 0 is a legal token and must still verify. This is the other half of
// the rule: refusing the impossible values must not also refuse a real one.
func TestTokenIDZeroIsAcceptedAsARealToken(t *testing.T) {
	trace := []tokenLogprob{{TokenID: 0, Logprob: -0.1, Rank: 1}}
	recomputed := []map[string]logprobEntry{{"0": {Logprob: -0.11, Rank: 1}}}

	_, samples, err := computeSingleSampleMetrics(trace, 0, recomputed, 2, missingLogprob)
	if err != nil {
		t.Fatalf("token id 0 was refused: %v", err)
	}
	if len(samples) != 1 || samples[0].EmittedTokenID != 0 || samples[0].Missing {
		t.Fatalf("sample = %#v, want token id 0 compared normally", samples)
	}
}
