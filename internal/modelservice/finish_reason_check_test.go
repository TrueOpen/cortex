package modelservice

import (
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// The local finish-reason checks, for every reason.
func TestValidateFinishReasonAppliesTheLocalChecks(t *testing.T) {
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.MaxOutputTokens = 3
	g.Params.DecodingParams.StopTokenIDs = []uint32{2, 9}
	for _, tc := range []struct {
		name      string
		reason    nodewire.FinishReasonV1
		generated []uint32
		ok        bool
	}{
		{"eos", nodewire.FinishReasonV1EosToken, []uint32{5}, true},
		{"eos without a token", nodewire.FinishReasonV1EosToken, nil, false},
		{"stop sequence", nodewire.FinishReasonV1StopSequence, []uint32{5, 6}, true},
		{"stop sequence without a token", nodewire.FinishReasonV1StopSequence, nil, false},
		{"max tokens at the limit", nodewire.FinishReasonV1MaxOutputTokens, []uint32{5, 6, 7}, true},
		{"max tokens below the limit", nodewire.FinishReasonV1MaxOutputTokens, []uint32{5, 6}, false},
		{"duration below the limit", nodewire.FinishReasonV1MaxOutputDuration, []uint32{5}, true},
		{"duration with no token", nodewire.FinishReasonV1MaxOutputDuration, nil, true},
		{"duration at the limit", nodewire.FinishReasonV1MaxOutputDuration, []uint32{5, 6, 7}, false},
		{"stop token last", nodewire.FinishReasonV1StopToken, []uint32{5, 9}, true},
		{"stop token not last", nodewire.FinishReasonV1StopToken, []uint32{9, 5}, false},
		{"stop token without a token", nodewire.FinishReasonV1StopToken, nil, false},
		{"user stop with no token", nodewire.FinishReasonV1UserStop, nil, true},
		{"unspecified", nodewire.FinishReasonV1Unspecified, []uint32{5}, false},
	} {
		err := ValidateFinishReason(g, tc.generated, tc.reason)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err = %v, want ok=%t", tc.name, err, tc.ok)
		}
		if err != nil && !IsDeterministic(err) {
			t.Fatalf("%s: refusal is not deterministic: %v", tc.name, err)
		}
	}
}
