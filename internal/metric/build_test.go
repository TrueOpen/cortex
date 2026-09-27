package metric

import (
	"github.com/TrueOpen/cortex/internal/codec"
)

// testVerifierValueRoot is fixed because the summary and proof tests do not
// depend on it.
var testVerifierValueRoot = codec.HashBytes([]byte("test verifier values"))

// OptionalFP is one optional fixed-point metric with explicit presence. Absent
// and "present, measured zero" are different facts and encode differently, so
// the zero value is absent rather than zero.
type OptionalFP struct {
	Value   float64
	Present bool
}

// PresentFP marks an optional metric as measured.
func PresentFP(value float64) OptionalFP { return OptionalFP{Value: value, Present: true} }

// Sample is a test fixture: one generated position's comparison in real
// units, converted to a SampleV3 by Build. It is deliberately pre-fixed-point: the
// conversion, its rounding mode and its overflow rule live in one place
// (fixedpoint.go) rather than at every producer.
//
// WorkerRank / VerifierRank are 1-based, and zero means "this side reported no
// rank at all" — the same convention the model service already uses.
type Sample struct {
	OutputPosition  uint32
	EmittedTokenID  uint32
	WorkerLogprob   float64
	VerifierLogprob float64
	WorkerRank      uint32
	VerifierRank    uint32
	TopKJaccard     OptionalFP
	UnionJS         OptionalFP
	// Missing says the verifier's recomputation had no entry for the token the
	// worker emitted at this position.
	Missing bool
	// Finite says both logprobs were finite and therefore comparable. A
	// non-finite pair is still a leaf: the position happened, and dropping it
	// would renumber every later output_position.
	Finite bool
}

// Build converts real-unit samples to V3 fixed-point samples and runs BuildV3,
// so the summary and proof tests keep their real-unit inputs.
func Build(binding Binding, samples []Sample) (Material, error) {
	v3, err := samplesToV3(samples)
	if err != nil {
		return Material{}, err
	}
	return BuildV3(binding, testVerifierValueRoot, v3)
}

func samplesToV3(samples []Sample) ([]SampleV3, error) {
	out := make([]SampleV3, len(samples))
	for i, s := range samples {
		out[i] = SampleV3{OutputPosition: s.OutputPosition, EmittedTokenID: s.EmittedTokenID, Missing: s.Missing, Finite: s.Finite}
		// A missing or non-finite V3 leaf carries zero values and absent ratios.
		if !s.Finite || s.Missing {
			out[i].Finite = false
			continue
		}
		out[i].WorkerRank, out[i].VerifierRank = s.WorkerRank, s.VerifierRank
		{
			var err error
			if out[i].WorkerLogprobFP1e6, err = signedFP1e6("worker logprob", s.WorkerLogprob); err != nil {
				return nil, err
			}
			if out[i].VerifierLogprobFP1e6, err = signedFP1e6("verifier logprob", s.VerifierLogprob); err != nil {
				return nil, err
			}
		}
		if s.TopKJaccard.Present {
			ratio, err := ratioFP1e6("topk_jaccard", s.TopKJaccard.Value)
			if err != nil {
				return nil, err
			}
			out[i].TopKJaccardFP1e6 = ratio
		}
		if s.UnionJS.Present {
			ratio, err := ratioFP1e6("union_js", s.UnionJS.Value)
			if err != nil {
				return nil, err
			}
			out[i].UnionJSFP1e6 = ratio
		}
	}
	return out, nil
}
