package metric

import (
	"github.com/TrueOpen/cortex/internal/codec"
)

// testVerifierValueRoot is fixed because the summary and proof tests do not
// depend on it.
var testVerifierValueRoot = codec.HashBytes([]byte("test verifier values"))

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
