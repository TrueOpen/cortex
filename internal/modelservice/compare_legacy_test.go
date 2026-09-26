package modelservice

import (
	"math"
	"sort"

	"github.com/TrueOpen/cortex/internal/metric"
)

// The pre-refactor comparison, kept verbatim (renamed with a legacy prefix) as
// the reference computeSingleSampleMetrics must keep matching. Delete it once
// the model service stops producing traces.

func legacyComputeSingleSampleMetrics(
	trace []tokenLogprob, inputLen int, recomputed []map[string]logprobEntry, comparedTopK int, missingLogprob float64,
) (singleSampleMetrics, []metric.Sample, error) {
	samples := make([]metric.Sample, 0, len(trace))

	for i, worker := range trace {
		entry, selectedPresent := recomputedEntryFor(worker.TokenID, inputLen+i, recomputed)
		position, err := leafUint32("output_position", i)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		tokenID, err := leafUint32("emitted_token_id", worker.TokenID)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		workerRank, err := leafUint32("worker_rank", worker.Rank)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		sample := metric.Sample{
			OutputPosition:  position,
			EmittedTokenID:  tokenID,
			WorkerLogprob:   worker.Logprob,
			VerifierLogprob: missingLogprob,
			WorkerRank:      workerRank,
			Missing:         !selectedPresent,
		}
		if selectedPresent {
			verifierRank, err := leafUint32("verifier_rank", entry.Rank)
			if err != nil {
				return singleSampleMetrics{}, nil, err
			}
			sample.VerifierLogprob = entry.Logprob
			sample.VerifierRank = verifierRank
			sample.Finite = finite(worker.Logprob) && finite(entry.Logprob)
		}
		workerTopK := legacyLimitTopLogprobs(worker.TopLogprobs, comparedTopK)
		verifierTopK := legacyLimitTopLogprobs(legacyPromptTopLogprobsAt(recomputed, inputLen+i), comparedTopK)
		if len(workerTopK) > 0 && len(verifierTopK) > 0 {
			sample.TopKJaccard = metric.PresentFP(legacyTopKJaccard(workerTopK, verifierTopK))
			if js, ok := legacyUnionJSDivergence(workerTopK, verifierTopK); ok {
				sample.UnionJS = metric.PresentFP(js)
			}
		}
		samples = append(samples, sample)
	}

	// The local verdict classifies from the SAME aggregation the submitted
	// summary is narrowed from. There is one aggregator (metric.AggregateFromSamples)
	// and this is a projection of it - a second pass here is exactly how the
	// number an operator reads and the number the Keeper judges start to differ.
	return localMetricsFromAggregates(metric.AggregateFromSamples(samples, uint32(comparedTopK))), samples, nil
}

func legacyLimitTopLogprobs(in map[string]float64, limit int) map[string]float64 {
	in = normalizeTopLogprobs(in)
	if len(in) == 0 || limit <= 0 || len(in) <= limit {
		return in
	}
	type tokenScore struct {
		token   string
		logprob float64
	}
	scores := make([]tokenScore, 0, len(in))
	for token, logprob := range in {
		scores = append(scores, tokenScore{token: normalizeTokenKey(token), logprob: logprob})
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].logprob == scores[j].logprob {
			return scores[i].token < scores[j].token
		}
		return scores[i].logprob > scores[j].logprob
	})
	out := make(map[string]float64, limit)
	for i := 0; i < limit && i < len(scores); i++ {
		out[scores[i].token] = scores[i].logprob
	}
	return out
}

func legacyPromptTopLogprobsAt(rows []map[string]logprobEntry, position int) map[string]float64 {
	if position < 0 || position >= len(rows) {
		return nil
	}
	out := make(map[string]float64, len(rows[position]))
	for key, entry := range rows[position] {
		if !finite(entry.Logprob) {
			continue
		}
		out[normalizeTokenKey(key)] = entry.Logprob
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func legacyTopKJaccard(a, b map[string]float64) float64 {
	a = normalizeTopLogprobs(a)
	b = normalizeTopLogprobs(b)
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	union := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		union[normalizeTokenKey(key)] = struct{}{}
	}
	for key := range b {
		union[normalizeTokenKey(key)] = struct{}{}
	}
	if len(union) == 0 {
		return 1
	}
	intersection := 0
	for key := range union {
		_, inA := a[key]
		_, inB := b[key]
		if inA && inB {
			intersection++
		}
	}
	return float64(intersection) / float64(len(union))
}

func legacyUnionJSDivergence(a, b map[string]float64) (float64, bool) {
	a = normalizeTopLogprobs(a)
	b = normalizeTopLogprobs(b)
	keys := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		keys[normalizeTokenKey(key)] = struct{}{}
	}
	for key := range b {
		keys[normalizeTokenKey(key)] = struct{}{}
	}
	if len(keys) == 0 {
		return 0, false
	}
	aProb, aOK := legacyNormalizedProbabilities(a, keys)
	bProb, bOK := legacyNormalizedProbabilities(b, keys)
	if !aOK || !bOK {
		return 0, false
	}
	js := 0.0
	for key := range keys {
		p := aProb[key]
		q := bProb[key]
		m := 0.5 * (p + q)
		if p > 0 {
			js += 0.5 * p * math.Log(p/m)
		}
		if q > 0 {
			js += 0.5 * q * math.Log(q/m)
		}
	}
	return js, finite(js)
}

func legacyNormalizedProbabilities(logprobs map[string]float64, keys map[string]struct{}) (map[string]float64, bool) {
	out := make(map[string]float64, len(keys))
	total := 0.0
	for key := range keys {
		if logprob, ok := logprobs[key]; ok && finite(logprob) {
			p := math.Exp(logprob)
			out[key] = p
			total += p
		}
	}
	if total <= 0 || !finite(total) {
		return nil, false
	}
	for key, value := range out {
		out[key] = value / total
	}
	return out, true
}
