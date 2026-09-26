package metric

import (
	"fmt"
	"math"
)

// TokenLogprob is one entry of a position's top-k list, in real units.
type TokenLogprob struct {
	TokenID uint32
	Logprob float64
}

// PositionValue is one side's value at one generated token position, in real
// units. It is the shape a model service reports and the input CompareSamples
// compares; fixed point happens later, once, when a leaf is framed.
//
// TopK is an ordered list, not a set: entry i is the token the engine ranked
// i+1. CompareSamples keeps that order and never re-sorts by logprob, so equal
// logprobs keep the engine's order.
type PositionValue struct {
	// TokenID is the token this value was measured for. On the verifier side it
	// is the Worker's emitted token, which teacher-forcing scored.
	TokenID uint32
	Logprob float64
	Rank    uint32 // 0 = not reported
	TopK    []TokenLogprob
	// Missing says this side has no value for TokenID at this position. Its
	// Logprob and Rank are then ignored; its TopK, if any, still takes part in
	// the top-k comparison.
	Missing bool
}

// CompareSamples compares the Worker's and the Verifier's values position by
// position and returns one Sample per generated token, in position order. The
// samples are what metric leaves and AggregateFromSamples are derived from, so
// this is the only place the two sides are compared.
//
// A missing side takes missingLogprob as its logprob and 0 as its rank: the
// position still becomes a leaf, flagged, because dropping it would renumber
// every later output_position. Only the Verifier side goes missing today; a
// missing Worker value is accepted with the same rule.
//
// Each side's top-k is filtered to finite logprobs and truncated to its first
// comparedTopK entries (comparedTopK <= 0 keeps them all). Top-k Jaccard and
// union JS divergence are present only when both truncated lists are non-empty.
func CompareSamples(worker, verifier []PositionValue, comparedTopK int, missingLogprob float64) ([]Sample, error) {
	if len(worker) != len(verifier) {
		return nil, fmt.Errorf("metric compare: %d worker values but %d verifier values", len(worker), len(verifier))
	}
	samples := make([]Sample, 0, len(worker))
	for i := range worker {
		position, err := countUint32("output_position", i)
		if err != nil {
			return nil, err
		}
		w, v := worker[i], verifier[i]
		if !v.Missing && v.TokenID != w.TokenID {
			return nil, fmt.Errorf("metric compare: position %d verifier scored token %d, worker emitted %d", i, v.TokenID, w.TokenID)
		}
		sample := Sample{
			OutputPosition:  position,
			EmittedTokenID:  w.TokenID,
			WorkerLogprob:   w.Logprob,
			VerifierLogprob: v.Logprob,
			WorkerRank:      w.Rank,
			VerifierRank:    v.Rank,
			Missing:         w.Missing || v.Missing,
		}
		if w.Missing {
			sample.WorkerLogprob, sample.WorkerRank = missingLogprob, 0
		}
		if v.Missing {
			sample.VerifierLogprob, sample.VerifierRank = missingLogprob, 0
		}
		sample.Finite = !sample.Missing && isFinite(sample.WorkerLogprob) && isFinite(sample.VerifierLogprob)

		workerTopK, err := comparableTopK("worker", i, w.TopK, comparedTopK)
		if err != nil {
			return nil, err
		}
		verifierTopK, err := comparableTopK("verifier", i, v.TopK, comparedTopK)
		if err != nil {
			return nil, err
		}
		if len(workerTopK) > 0 && len(verifierTopK) > 0 {
			sample.TopKJaccard = PresentFP(TopKJaccard(workerTopK, verifierTopK))
			if js, ok := UnionJSDivergence(workerTopK, verifierTopK); ok {
				sample.UnionJS = PresentFP(js)
			}
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

// comparableTopK drops non-finite entries, then keeps the first limit entries
// in the given order. A repeated token is refused: the list is one entry per
// distinct token, and a repeat would count twice in both metrics.
func comparableTopK(side string, position int, topK []TokenLogprob, limit int) ([]TokenLogprob, error) {
	out := make([]TokenLogprob, 0, len(topK))
	seen := make(map[uint32]struct{}, len(topK))
	for _, entry := range topK {
		if _, dup := seen[entry.TokenID]; dup {
			return nil, fmt.Errorf("metric compare: position %d %s top-k repeats token %d", position, side, entry.TokenID)
		}
		seen[entry.TokenID] = struct{}{}
		if isFinite(entry.Logprob) {
			out = append(out, entry)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// TopKJaccard is |A ∩ B| / |A ∪ B| over the two token sets. Two empty lists
// agree completely.
func TopKJaccard(a, b []TokenLogprob) float64 {
	union := unionTokens(a, b)
	if len(union) == 0 {
		return 1
	}
	inA := tokenSet(a)
	inB := tokenSet(b)
	intersection := 0
	for _, token := range union {
		_, okA := inA[token]
		_, okB := inB[token]
		if okA && okB {
			intersection++
		}
	}
	return float64(intersection) / float64(len(union))
}

// UnionJSDivergence is the Jensen-Shannon divergence (natural log) between the
// two top-k lists, each renormalised over the union of their tokens; a token a
// side did not list has probability zero on that side. It reports false when
// either side has no probability mass to normalise.
//
// Every sum runs in union order - a's tokens, then b's tokens not in a - so the
// result is the same bits on every run for the same input.
func UnionJSDivergence(a, b []TokenLogprob) (float64, bool) {
	union := unionTokens(a, b)
	if len(union) == 0 {
		return 0, false
	}
	p, okP := normalizedProbabilities(a, union)
	q, okQ := normalizedProbabilities(b, union)
	if !okP || !okQ {
		return 0, false
	}
	js := 0.0
	for i := range union {
		m := 0.5 * (p[i] + q[i])
		if p[i] > 0 {
			js += 0.5 * p[i] * math.Log(p[i]/m)
		}
		if q[i] > 0 {
			js += 0.5 * q[i] * math.Log(q[i]/m)
		}
	}
	return js, isFinite(js)
}

// normalizedProbabilities returns one probability per union token, in union
// order, summing to one over the tokens this side listed with a finite logprob.
func normalizedProbabilities(topK []TokenLogprob, union []uint32) ([]float64, bool) {
	logprobs := make(map[uint32]float64, len(topK))
	for _, entry := range topK {
		logprobs[entry.TokenID] = entry.Logprob
	}
	out := make([]float64, len(union))
	total := 0.0
	for i, token := range union {
		if logprob, ok := logprobs[token]; ok && isFinite(logprob) {
			out[i] = math.Exp(logprob)
			total += out[i]
		}
	}
	if total <= 0 || !isFinite(total) {
		return nil, false
	}
	for i := range out {
		out[i] /= total
	}
	return out, true
}

func unionTokens(a, b []TokenLogprob) []uint32 {
	union := make([]uint32, 0, len(a)+len(b))
	seen := make(map[uint32]struct{}, len(a)+len(b))
	for _, list := range [][]TokenLogprob{a, b} {
		for _, entry := range list {
			if _, ok := seen[entry.TokenID]; !ok {
				seen[entry.TokenID] = struct{}{}
				union = append(union, entry.TokenID)
			}
		}
	}
	return union
}

func tokenSet(list []TokenLogprob) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(list))
	for _, entry := range list {
		set[entry.TokenID] = struct{}{}
	}
	return set
}

func isFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
