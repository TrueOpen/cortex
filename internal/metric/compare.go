package metric

import (
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
//
// It normalizes by log-sum-exp: every logprob is shifted by this side's
// maximum before exp, so a list of legal but very small logprobs (vLLM clamps
// at -9999) does not underflow to an all-zero, unnormalizable distribution.
func normalizedProbabilities(topK []TokenLogprob, union []uint32) ([]float64, bool) {
	logprobs := make(map[uint32]float64, len(topK))
	maxLogprob := math.Inf(-1)
	for _, entry := range topK {
		logprobs[entry.TokenID] = entry.Logprob
		if isFinite(entry.Logprob) && entry.Logprob > maxLogprob {
			maxLogprob = entry.Logprob
		}
	}
	if math.IsInf(maxLogprob, -1) {
		return nil, false
	}
	out := make([]float64, len(union))
	total := 0.0
	for i, token := range union {
		if logprob, ok := logprobs[token]; ok && isFinite(logprob) {
			out[i] = math.Exp(logprob - maxLogprob)
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
