package modelservice

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/metric"
)

// tokenIDFromKey reads a top-logprobs key as a vocabulary id. Every request
// this service sends sets return_tokens_as_token_ids, so vLLM spells keys
// "token_id:<n>"; a bare decimal is accepted as the same id. A text key is
// refused: a string cannot enter a value leaf, and guessing an id for it would
// commit a value for a token the engine never named.
func tokenIDFromKey(key string) (uint32, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(key), "token_id:")
	id, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil || strconv.FormatUint(id, 10) != trimmed {
		return 0, fmt.Errorf("top-logprobs key %q is not a vocabulary id; return_tokens_as_token_ids is required", key)
	}
	return uint32(id), nil
}

// completionTopK orders one /v1/completions top_logprobs dictionary into rank
// order. The completions API reports the dictionary without ranks, and JSON
// object order does not survive decoding, so rank order is reconstructed as
// logprob descending with ties broken by token id ascending. A sampled token
// the engine appended outside its top-k has the lowest logprob and lands last.
func completionTopK(position int, row map[string]float64) ([]metric.TokenLogprob, error) {
	out := make([]metric.TokenLogprob, 0, len(row))
	seen := make(map[uint32]struct{}, len(row))
	for key, logprob := range row {
		id, err := tokenIDFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("position %d: %w", position, err)
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("position %d: top-logprobs repeat token %d", position, id)
		}
		seen[id] = struct{}{}
		out = append(out, metric.TokenLogprob{TokenID: id, Logprob: logprob})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Logprob, out[j].Logprob
		if a == b || math.IsNaN(a) && math.IsNaN(b) {
			return out[i].TokenID < out[j].TokenID
		}
		// NaN sorts last, so a non-finite entry never displaces a real one.
		if math.IsNaN(a) || math.IsNaN(b) {
			return !math.IsNaN(a)
		}
		return a > b
	})
	return out, nil
}

// promptTopK orders one prompt_logprobs row by the rank vLLM reported for each
// entry, which is the engine's own order.
func promptTopK(position int, row map[string]logprobEntry) ([]metric.TokenLogprob, map[uint32]logprobEntry, error) {
	type ranked struct {
		id    uint32
		entry logprobEntry
	}
	entries := make([]ranked, 0, len(row))
	byID := make(map[uint32]logprobEntry, len(row))
	for key, entry := range row {
		id, err := tokenIDFromKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("prompt position %d: %w", position, err)
		}
		if _, dup := byID[id]; dup {
			return nil, nil, fmt.Errorf("prompt position %d: prompt_logprobs repeat token %d", position, id)
		}
		byID[id] = entry
		entries = append(entries, ranked{id: id, entry: entry})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].entry.Rank == entries[j].entry.Rank {
			return entries[i].id < entries[j].id
		}
		return entries[i].entry.Rank < entries[j].entry.Rank
	})
	out := make([]metric.TokenLogprob, len(entries))
	for i, e := range entries {
		out[i] = metric.TokenLogprob{TokenID: e.id, Logprob: e.entry.Logprob}
	}
	return out, byID, nil
}

// rankIn is the 1-based position of tokenID in a rank-ordered top-k, or 0 when
// the list does not contain it.
func rankIn(tokenID uint32, topK []metric.TokenLogprob) uint32 {
	for i, entry := range topK {
		if entry.TokenID == tokenID {
			return uint32(i + 1)
		}
	}
	return 0
}

func tokenIDsUint32(name string, ids []int) ([]uint32, error) {
	out := make([]uint32, len(ids))
	for i, id := range ids {
		if id < 0 || int64(id) > math.MaxUint32 {
			return nil, fmt.Errorf("%s[%d] = %d is not a vocabulary id", name, i, id)
		}
		out[i] = uint32(id)
	}
	return out, nil
}
