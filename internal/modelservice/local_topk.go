package modelservice

import (
	"bytes"
	"encoding/json"
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

// TopLogprob is one entry of a generated position's top_logprobs.
type TopLogprob struct {
	Token   string
	Logprob float64
}

// TopLogprobRow is one generated position's top_logprobs in the order the
// engine wrote them. That order is NOT rank order: vLLM writes the sampled token
// first (chat as the leading list element, /v1/completions as the first object
// key), so completionTopK sorts the row by logprob before it becomes evidence.
// The row is decoded preserving the engine's order -- never through a Go map,
// which would drop it -- so the sort has a stable, well-defined input.
type TopLogprobRow []TopLogprob

func (r *TopLogprobRow) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		*r = nil
		return nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("top_logprobs row must be a JSON object, got %v", tok)
	}
	row := TopLogprobRow{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		var logprob float64
		if err := dec.Decode(&logprob); err != nil {
			return fmt.Errorf("top_logprobs %q: %w", key, err)
		}
		row = append(row, TopLogprob{Token: key, Logprob: logprob})
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	*r = row
	return nil
}

// MarshalJSON writes the row as a JSON object in row order, the shape vLLM's
// /v1/completions emits.
func (r TopLogprobRow) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, entry := range r {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(entry.Token)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(entry.Logprob)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// completionTopK reads one generated position's top_logprobs and returns the
// required top-k in rank order (highest logprob first).
//
// vLLM does NOT emit the entries in rank order: it writes the sampled token
// first regardless of its logprob, and when that token falls outside the
// requested top-k the row carries requiredTopK+1 entries with the sampled token
// still up front. So the entries are sorted by logprob here rather than trusted
// as the engine wrote them -- otherwise the emitted token's rank (rankIn, derived
// from list position) would read 1 whenever the sampled token led the row, even
// when its logprob ranked it lower. The sort is stable, so equal logprobs keep
// the engine's relative order and the result stays deterministic.
//
// When the row holds requiredTopK+1 entries the sampled token fell outside the
// top-k: it is dropped so the kept list is exactly the requiredTopK highest
// logprobs and the emitted token's rank is 0. The entries must be distinct
// vocabulary ids with non-NaN logprobs; anything else is refused rather than
// repaired.
func completionTopK(position int, emitted uint32, row TopLogprobRow, requiredTopK int) ([]metric.TokenLogprob, error) {
	if requiredTopK <= 0 {
		return nil, fmt.Errorf("position %d: required_top_k must be positive", position)
	}
	if len(row) != requiredTopK && len(row) != requiredTopK+1 {
		return nil, fmt.Errorf("position %d: top-logprobs hold %d entries, want %d or %d", position, len(row), requiredTopK, requiredTopK+1)
	}
	entries := make([]metric.TokenLogprob, 0, len(row))
	seen := make(map[uint32]struct{}, len(row))
	for _, entry := range row {
		id, err := tokenIDFromKey(entry.Token)
		if err != nil {
			return nil, fmt.Errorf("position %d: %w", position, err)
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("position %d: top-logprobs repeat token %d", position, id)
		}
		seen[id] = struct{}{}
		if math.IsNaN(entry.Logprob) {
			return nil, fmt.Errorf("position %d: top-logprobs token %d has a NaN logprob", position, id)
		}
		entries = append(entries, metric.TokenLogprob{TokenID: id, Logprob: entry.Logprob})
	}
	// Rank order is logprob descending. Stable so equal logprobs keep the engine's
	// order and the committed vector is reproducible.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Logprob > entries[j].Logprob
	})
	if len(entries) == requiredTopK+1 {
		// The extra entry is the sampled token, appended because it fell outside the
		// top-k. Drop the emitted token specifically, and require it to be no better
		// than any kept token so a mis-sized row is refused rather than repaired.
		dropped := -1
		for i, entry := range entries {
			if entry.TokenID == emitted {
				dropped = i
				break
			}
		}
		if dropped < 0 {
			return nil, fmt.Errorf("position %d: top-logprobs hold %d entries but none is the emitted token %d to drop", position, len(entries), emitted)
		}
		droppedLogprob := entries[dropped].Logprob
		entries = append(entries[:dropped], entries[dropped+1:]...)
		if droppedLogprob > entries[len(entries)-1].Logprob {
			return nil, fmt.Errorf("position %d: the emitted token %d is inside the top-k but was appended as an extra entry", position, emitted)
		}
	}
	return entries, nil
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
