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
// engine wrote them, which is rank order: chat returns an ordered list, and
// vLLM writes a /v1/completions top_logprobs object key by key in rank order.
// It decodes from either shape and never through a Go map, which would lose
// that order.
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

// completionTopK reads one generated position's top_logprobs in the engine's
// own rank order; nothing is re-sorted. The row must hold exactly requiredTopK
// distinct vocabulary ids with non-increasing logprobs, otherwise it is refused
// rather than repaired.
func completionTopK(position int, row TopLogprobRow, requiredTopK int) ([]metric.TokenLogprob, error) {
	if len(row) != requiredTopK {
		return nil, fmt.Errorf("position %d: top-logprobs hold %d entries, want exactly %d", position, len(row), requiredTopK)
	}
	out := make([]metric.TokenLogprob, 0, len(row))
	seen := make(map[uint32]struct{}, len(row))
	for i, entry := range row {
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
		if i > 0 && entry.Logprob > row[i-1].Logprob {
			return nil, fmt.Errorf("position %d: top-logprobs are not in rank order at entry %d", position, i)
		}
		out = append(out, metric.TokenLogprob{TokenID: id, Logprob: entry.Logprob})
	}
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
