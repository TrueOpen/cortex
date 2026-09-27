package metric

import (
	"fmt"
	"math"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// ValueLeaves converts one side's real-valued position values into the
// fixed-point value leaves of wire v0.3.0. It is the only place a model
// service's doubles become protocol numbers, so the Worker's worker_values and
// the Verifier's value tree cannot round differently.
//
// Each value becomes one of the three leaf states:
//
//   - missing: the model service reported no value for the token. Zero logprob,
//     zero rank, empty top-k.
//   - non-finite: a value was reported but its logprob is NaN or infinite. Same
//     zero values as missing, with missing_flag false.
//   - normal: logprob in fp_1e6 (signedFP1e6's rounding), the rank if it is
//     inside 1..requiredTopK and 0 otherwise, and exactly requiredTopK top-k
//     entries: the first requiredTopK of the reported list, which is in rank
//     order. A normal value with fewer entries, or with a non-finite logprob
//     among them, cannot be framed and is refused.
func ValueLeaves(values []PositionValue, requiredTopK uint32) ([]nodewire.PositionValueV1, error) {
	if requiredTopK == 0 {
		return nil, fmt.Errorf("required_top_k must be positive")
	}
	leaves := make([]nodewire.PositionValueV1, len(values))
	for i, value := range values {
		position, err := countUint32("position", i)
		if err != nil {
			return nil, err
		}
		leaf := nodewire.PositionValueV1{Position: position, TokenID: value.TokenID, Missing: value.Missing}
		if !value.Missing && isFinite(value.Logprob) {
			if leaf.LogprobFP1e6, err = signedFP1e6(fmt.Sprintf("position %d logprob", i), value.Logprob); err != nil {
				return nil, err
			}
			if value.Rank >= 1 && value.Rank <= requiredTopK {
				leaf.Rank = value.Rank
			}
			if uint64(len(value.TopK)) < uint64(requiredTopK) {
				return nil, fmt.Errorf("position %d reports %d top-k entries, fewer than required_top_k %d", i, len(value.TopK), requiredTopK)
			}
			leaf.TopK = make([]nodewire.TopKEntryV1, requiredTopK)
			for j, entry := range value.TopK[:requiredTopK] {
				if math.IsNaN(entry.Logprob) || math.IsInf(entry.Logprob, 0) {
					return nil, fmt.Errorf("position %d top-k entry %d has a non-finite logprob", i, j)
				}
				fp, err := signedFP1e6(fmt.Sprintf("position %d top-k entry %d logprob", i, j), entry.Logprob)
				if err != nil {
					return nil, err
				}
				leaf.TopK[j] = nodewire.TopKEntryV1{TokenID: entry.TokenID, LogprobFP1e6: fp}
			}
			leaf.Finite = true
		}
		leaves[i] = leaf
	}
	return leaves, nil
}
