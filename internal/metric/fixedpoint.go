package metric

import (
	"fmt"
	"math"
)

// FixedPointScale is the 1e6 denominator every `*_fp_1e6` protocol field is
// expressed in. The profile carries the same fact as
// MetricSpec.numeric_scale = NUMERIC_SCALE_FP_1E6, and Bind refuses any profile
// that names a different scale rather than quietly using this one.
const FixedPointScale = 1_000_000

// numericScaleFP1e6 is the only MetricSpec.numeric_scale this pipeline can
// produce. The Keeper stores the token as a string and matches a whitelist, so
// both the bare and the prefixed spelling are accepted on read.
const (
	numericScaleFP1e6         = "FP_1E6"
	numericScaleFP1e6Prefixed = "NUMERIC_SCALE_FP_1E6"
)

// signedFP1e6 converts a real-valued metric to its signed fixed-point int64.
//
// Rounding is half away from zero (math.Round). The protocol documents the
// scale but not the rounding mode, so the choice is made once, here, and stated
// rather than repeated per call site: two verifiers that round differently
// produce different leaves for the same model output, which is exactly the
// divergence metric_root exists to make visible.
//
// NaN and infinities are refused. They have no fixed-point image, and the
// alternative - mapping them to zero - would report "the two logprobs agreed
// exactly" for a position where the comparison did not happen at all.
func signedFP1e6(name string, value float64) (int64, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("%s is %v and has no fixed-point encoding", name, value)
	}
	scaled := math.Round(value * FixedPointScale)
	if scaled > math.MaxInt64 || scaled < math.MinInt64 {
		return 0, fmt.Errorf("%s = %v does not fit the signed fp_1e6 int64 field", name, value)
	}
	return int64(scaled), nil
}

// unsignedFP1e6 converts a non-negative metric to its fixed-point uint64. A
// negative input is a caller bug rather than a value to clamp: every field that
// uses this encoding is an absolute difference, a rate or a similarity, none of
// which can be below zero.
func unsignedFP1e6(name string, value float64) (uint64, error) {
	scaled, err := signedFP1e6(name, value)
	if err != nil {
		return 0, err
	}
	if scaled < 0 {
		return 0, fmt.Errorf("%s = %v is negative and the field is unsigned", name, value)
	}
	return uint64(scaled), nil
}

// countUint32 narrows a Go int count to the uint32 the wire carries, refusing a
// negative or oversized one instead of wrapping.
func countUint32(name string, value int) (uint32, error) {
	if value < 0 || int64(value) > math.MaxUint32 {
		return 0, fmt.Errorf("%s = %d does not fit the uint32 field", name, value)
	}
	return uint32(value), nil
}
