package revealcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/SingaXYZ/cortex/internal/codec"
)

const domainResultCommit = "TRUEOPEN_RESULT_COMMIT_V1"

type CompactReveal struct {
	Points string
	Salt   string
}

func ParseCompact(reveal string) (CompactReveal, error) {
	if reveal == "" || strings.TrimSpace(reveal) != reveal {
		return CompactReveal{}, fmt.Errorf("result reveal is not canonical")
	}
	parts := strings.Split(reveal, "|")
	points := make(map[string]string)
	pointIDs := make([]string, 0, len(parts))
	salt := ""
	for index, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" || value == "" || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return CompactReveal{}, fmt.Errorf("result reveal part %d is not canonical", index)
		}
		if key == "salt" {
			if salt != "" || index != len(parts)-1 {
				return CompactReveal{}, fmt.Errorf("result reveal salt must occur once at the end")
			}
			salt = value
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != value {
			return CompactReveal{}, fmt.Errorf("result reveal point %q must be a canonical uint64", key)
		}
		if _, exists := points[key]; exists {
			return CompactReveal{}, fmt.Errorf("result reveal point %q is duplicated", key)
		}
		points[key] = value
		pointIDs = append(pointIDs, key)
	}
	if len(points) == 0 {
		return CompactReveal{}, fmt.Errorf("result reveal points are required")
	}
	if !sort.StringsAreSorted(pointIDs) {
		return CompactReveal{}, fmt.Errorf("result reveal points must be sorted")
	}
	canonical := make([]string, 0, len(pointIDs))
	for _, pointID := range pointIDs {
		canonical = append(canonical, pointID+"="+points[pointID])
	}
	return CompactReveal{Points: strings.Join(canonical, "|"), Salt: salt}, nil
}

func CommitHash(taskID string, verifyRound uint64, verifierAddress, sampleSeed, reveal string) (codec.Hash, error) {
	parsed, err := ParseCompact(reveal)
	if err != nil {
		return codec.Hash{}, err
	}
	pointsHash := sha256.Sum256([]byte(parsed.Points))
	return codec.HashWithDomain(
		domainResultCommit,
		[]byte(taskID),
		[]byte(strconv.FormatUint(verifyRound, 10)),
		[]byte(verifierAddress),
		[]byte(sampleSeed),
		[]byte(hex.EncodeToString(pointsHash[:])),
		[]byte(parsed.Salt),
	), nil
}
