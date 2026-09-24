package keepercontract

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const (
	TaskEpochLengthBlocks          = uint64(100)
	DomainSupportProfiles          = "TRUEOPEN_SUPPORT_PROFILES_V1"
	DomainDailySupportConfirmation = "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1"
	DomainWorkerReveal             = "TRUEOPEN_WORKER_REVEAL_RECEIPT_V1"
)

func TaskEpoch(height uint64) uint64 {
	return height / TaskEpochLengthBlocks
}

type ProfileRef struct {
	ModelID        string
	ProfileVersion uint32
}

// CanonicalProfileRefs returns a sorted copy of profiles in the order Node
// requires for supported_profiles: model_id ascending, then profile_version
// ascending as a number. It refuses an empty set, a missing or untrimmed
// identity, and duplicates, so its result is always accepted by
// SupportedProfilesHash and DailySupportConfirmation.
func CanonicalProfileRefs(profiles []ProfileRef) ([]ProfileRef, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("supported profiles are required")
	}
	sorted := slices.Clone(profiles)
	for _, profile := range sorted {
		if profile.ModelID == "" || strings.TrimSpace(profile.ModelID) != profile.ModelID || profile.ProfileVersion == 0 {
			return nil, fmt.Errorf("supported profile identity must be canonical and non-empty")
		}
	}
	slices.SortFunc(sorted, compareProfileRefs)
	for index := 1; index < len(sorted); index++ {
		if compareProfileRefs(sorted[index-1], sorted[index]) == 0 {
			return nil, fmt.Errorf("supported profiles contain duplicate %s@%d", sorted[index].ModelID, sorted[index].ProfileVersion)
		}
	}
	return sorted, nil
}

func SupportedProfilesHash(profiles []ProfileRef) (codec.Hash, error) {
	fields, err := supportedProfileFields(profiles)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainSupportProfiles, fields...)
}

func DailySupportConfirmation(
	chainID, operatorAddress string,
	epoch, serviceAuthorizationNonce, expiryHeight uint64,
	profiles []ProfileRef,
) (codec.Hash, error) {
	operator, err := nodewire.CanonicalOperatorAddressBytes("operator_address", operatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	profileFields, err := supportedProfileFields(profiles)
	if err != nil {
		return codec.Hash{}, err
	}
	fields := []hfields.Field{
		hfields.String(chainID), hfields.Bytes(operator), hfields.Uint64(epoch),
		hfields.Uint64(serviceAuthorizationNonce), hfields.Uint64(expiryHeight),
	}
	fields = append(fields, profileFields...)
	return hfields.Digest(DomainDailySupportConfirmation, fields...)
}

// supportedProfileFields returns the two fields the repeated profile list
// contributes: profile_count, then ONE nested frame holding its own
// element_count and a frame per profile.
//
// The list used to be flattened into the caller's field list, one top-level
// field per profile. That is the same mistake internal/nodewire corrected for
// TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1, and it is settled the same way, by
// github.com/TrueOpen/wire's published vectors (testdata/v1/hub/hub_domains_v1.json,
// support_profiles_v1 and daily_support_confirmation_v1), both of which frame
// "profiles" as a frame carrying element_count. It reached a signed message:
// DailySupportConfirmation is signed with the Keeper-confirmed ServiceKey, so
// the flattened form produced a signature over a preimage the chain never
// derives.
func supportedProfileFields(profiles []ProfileRef) ([]hfields.Field, error) {
	if len(profiles) == 0 || len(profiles) > math.MaxUint32 {
		return nil, fmt.Errorf("supported profiles count is outside uint32")
	}
	elements := make([]hfields.Field, 0, len(profiles)+1)
	elements = append(elements, hfields.Uint32(uint32(len(profiles))))
	for index, profile := range profiles {
		if profile.ModelID == "" || profile.ProfileVersion == 0 {
			return nil, fmt.Errorf("supported profile identity is required")
		}
		// Compare the version as a number: ordering the decimal text put "10"
		// before "2", the reverse of the order Node requires.
		if index > 0 && compareProfileRefs(profiles[index-1], profile) >= 0 {
			return nil, fmt.Errorf("supported profiles must be strictly ascending and unique")
		}
		elements = append(elements, hfields.Frame(hfields.String(profile.ModelID), hfields.Uint32(profile.ProfileVersion)))
	}
	// profile_count and the frame's element_count are two separate fields
	// carrying the same number; wire's vectors list both.
	return []hfields.Field{hfields.Uint32(uint32(len(profiles))), hfields.Frame(elements...)}, nil
}

// compareProfileRefs orders profiles the way Node's
// validateCanonicalSupportedProfiles does: by model_id, then by the numeric
// profile_version.
func compareProfileRefs(a, b ProfileRef) int {
	if order := strings.Compare(a.ModelID, b.ModelID); order != 0 {
		return order
	}
	return cmp.Compare(a.ProfileVersion, b.ProfileVersion)
}

func WorkerReveal(chainID, taskID string, verifyRound uint64, sampleSeed, sampledValueSetHash, evidenceSchemaVersion string) codec.Hash {
	return hash(DomainWorkerReveal, chainID, taskID, decimal(verifyRound), sampleSeed, strings.TrimSpace(sampledValueSetHash), strings.TrimSpace(evidenceSchemaVersion))
}

func hash(domain string, fields ...string) codec.Hash {
	encoded := make([][]byte, 0, len(fields))
	for _, field := range fields {
		encoded = append(encoded, []byte(field))
	}
	return codec.HashWithDomain(domain, encoded...)
}

func decimal(value uint64) string {
	return strconv.FormatUint(value, 10)
}
