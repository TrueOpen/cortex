package keepercontract

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
	"github.com/SingaXYZ/cortex/internal/nodewire"
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
	var previous string
	for _, profile := range profiles {
		if profile.ModelID == "" || profile.ProfileVersion == 0 {
			return nil, fmt.Errorf("supported profile identity is required")
		}
		key := profile.ModelID + "\x00" + strconv.FormatUint(uint64(profile.ProfileVersion), 10)
		if previous != "" && key <= previous {
			return nil, fmt.Errorf("supported profiles must be strictly ascending and unique")
		}
		previous = key
		elements = append(elements, hfields.Frame(hfields.String(profile.ModelID), hfields.Uint32(profile.ProfileVersion)))
	}
	// profile_count and the frame's element_count are two separate fields
	// carrying the same number; wire's vectors list both.
	return []hfields.Field{hfields.Uint32(uint32(len(profiles))), hfields.Frame(elements...)}, nil
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
