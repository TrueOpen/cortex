package keepercontract

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const (
	TaskEpochLengthBlocks          = uint64(100)
	DomainSupportModels            = "TRUEOPEN_SUPPORT_MODELS_V1"
	DomainDailySupportConfirmation = "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1"
	DomainWorkerReveal             = "TRUEOPEN_WORKER_REVEAL_RECEIPT_V1"
)

func TaskEpoch(height uint64) uint64 {
	return height / TaskEpochLengthBlocks
}

// CanonicalModelIDs returns a sorted copy of model ids (canonical lowercase hex
// of their Hash32) in the order Node requires for supported_models: raw bytes
// ascending, which for fixed-width lowercase hex is the same as text order. It
// refuses an empty set, a non-canonical id and duplicates, so its result is
// always accepted by SupportedModelsHash and DailySupportConfirmation.
func CanonicalModelIDs(modelIDs []string) ([]string, error) {
	if len(modelIDs) == 0 {
		return nil, fmt.Errorf("supported models are required")
	}
	sorted := slices.Clone(modelIDs)
	for _, modelID := range sorted {
		if !identity.ValidModelIDHex(modelID) {
			return nil, fmt.Errorf("supported model id %q is not canonical", modelID)
		}
	}
	slices.Sort(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index-1] == sorted[index] {
			return nil, fmt.Errorf("supported models contain duplicate %s", sorted[index])
		}
	}
	return sorted, nil
}

func SupportedModelsHash(modelIDs []string) (codec.Hash, error) {
	fields, err := supportedModelFields(modelIDs)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainSupportModels, fields...)
}

func DailySupportConfirmation(
	chainID, operatorAddress string,
	epoch, serviceAuthorizationNonce, expiryHeight uint64,
	modelIDs []string,
) (codec.Hash, error) {
	operator, err := nodewire.CanonicalOperatorAddressBytes("operator_address", operatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	modelFields, err := supportedModelFields(modelIDs)
	if err != nil {
		return codec.Hash{}, err
	}
	fields := []hfields.Field{
		hfields.String(chainID), hfields.Bytes(operator), hfields.Uint64(epoch),
		hfields.Uint64(serviceAuthorizationNonce), hfields.Uint64(expiryHeight),
	}
	fields = append(fields, modelFields...)
	return hfields.Digest(DomainDailySupportConfirmation, fields...)
}

// supportedModelFields returns the two fields the repeated model list
// contributes: model_count, then ONE nested frame holding its own element_count
// and each raw Hash32. wire's vectors (testdata/v1/hub/hub_domains_v1.json,
// support_models_v1 and daily_support_confirmation_v1) list both counts.
func supportedModelFields(modelIDs []string) ([]hfields.Field, error) {
	if len(modelIDs) == 0 || len(modelIDs) > math.MaxUint32 {
		return nil, fmt.Errorf("supported models count is outside uint32")
	}
	elements := make([]hfields.Field, 0, len(modelIDs)+1)
	elements = append(elements, hfields.Uint32(uint32(len(modelIDs))))
	for index, modelID := range modelIDs {
		raw, err := identity.ModelIDBytes(modelID)
		if err != nil {
			return nil, err
		}
		if index > 0 && modelIDs[index-1] >= modelID {
			return nil, fmt.Errorf("supported models must be strictly ascending and unique")
		}
		elements = append(elements, hfields.Bytes(raw))
	}
	return []hfields.Field{hfields.Uint32(uint32(len(modelIDs))), hfields.Frame(elements...)}, nil
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
