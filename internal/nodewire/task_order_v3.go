package nodewire

// TaskOrderV3 of wire v0.3.0 (TrueOpen/wire#14, task/task_order_v3.json). It
// binds the raw Hash32 model id and adds the three payload-encryption fields
// (payload_mode, input_key_commitment and user_recipient_pubkey).

import (
	"fmt"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainTaskOrderV3               = "TRUEOPEN_TASK_ORDER_V3"
	TaskOrderSchemaVersionV3 uint32 = 3
	// PayloadModeV1Plaintext is the only payload mode accepted until
	// encryption activates.
	PayloadModeV1Plaintext uint32 = 1
)

// TaskOrderV3 is in schema field-number order. The four amounts are canonical
// unsigned decimal atomic units, as in V2.
type TaskOrderV3 struct {
	SchemaVersion          uint32
	ChainID                string
	UserAddress            string // canonical Bech32; framed as address bytes
	SessionID              []byte // Hash32
	OrderSequence          uint64
	ModelID                []byte // Hash32
	ProfileVersion         uint32
	TaskType               uint32
	InputHash              []byte // Hash32
	InputSizeBytes         uint64
	InputBucket            uint32
	OutputBudgetBucket     uint32
	GenerationParams       GenerationParamsV1
	PriceBid               string
	MaxFee                 string
	AssignmentPriorityFee  string
	TxFeeReserve           string
	EarliestSubmitHeight   uint64
	OrderExpireHeight      uint64
	LatencyClass           uint32 // deadline_policy
	TimeoutBucketVersion   uint64
	SessionAnchorHeight    uint64
	SessionAnchorBlockHash []byte // Hash32
	BuilderSetID           string
	BuilderSetHash         []byte // Hash32
	PayloadMode            uint32
	InputKeyCommitment     []byte // Hash32, ZERO32 in plaintext
	UserRecipientPubkey    []byte // empty in plaintext
}

// TaskOrderV3Hash is the V3 task hash over the 28 top-level fields.
func TaskOrderV3Hash(order TaskOrderV3) (codec.Hash, error) {
	if order.SchemaVersion != TaskOrderSchemaVersionV3 || order.ChainID == "" || !utf8.ValidString(order.ChainID) ||
		order.ProfileVersion == 0 || order.InputSizeBytes == 0 || order.OutputBudgetBucket == 0 ||
		order.EarliestSubmitHeight == 0 || order.OrderExpireHeight == 0 || order.EarliestSubmitHeight >= order.OrderExpireHeight ||
		order.TimeoutBucketVersion == 0 || order.SessionAnchorHeight == 0 || order.BuilderSetID == "" || !utf8.ValidString(order.BuilderSetID) {
		return codec.Hash{}, fmt.Errorf("TaskOrderV3 scalar scope is invalid")
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{
		{"session_id", order.SessionID}, {"model_id", order.ModelID}, {"input_hash", order.InputHash},
		{"session_anchor_block_hash", order.SessionAnchorBlockHash}, {"builder_set_hash", order.BuilderSetHash},
	} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return codec.Hash{}, err
		}
	}
	user, err := CanonicalOperatorAddressBytes("user_address", order.UserAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	if order.TaskType == 0 || order.TaskType > 6 {
		return codec.Hash{}, fmt.Errorf("TaskOrderV3 task_type is invalid")
	}
	if order.LatencyClass == 0 || order.LatencyClass > 4 {
		return codec.Hash{}, fmt.Errorf("TaskOrderV3 latency_class is invalid")
	}
	if order.PayloadMode != PayloadModeV1Plaintext {
		return codec.Hash{}, fmt.Errorf("TaskOrderV3 payload_mode must be PLAINTEXT")
	}
	if err := requirePlaintextSlot("input_key_commitment", order.InputKeyCommitment); err != nil {
		return codec.Hash{}, err
	}
	if err := requireEmptyRecipient(order.UserRecipientPubkey); err != nil {
		return codec.Hash{}, err
	}
	d := order.GenerationParams.DecodingParams
	generation, err := taskOrderGenerationFrame(taskOrderGenerationParams{
		SchemaVersion:     order.GenerationParams.SchemaVersion,
		MaxOutputTokens:   taskOrderUint64(order.GenerationParams.MaxOutputTokens),
		MaxOutputDuration: taskOrderUint64(order.GenerationParams.MaxOutputDuration),
		DecodingParams: taskOrderDecodingParams{
			SamplingEnabled: d.SamplingEnabled, TemperatureMilli: d.TemperatureMilli, TopPPPM: d.TopPPPM, TopK: d.TopK,
			Seed: taskOrderUint64(d.Seed), PresencePenaltyMilli: d.PresencePenaltyMilli, FrequencyPenaltyMilli: d.FrequencyPenaltyMilli,
			RepetitionPenaltyPPM: d.RepetitionPenaltyPPM, StopSequences: d.StopSequences, StopTokenIDs: d.StopTokenIDs,
		},
	})
	if err != nil {
		return codec.Hash{}, err
	}
	fields := []hfields.Field{
		hfields.Uint32(order.SchemaVersion), hfields.String(order.ChainID), hfields.Bytes(user), hfields.Bytes(order.SessionID), hfields.Uint64(order.OrderSequence),
		hfields.Bytes(order.ModelID), hfields.Uint32(order.ProfileVersion), hfields.Uint32(order.TaskType), hfields.Bytes(order.InputHash), hfields.Uint64(order.InputSizeBytes),
		hfields.Uint32(order.InputBucket), hfields.Uint32(order.OutputBudgetBucket), generation,
	}
	for index, amount := range []string{order.PriceBid, order.MaxFee, order.AssignmentPriorityFee, order.TxFeeReserve} {
		if err := validateTaskOrderAmount(amount); err != nil {
			return codec.Hash{}, fmt.Errorf("TaskOrderV3 amount field %d: %w", index+14, err)
		}
		fields = append(fields, hfields.Frame(hfields.String(amount)))
	}
	fields = append(fields,
		hfields.Uint64(order.EarliestSubmitHeight), hfields.Uint64(order.OrderExpireHeight), hfields.Frame(hfields.Uint32(order.LatencyClass)),
		hfields.Uint64(order.TimeoutBucketVersion), hfields.Uint64(order.SessionAnchorHeight),
		hfields.Bytes(order.SessionAnchorBlockHash), hfields.String(order.BuilderSetID), hfields.Bytes(order.BuilderSetHash),
		hfields.Uint32(order.PayloadMode), hfields.Bytes(order.InputKeyCommitment), hfields.Bytes(order.UserRecipientPubkey),
	)
	return hfields.Digest(DomainTaskOrderV3, fields...)
}
