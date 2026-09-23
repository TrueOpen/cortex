package nodewire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const DomainTaskOrderV2 = "TRUEOPEN_TASK_ORDER_V2"

type taskOrderUint64 uint64

func (v *taskOrderUint64) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("uint64 must use ProtoJSON decimal string: %w", err)
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != text {
		return fmt.Errorf("uint64 must be canonical unsigned decimal")
	}
	*v = taskOrderUint64(parsed)
	return nil
}

type taskOrderBytes []byte

func (v *taskOrderBytes) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return fmt.Errorf("bytes must use canonical ProtoJSON base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(raw) != text {
		return fmt.Errorf("bytes must use canonical ProtoJSON base64")
	}
	*v = raw
	return nil
}

// taskOrderTaskTypeValue and taskOrderLatencyClassValue hold the frozen enum
// numbers, which is what the H_FIELDS_V1 preimage is expressed over. The wire
// spells them two different ways - ProtoJSON writes the enum name, the proto
// carrier writes the number - so the name lives in the JSON decoder and nowhere
// else. Both carriers reach taskOrderHash holding the same number.
type taskOrderTaskTypeValue uint32

func (v *taskOrderTaskTypeValue) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("TaskOrderV2 task_type must be a ProtoJSON enum name: %w", err)
	}
	number := map[string]uint32{"TASK_TYPE_TEXT_GENERATION": 1, "TASK_TYPE_CHAT": 2, "TASK_TYPE_EMBEDDING": 3, "TASK_TYPE_CLASSIFICATION": 4, "TASK_TYPE_IMAGE_GENERATION": 5, "TASK_TYPE_MULTIMODAL": 6}[text]
	if number == 0 {
		return fmt.Errorf("TaskOrderV2 task_type is invalid")
	}
	*v = taskOrderTaskTypeValue(number)
	return nil
}

type taskOrderLatencyClassValue uint32

func (v *taskOrderLatencyClassValue) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("TaskOrderV2 latency_class must be a ProtoJSON enum name: %w", err)
	}
	number := map[string]uint32{"DEADLINE_LATENCY_CLASS_ECONOMY": 1, "DEADLINE_LATENCY_CLASS_STANDARD": 2, "DEADLINE_LATENCY_CLASS_FAST": 3, "DEADLINE_LATENCY_CLASS_EXPRESS": 4}[text]
	if number == 0 {
		return fmt.Errorf("TaskOrderV2 latency_class is invalid")
	}
	*v = taskOrderLatencyClassValue(number)
	return nil
}

type taskOrderAmount struct {
	AtomicUnits string `json:"atomic_units"`
}

type taskOrderDecodingParams struct {
	SamplingEnabled       bool            `json:"sampling_enabled"`
	TemperatureMilli      uint32          `json:"temperature_milli"`
	TopPPPM               uint32          `json:"top_p_ppm"`
	TopK                  uint32          `json:"top_k"`
	Seed                  taskOrderUint64 `json:"seed"`
	PresencePenaltyMilli  int32           `json:"presence_penalty_milli"`
	FrequencyPenaltyMilli int32           `json:"frequency_penalty_milli"`
	RepetitionPenaltyPPM  uint32          `json:"repetition_penalty_ppm"`
	StopSequences         []string        `json:"stop_sequences"`
	StopTokenIDs          []uint32        `json:"stop_token_ids"`
}

type taskOrderGenerationParams struct {
	SchemaVersion     uint32                  `json:"generation_params_schema_version"`
	MaxOutputTokens   taskOrderUint64         `json:"max_output_tokens"`
	MaxOutputDuration taskOrderUint64         `json:"max_output_duration"`
	DecodingParams    taskOrderDecodingParams `json:"decoding_params"`
}

type taskOrderDeadlinePolicy struct {
	LatencyClass taskOrderLatencyClassValue `json:"latency_class"`
}

type taskOrderV2 struct {
	SchemaVersion          uint32                    `json:"schema_version"`
	ChainID                string                    `json:"chain_id"`
	UserAddress            string                    `json:"user_address"`
	SessionID              taskOrderBytes            `json:"session_id"`
	OrderSequence          taskOrderUint64           `json:"order_sequence"`
	ModelID                string                    `json:"model_id"`
	ProfileVersion         uint32                    `json:"profile_version"`
	TaskType               taskOrderTaskTypeValue    `json:"task_type"`
	InputHash              taskOrderBytes            `json:"input_hash"`
	InputSizeBytes         taskOrderUint64           `json:"input_size_bytes"`
	InputBucket            uint32                    `json:"input_bucket"`
	OutputBudgetBucket     uint32                    `json:"output_budget_bucket"`
	GenerationParams       taskOrderGenerationParams `json:"generation_params"`
	PriceBid               taskOrderAmount           `json:"price_bid"`
	MaxFee                 taskOrderAmount           `json:"max_fee"`
	AssignmentPriorityFee  taskOrderAmount           `json:"assignment_priority_fee"`
	TxFeeReserve           taskOrderAmount           `json:"tx_fee_reserve"`
	EarliestSubmitHeight   taskOrderUint64           `json:"earliest_submit_height"`
	OrderExpireHeight      taskOrderUint64           `json:"order_expire_height"`
	DeadlinePolicy         taskOrderDeadlinePolicy   `json:"deadline_policy"`
	TimeoutBucketVersion   taskOrderUint64           `json:"timeout_bucket_version"`
	SessionAnchorHeight    taskOrderUint64           `json:"session_anchor_height"`
	SessionAnchorBlockHash taskOrderBytes            `json:"session_anchor_block_hash"`
	BuilderSetID           string                    `json:"builder_set_id"`
	BuilderSetHash         taskOrderBytes            `json:"builder_set_hash"`
}

type TaskOrderFacts struct {
	ChainID                string
	SessionID              string
	OrderSequence          uint64
	ModelID                string
	ProfileVersion         uint32
	Generation             *GenerationContext
	InputHash              string
	InputSizeBytes         uint64
	SessionAnchorBlockHash string
	BuilderSetID           string
	BuilderSetHash         string
	OrderExpireHeight      uint64

	// SignatureScheme and UserSignature are the two SignedOrderV2 fields that sit
	// beside the order in the proto carrier. They are empty for the legacy JSON
	// carrier, which holds the bare order and nothing around it, so a caller must
	// treat empty as "the carrier did not state one" rather than as a mismatch.
	SignatureScheme string
	UserSignature   string
}

func TaskOrderHashJSON(value string) (codec.Hash, error) {
	digest, _, err := TaskOrderHashAndFactsJSON(value)
	return digest, err
}

// TaskOrderHashAndFactsEnvelope reads whichever of the two order_envelope
// carriers a frame holds. Nexus decides between them by first byte and so does
// this: a canonical JSON document always opens with '{', and a proto-encoded
// SignedOrderV2 always opens with the tag byte of field 1, which is 0x0a. The
// carrier a real Builder publishes is the proto one - the user signs the frozen
// TaskOrderV2 and Nexus forwards those exact bytes rather than re-encoding them
// (nexus internal/ingress/service.go parseSignedOrderEnvelope) - so the JSON arm
// is only reachable from the legacy order path and from scripts/testorder.
func TaskOrderHashAndFactsEnvelope(value string) (codec.Hash, TaskOrderFacts, error) {
	if strings.HasPrefix(value, "{") {
		return TaskOrderHashAndFactsJSON(value)
	}
	return TaskOrderHashAndFactsSignedOrderHex(value)
}

func TaskOrderHashAndFactsJSON(value string) (codec.Hash, TaskOrderFacts, error) {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var order taskOrderV2
	if err := decoder.Decode(&order); err != nil {
		return codec.Hash{}, TaskOrderFacts{}, fmt.Errorf("decode TaskOrderV2: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return codec.Hash{}, TaskOrderFacts{}, fmt.Errorf("TaskOrderV2 carries trailing JSON")
	}
	digest, err := taskOrderHash(order)
	if err != nil {
		return codec.Hash{}, TaskOrderFacts{}, err
	}
	return digest, taskOrderFacts(order), nil
}

func taskOrderFacts(order taskOrderV2) TaskOrderFacts {
	d := order.GenerationParams.DecodingParams
	generation := GenerationContext{
		ModelID: order.ModelID, ProfileVersion: order.ProfileVersion, TaskType: uint32(order.TaskType), OutputBudgetBucket: order.OutputBudgetBucket,
		Params: GenerationParamsV1{
			SchemaVersion:   order.GenerationParams.SchemaVersion,
			MaxOutputTokens: uint64(order.GenerationParams.MaxOutputTokens), MaxOutputDuration: uint64(order.GenerationParams.MaxOutputDuration),
			DecodingParams: DecodingParamsV1{
				SamplingEnabled: d.SamplingEnabled, TemperatureMilli: d.TemperatureMilli, TopPPPM: d.TopPPPM, TopK: d.TopK, Seed: uint64(d.Seed),
				PresencePenaltyMilli: d.PresencePenaltyMilli, FrequencyPenaltyMilli: d.FrequencyPenaltyMilli, RepetitionPenaltyPPM: d.RepetitionPenaltyPPM,
				StopSequences: d.StopSequences, StopTokenIDs: d.StopTokenIDs,
			},
		},
	}.Clone()
	return TaskOrderFacts{
		ChainID: order.ChainID, SessionID: fmt.Sprintf("%x", []byte(order.SessionID)), OrderSequence: uint64(order.OrderSequence),
		ModelID: order.ModelID, ProfileVersion: order.ProfileVersion, InputHash: fmt.Sprintf("%x", []byte(order.InputHash)),
		Generation:             &generation,
		InputSizeBytes:         uint64(order.InputSizeBytes),
		SessionAnchorBlockHash: fmt.Sprintf("%x", []byte(order.SessionAnchorBlockHash)),
		BuilderSetID:           order.BuilderSetID, BuilderSetHash: fmt.Sprintf("%x", []byte(order.BuilderSetHash)),
		OrderExpireHeight: uint64(order.OrderExpireHeight),
	}
}

func taskOrderHash(order taskOrderV2) (codec.Hash, error) {
	if order.SchemaVersion != 2 || order.ChainID == "" || !utf8.ValidString(order.ChainID) || order.ModelID == "" || !utf8.ValidString(order.ModelID) ||
		len(order.SessionID) != 32 || order.ProfileVersion == 0 || len(order.InputHash) != 32 || order.InputSizeBytes == 0 || order.OutputBudgetBucket == 0 ||
		order.EarliestSubmitHeight == 0 || order.OrderExpireHeight == 0 || order.EarliestSubmitHeight >= order.OrderExpireHeight ||
		order.TimeoutBucketVersion == 0 || order.SessionAnchorHeight == 0 || len(order.SessionAnchorBlockHash) != 32 ||
		order.BuilderSetID == "" || !utf8.ValidString(order.BuilderSetID) || len(order.BuilderSetHash) != 32 {
		return codec.Hash{}, fmt.Errorf("TaskOrderV2 scalar scope is invalid")
	}
	user, err := CanonicalOperatorAddressBytes("user_address", order.UserAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	if order.TaskType == 0 || order.TaskType > 6 {
		return codec.Hash{}, fmt.Errorf("TaskOrderV2 task_type is invalid")
	}
	if order.DeadlinePolicy.LatencyClass == 0 || order.DeadlinePolicy.LatencyClass > 4 {
		return codec.Hash{}, fmt.Errorf("TaskOrderV2 latency_class is invalid")
	}
	taskType, latency := uint32(order.TaskType), uint32(order.DeadlinePolicy.LatencyClass)
	generation, err := taskOrderGenerationFrame(order.GenerationParams)
	if err != nil {
		return codec.Hash{}, err
	}
	amounts := []taskOrderAmount{order.PriceBid, order.MaxFee, order.AssignmentPriorityFee, order.TxFeeReserve}
	fields := []hfields.Field{
		hfields.Uint32(order.SchemaVersion), hfields.String(order.ChainID), hfields.Bytes(user), hfields.Bytes(order.SessionID), hfields.Uint64(uint64(order.OrderSequence)),
		hfields.String(order.ModelID), hfields.Uint32(order.ProfileVersion), hfields.Uint32(taskType), hfields.Bytes(order.InputHash), hfields.Uint64(uint64(order.InputSizeBytes)),
		hfields.Uint32(order.InputBucket), hfields.Uint32(order.OutputBudgetBucket), generation,
	}
	for index, amount := range amounts {
		if err := validateTaskOrderAmount(amount.AtomicUnits); err != nil {
			return codec.Hash{}, fmt.Errorf("TaskOrderV2 amount field %d: %w", index+14, err)
		}
		fields = append(fields, hfields.Frame(hfields.String(amount.AtomicUnits)))
	}
	fields = append(fields,
		hfields.Uint64(uint64(order.EarliestSubmitHeight)), hfields.Uint64(uint64(order.OrderExpireHeight)), hfields.Frame(hfields.Uint32(latency)),
		hfields.Uint64(uint64(order.TimeoutBucketVersion)), hfields.Uint64(uint64(order.SessionAnchorHeight)),
		hfields.Bytes(order.SessionAnchorBlockHash), hfields.String(order.BuilderSetID), hfields.Bytes(order.BuilderSetHash),
	)
	return hfields.Digest(DomainTaskOrderV2, fields...)
}

func taskOrderGenerationFrame(params taskOrderGenerationParams) (hfields.Field, error) {
	if params.SchemaVersion != 1 {
		return hfields.Field{}, fmt.Errorf("unsupported generation params schema version")
	}
	decoding := params.DecodingParams
	for index, value := range decoding.StopSequences {
		if !utf8.ValidString(value) || index > 0 && value <= decoding.StopSequences[index-1] {
			return hfields.Field{}, fmt.Errorf("stop sequences must be strict UTF-8, sorted, and unique")
		}
	}
	for index, value := range decoding.StopTokenIDs {
		if index > 0 && value <= decoding.StopTokenIDs[index-1] {
			return hfields.Field{}, fmt.Errorf("stop token ids must be sorted and unique")
		}
	}
	stopFields := []hfields.Field{hfields.Uint32(uint32(len(decoding.StopSequences)))}
	for _, value := range decoding.StopSequences {
		stopFields = append(stopFields, hfields.String(value))
	}
	tokenFields := []hfields.Field{hfields.Uint32(uint32(len(decoding.StopTokenIDs)))}
	for _, value := range decoding.StopTokenIDs {
		tokenFields = append(tokenFields, hfields.Uint32(value))
	}
	decodingFrame := hfields.Frame(
		hfields.Bool(decoding.SamplingEnabled), hfields.Uint32(decoding.TemperatureMilli), hfields.Uint32(decoding.TopPPPM), hfields.Uint32(decoding.TopK),
		hfields.Uint64(uint64(decoding.Seed)), hfields.Int32(decoding.PresencePenaltyMilli), hfields.Int32(decoding.FrequencyPenaltyMilli),
		hfields.Uint32(decoding.RepetitionPenaltyPPM), hfields.Frame(stopFields...), hfields.Frame(tokenFields...),
	)
	return hfields.Frame(hfields.Uint32(params.SchemaVersion), hfields.Uint64(uint64(params.MaxOutputTokens)), hfields.Uint64(uint64(params.MaxOutputDuration)), decodingFrame), nil
}

func validateTaskOrderAmount(value string) error {
	if value == "" || value != "0" && value[0] == '0' {
		return fmt.Errorf("atomic_units is not canonical")
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return fmt.Errorf("atomic_units is not unsigned decimal")
		}
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return fmt.Errorf("atomic_units exceeds uint64")
	}
	return nil
}
