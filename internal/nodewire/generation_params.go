package nodewire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
)

const DomainGenerationParamsV1 = "TRUEOPEN_TASK_GENERATION_PARAMS_V1"

const (
	maxGenerationPayloadBytes = 32 << 20
	maxGenerationListElements = 65534
)

type DecodingParamsV1 struct {
	SamplingEnabled       bool     `json:"sampling_enabled"`
	TemperatureMilli      uint32   `json:"temperature_milli"`
	TopPPPM               uint32   `json:"top_p_ppm"`
	TopK                  uint32   `json:"top_k"`
	Seed                  uint64   `json:"seed"`
	PresencePenaltyMilli  int32    `json:"presence_penalty_milli"`
	FrequencyPenaltyMilli int32    `json:"frequency_penalty_milli"`
	RepetitionPenaltyPPM  uint32   `json:"repetition_penalty_ppm"`
	StopSequences         []string `json:"stop_sequences"`
	StopTokenIDs          []uint32 `json:"stop_token_ids"`
}

type GenerationParamsV1 struct {
	SchemaVersion     uint32           `json:"generation_params_schema_version"`
	MaxOutputTokens   uint64           `json:"max_output_tokens"`
	MaxOutputDuration uint64           `json:"max_output_duration"`
	DecodingParams    DecodingParamsV1 `json:"decoding_params"`
}

// GenerationContext is the chain-bound generation identity. ModelID is the
// canonical lowercase hex of the Hash32 model id; the digest projection writes
// it as "0x"-prefixed hex, the canonical-JSON form of a Hash32.
type GenerationContext struct {
	ModelID            string             `json:"model_id"`
	ProfileVersion     uint32             `json:"profile_version"`
	TaskType           uint32             `json:"task_type"`
	OutputBudgetBucket uint32             `json:"output_budget_bucket"`
	Params             GenerationParamsV1 `json:"generation_params"`
}

func (g GenerationContext) Clone() GenerationContext {
	g.Params.DecodingParams.StopSequences = slices.Clone(g.Params.DecodingParams.StopSequences)
	g.Params.DecodingParams.StopTokenIDs = slices.Clone(g.Params.DecodingParams.StopTokenIDs)
	return g
}

// Digest implements 08-TaskOrderHash sections 4.3 and 5. This JSON projection is
// distinct from the nested field frame used by the deployed TaskOrderV2 hash.
func (g GenerationContext) Digest() (codec.Hash, error) {
	payload, err := g.canonicalJSON()
	if err != nil {
		return codec.Hash{}, err
	}
	return codec.HashV1(DomainGenerationParamsV1, payload), nil
}

// CanonicalJSON returns canonical_generation_params_json, the exact bytes the
// digest covers and the Worker's A-level generation_params artifact carries.
func (g GenerationContext) CanonicalJSON() ([]byte, error) {
	return g.canonicalJSON()
}

// GenerationParamsDigest is generation_params_digest over raw canonical bytes.
// Consumers of the generation_params artifact hash the bytes they received and
// never a re-serialization.
func GenerationParamsDigest(raw []byte) codec.Hash {
	return codec.HashV1(DomainGenerationParamsV1, raw)
}

// ParseCanonicalGenerationParams reads a generation_params artifact. It decodes
// strictly and requires raw to be the canonical encoding of what it decoded,
// so the parameters a Verifier prefills under are exactly the ones the digest
// of raw commits to.
func ParseCanonicalGenerationParams(raw []byte) (GenerationContext, error) {
	if len(raw) == 0 || len(raw) > maxGenerationPayloadBytes {
		return GenerationContext{}, fmt.Errorf("generation_params must hold 1..%d bytes", maxGenerationPayloadBytes)
	}
	var p generationProjection
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return GenerationContext{}, fmt.Errorf("decode generation_params: %w", err)
	}
	if dec.More() {
		return GenerationContext{}, fmt.Errorf("generation_params carries trailing data")
	}
	if len(p.ModelID) != 66 || p.ModelID[:2] != "0x" {
		return GenerationContext{}, fmt.Errorf("generation_params model_id must be 0x-prefixed Hash32 hex")
	}
	g := GenerationContext{
		ModelID: p.ModelID[2:], ProfileVersion: p.ProfileVersion, OutputBudgetBucket: p.OutputBudgetBucket,
		Params: GenerationParamsV1{
			SchemaVersion: p.SchemaVersion, MaxOutputTokens: p.MaxOutputTokens, MaxOutputDuration: p.MaxOutputDuration,
			DecodingParams: DecodingParamsV1{
				SamplingEnabled: p.DecodingParams.SamplingEnabled, TemperatureMilli: p.DecodingParams.TemperatureMilli,
				TopPPPM: p.DecodingParams.TopPPPM, TopK: p.DecodingParams.TopK, Seed: p.DecodingParams.Seed,
				PresencePenaltyMilli: p.DecodingParams.PresencePenaltyMilli, FrequencyPenaltyMilli: p.DecodingParams.FrequencyPenaltyMilli,
				RepetitionPenaltyPPM: p.DecodingParams.RepetitionPenaltyPPM,
				StopSequences:        p.DecodingParams.StopSequences, StopTokenIDs: p.DecodingParams.StopTokenIDs,
			},
		},
	}
	switch p.TaskType {
	case "TEXT_GENERATION":
		g.TaskType = 1
	case "CHAT":
		g.TaskType = 2
	default:
		return GenerationContext{}, fmt.Errorf("generation_params task_type %q is not TEXT_GENERATION or CHAT", p.TaskType)
	}
	canonical, err := g.canonicalJSON()
	if err != nil {
		return GenerationContext{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return GenerationContext{}, fmt.Errorf("generation_params is not canonical JSON")
	}
	return g, nil
}

// Struct declaration order is canonical UTF-8 key order, including the nested
// object. Transport structs deliberately do not define the digest projection.
type generationProjection struct {
	DecodingParams struct {
		FrequencyPenaltyMilli int32    `json:"frequency_penalty_milli"`
		PresencePenaltyMilli  int32    `json:"presence_penalty_milli"`
		RepetitionPenaltyPPM  uint32   `json:"repetition_penalty_ppm"`
		SamplingEnabled       bool     `json:"sampling_enabled"`
		Seed                  uint64   `json:"seed"`
		StopSequences         []string `json:"stop_sequences"`
		StopTokenIDs          []uint32 `json:"stop_token_ids"`
		TemperatureMilli      uint32   `json:"temperature_milli"`
		TopK                  uint32   `json:"top_k"`
		TopPPPM               uint32   `json:"top_p_ppm"`
	} `json:"decoding_params"`
	SchemaVersion      uint32 `json:"generation_params_schema_version"`
	MaxOutputDuration  uint64 `json:"max_output_duration"`
	MaxOutputTokens    uint64 `json:"max_output_tokens"`
	ModelID            string `json:"model_id"`
	OutputBudgetBucket uint32 `json:"output_budget_bucket"`
	ProfileVersion     uint32 `json:"profile_version"`
	TaskType           string `json:"task_type"`
}

func (g GenerationContext) canonicalJSON() ([]byte, error) {
	d := g.Params.DecodingParams
	if !canonicalModelIDHex(g.ModelID) || g.ProfileVersion == 0 || g.OutputBudgetBucket == 0 {
		return nil, fmt.Errorf("generation context model, profile, or output budget is invalid")
	}
	if g.TaskType != 1 && g.TaskType != 2 {
		return nil, fmt.Errorf("generation context task_type must be TEXT_GENERATION or CHAT")
	}
	if g.Params.SchemaVersion != 1 || g.Params.MaxOutputTokens == 0 || g.Params.MaxOutputDuration == 0 {
		return nil, fmt.Errorf("generation params schema or output limits are invalid")
	}
	if d.TemperatureMilli > 2000 || d.TopPPPM < 1 || d.TopPPPM > 1000000 ||
		d.PresencePenaltyMilli < -2000 || d.PresencePenaltyMilli > 2000 ||
		d.FrequencyPenaltyMilli < -2000 || d.FrequencyPenaltyMilli > 2000 ||
		d.RepetitionPenaltyPPM < 100000 || d.RepetitionPenaltyPPM > 2000000 {
		return nil, fmt.Errorf("generation decoding parameter is outside its frozen range")
	}
	if len(d.StopSequences) > maxGenerationListElements || len(d.StopTokenIDs) > maxGenerationListElements {
		return nil, fmt.Errorf("generation stop list exceeds canonical element limit")
	}
	p := generationProjection{
		SchemaVersion: g.Params.SchemaVersion, MaxOutputDuration: g.Params.MaxOutputDuration,
		MaxOutputTokens: g.Params.MaxOutputTokens, OutputBudgetBucket: g.OutputBudgetBucket,
		ProfileVersion: g.ProfileVersion, TaskType: "TEXT_GENERATION",
	}
	if g.TaskType == 2 {
		p.TaskType = "CHAT"
	}
	p.DecodingParams.FrequencyPenaltyMilli = d.FrequencyPenaltyMilli
	p.DecodingParams.PresencePenaltyMilli = d.PresencePenaltyMilli
	p.DecodingParams.RepetitionPenaltyPPM = d.RepetitionPenaltyPPM
	p.DecodingParams.SamplingEnabled = d.SamplingEnabled
	p.DecodingParams.Seed = d.Seed
	p.DecodingParams.TemperatureMilli = d.TemperatureMilli
	p.DecodingParams.TopK = d.TopK
	p.DecodingParams.TopPPPM = d.TopPPPM
	p.DecodingParams.StopSequences = []string{}
	p.DecodingParams.StopTokenIDs = []uint32{}
	// Compute the exact escaped payload size before allocating its full buffer.
	// The fixed portion is small; variable strings and lists are counted in place.
	base, err := encodeGenerationProjection(p)
	if err != nil {
		return nil, err
	}
	size := uint64(len(base)) + 2 + uint64(len(g.ModelID))
	for i, value := range d.StopSequences {
		if len(value) > maxGenerationPayloadBytes || !utf8.ValidString(value) || i > 0 && value <= d.StopSequences[i-1] {
			return nil, fmt.Errorf("generation stop sequences must be bounded UTF-8, sorted, and unique")
		}
		size += 2 + generationJSONStringContentSize(value)
		if i > 0 {
			size++
		}
		if size > maxGenerationPayloadBytes {
			return nil, fmt.Errorf("generation canonical payload exceeds 32 MiB")
		}
	}
	for i, value := range d.StopTokenIDs {
		if i > 0 && value <= d.StopTokenIDs[i-1] {
			return nil, fmt.Errorf("generation stop token ids must be sorted and unique")
		}
		size += uint64(len(strconv.FormatUint(uint64(value), 10)))
		if i > 0 {
			size++
		}
	}
	if size > maxGenerationPayloadBytes {
		return nil, fmt.Errorf("generation canonical payload exceeds 32 MiB")
	}
	p.ModelID = "0x" + g.ModelID
	if d.StopSequences != nil {
		p.DecodingParams.StopSequences = d.StopSequences
	}
	if d.StopTokenIDs != nil {
		p.DecodingParams.StopTokenIDs = d.StopTokenIDs
	}
	return encodeGenerationProjection(p)
}

func encodeGenerationProjection(p generationProjection) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// CANONICAL_ENCODING_V1 strings: only '"', '\\' and U+0000..U+001F are
	// escaped (\b \t \n \f \r short, others lowercase \u00xx), plus U+2028 and
	// U+2029; '<', '>', '&' and '/' are written as themselves. That is exactly
	// encoding/json with HTML escaping off (Go 1.22+ writes \b and \f short).
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(p); err != nil {
		return nil, fmt.Errorf("encode generation params: %w", err)
	}
	return buf.Bytes()[:buf.Len()-1], nil // Encoder appends one non-canonical newline.
}

func generationJSONStringContentSize(s string) uint64 {
	size := uint64(len(s))
	for _, r := range s {
		switch r {
		case '"', '\\', '\b', '\t', '\n', '\f', '\r':
			size++
		case '\u2028', '\u2029':
			size += 3
		default:
			if r < 0x20 {
				size += 5
			}
		}
	}
	return size
}

// canonicalModelIDHex reports whether text is the 64-lowercase-hex form of a
// Hash32 model id.
func canonicalModelIDHex(text string) bool {
	if len(text) != 64 {
		return false
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
