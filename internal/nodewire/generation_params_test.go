package nodewire

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// goldenGenerationContext is wire's generation_params_v1 vector.
func goldenGenerationContext() GenerationContext {
	return GenerationContext{
		ModelID: strings.Repeat("55", 32), ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: GenerationParamsV1{
			SchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 800, TopPPPM: 950000, TopK: 40, Seed: 42,
				PresencePenaltyMilli: -100, FrequencyPenaltyMilli: 200, RepetitionPenaltyPPM: 1100000,
				StopSequences: []string{"\n\n", "</s>"}, StopTokenIDs: []uint32{2, 128001},
			},
		},
	}
}

func TestGenerationContextDigestMatchesPublishedVector(t *testing.T) {
	raw, err := wirevectors.File("task/generation_params_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		CanonicalJSON string `json:"canonical_json"`
		DigestHex     string `json:"digest_hex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	g := goldenGenerationContext()
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.String(); got != vector.DigestHex {
		t.Fatalf("generation digest = %s, want %s", got, vector.DigestHex)
	}
	payload, err := g.canonicalJSON()
	if err != nil || string(payload) != vector.CanonicalJSON {
		t.Fatalf("canonical payload = %s, err = %v\nwant %s", payload, err, vector.CanonicalJSON)
	}
}

// wire v0.4.0 publishes min, max, min-1 and max+1 for every bounded
// DecodingParams field. Cortex implements the TaskOrderV3 projection rule set,
// so each case's task_order_v3 expectation decides whether canonicalJSON
// accepts here: the projection does not bound top_k (only the Keeper's
// generation-parameter payload does, against the registered limit), which is
// why top_k_max+1 is order-accepted while its generation_params row rejects.
func TestGenerationParamRangesMatchThePublishedVectors(t *testing.T) {
	raw, err := wirevectors.File("task/generation_params_ranges_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name             string `json:"name"`
			Field            string `json:"field"`
			Value            int64  `json:"value"`
			GenerationParams struct {
				Expect      string `json:"expect"`
				PayloadUTF8 string `json:"payload_utf8"`
				DigestHex   string `json:"digest_hex"`
			} `json:"generation_params"`
			TaskOrder struct {
				Expect string `json:"expect"`
			} `json:"task_order_v3"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("wire publishes no generation-parameter range cases")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			g := goldenGenerationContext()
			d := &g.Params.DecodingParams
			switch c.Field {
			case "decoding_params.temperature_milli":
				d.TemperatureMilli = uint32(c.Value)
			case "decoding_params.top_p_ppm":
				d.TopPPPM = uint32(c.Value)
			case "decoding_params.top_k":
				d.TopK = uint32(c.Value)
			case "decoding_params.presence_penalty_milli":
				d.PresencePenaltyMilli = int32(c.Value)
			case "decoding_params.frequency_penalty_milli":
				d.FrequencyPenaltyMilli = int32(c.Value)
			case "decoding_params.repetition_penalty_ppm":
				d.RepetitionPenaltyPPM = uint32(c.Value)
			default:
				t.Fatalf("wire published a range case for %q, which this projection does not know", c.Field)
			}
			payload, err := g.CanonicalJSON()
			if c.TaskOrder.Expect == "reject" {
				if err == nil {
					t.Fatalf("%s = %d is outside its frozen range and must be refused", c.Field, c.Value)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if c.GenerationParams.Expect != "accept" {
				// top_k above the chain limit: a valid order projection whose
				// Keeper payload row publishes no bytes. Nothing left to bind.
				return
			}
			if string(payload) != c.GenerationParams.PayloadUTF8 {
				t.Fatalf("canonical payload = %s\nwant %s", payload, c.GenerationParams.PayloadUTF8)
			}
			if got := GenerationParamsDigest(payload).String(); got != c.GenerationParams.DigestHex {
				t.Fatalf("generation digest = %s, want %s", got, c.GenerationParams.DigestHex)
			}
			if _, err := ParseCanonicalGenerationParams(payload); err != nil {
				t.Fatalf("ParseCanonicalGenerationParams: %v", err)
			}
		})
	}
}

// The published generation_params bytes parse back to the same context, their
// raw-bytes digest is the published digest, and a non-canonical or foreign
// encoding is refused.
func TestParseCanonicalGenerationParamsReadsThePublishedBytes(t *testing.T) {
	raw, err := wirevectors.File("task/generation_params_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		CanonicalJSON string `json:"canonical_json"`
		DigestHex     string `json:"digest_hex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	got, err := ParseCanonicalGenerationParams([]byte(vector.CanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, goldenGenerationContext()) {
		t.Fatalf("parsed = %+v, want the golden context", got)
	}
	if GenerationParamsDigest([]byte(vector.CanonicalJSON)).String() != vector.DigestHex {
		t.Fatal("raw-bytes digest differs from the published digest")
	}
	for name, bad := range map[string]string{
		"html escaped":  strings.Replace(vector.CanonicalJSON, "</s>", `\u003c/s\u003e`, 1),
		"whitespace":    strings.Replace(vector.CanonicalJSON, `{"decoding_params"`, `{ "decoding_params"`, 1),
		"unknown field": strings.Replace(vector.CanonicalJSON, `"task_type"`, `"x":1,"task_type"`, 1),
		"unhexed model": strings.Replace(vector.CanonicalJSON, `"0x55`, `"55`, 1),
		"trailing":      vector.CanonicalJSON + "{}",
	} {
		if _, err := ParseCanonicalGenerationParams([]byte(bad)); err == nil {
			t.Fatalf("%s generation_params was accepted", name)
		}
	}
}

// Each mutation must move the digest away from the published one; comparing
// against any other value would pass even if a field were not bound.
func TestGenerationContextDigestBindsEveryField(t *testing.T) {
	raw, err := wirevectors.File("task/generation_params_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		DigestHex string `json:"digest_hex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	base := goldenGenerationContext()
	if digest, err := base.Digest(); err != nil || digest.String() != vector.DigestHex {
		t.Fatalf("golden context digest = %s (%v), published %s", digest, err, vector.DigestHex)
	}
	mutations := map[string]func(*GenerationContext){
		"model":         func(g *GenerationContext) { g.ModelID = strings.Repeat("56", 32) },
		"profile":       func(g *GenerationContext) { g.ProfileVersion++ },
		"task type":     func(g *GenerationContext) { g.TaskType = 1 },
		"bucket":        func(g *GenerationContext) { g.OutputBudgetBucket++ },
		"tokens":        func(g *GenerationContext) { g.Params.MaxOutputTokens++ },
		"duration":      func(g *GenerationContext) { g.Params.MaxOutputDuration++ },
		"sampling":      func(g *GenerationContext) { g.Params.DecodingParams.SamplingEnabled = false },
		"temperature":   func(g *GenerationContext) { g.Params.DecodingParams.TemperatureMilli++ },
		"top p":         func(g *GenerationContext) { g.Params.DecodingParams.TopPPPM++ },
		"top k":         func(g *GenerationContext) { g.Params.DecodingParams.TopK++ },
		"seed":          func(g *GenerationContext) { g.Params.DecodingParams.Seed++ },
		"presence":      func(g *GenerationContext) { g.Params.DecodingParams.PresencePenaltyMilli++ },
		"frequency":     func(g *GenerationContext) { g.Params.DecodingParams.FrequencyPenaltyMilli++ },
		"repetition":    func(g *GenerationContext) { g.Params.DecodingParams.RepetitionPenaltyPPM++ },
		"stop sequence": func(g *GenerationContext) { g.Params.DecodingParams.StopSequences[1] += "!" },
		"stop token":    func(g *GenerationContext) { g.Params.DecodingParams.StopTokenIDs[1]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			g := goldenGenerationContext()
			mutate(&g)
			digest, err := g.Digest()
			if err != nil || digest.String() == vector.DigestHex {
				t.Fatalf("mutation not bound: digest=%s err=%v", digest, err)
			}
		})
	}
}

func TestGenerationContextRejectsInvalidScalarsAndLists(t *testing.T) {
	mutations := map[string]func(*GenerationContext){
		"empty model":        func(g *GenerationContext) { g.ModelID = "" },
		"invalid model UTF8": func(g *GenerationContext) { g.ModelID = "\xff" },
		"zero profile":       func(g *GenerationContext) { g.ProfileVersion = 0 },
		"zero task":          func(g *GenerationContext) { g.TaskType = 0 },
		"unsupported task":   func(g *GenerationContext) { g.TaskType = 3 },
		"zero bucket":        func(g *GenerationContext) { g.OutputBudgetBucket = 0 },
		"schema":             func(g *GenerationContext) { g.Params.SchemaVersion = 2 },
		"zero tokens":        func(g *GenerationContext) { g.Params.MaxOutputTokens = 0 },
		"zero duration":      func(g *GenerationContext) { g.Params.MaxOutputDuration = 0 },
		"temperature":        func(g *GenerationContext) { g.Params.DecodingParams.TemperatureMilli = 2001 },
		"zero top p":         func(g *GenerationContext) { g.Params.DecodingParams.TopPPPM = 0 },
		"high top p":         func(g *GenerationContext) { g.Params.DecodingParams.TopPPPM = 1000001 },
		"low presence":       func(g *GenerationContext) { g.Params.DecodingParams.PresencePenaltyMilli = -2001 },
		"high presence":      func(g *GenerationContext) { g.Params.DecodingParams.PresencePenaltyMilli = 2001 },
		"low frequency":      func(g *GenerationContext) { g.Params.DecodingParams.FrequencyPenaltyMilli = -2001 },
		"high frequency":     func(g *GenerationContext) { g.Params.DecodingParams.FrequencyPenaltyMilli = 2001 },
		"low repetition":     func(g *GenerationContext) { g.Params.DecodingParams.RepetitionPenaltyPPM = 99999 },
		"high repetition":    func(g *GenerationContext) { g.Params.DecodingParams.RepetitionPenaltyPPM = 2000001 },
		"stop UTF8":          func(g *GenerationContext) { g.Params.DecodingParams.StopSequences = []string{"\xff"} },
		"unsorted stops":     func(g *GenerationContext) { g.Params.DecodingParams.StopSequences = []string{"b", "a"} },
		"duplicate stops":    func(g *GenerationContext) { g.Params.DecodingParams.StopSequences = []string{"a", "a"} },
		"unsorted IDs":       func(g *GenerationContext) { g.Params.DecodingParams.StopTokenIDs = []uint32{2, 1} },
		"duplicate IDs":      func(g *GenerationContext) { g.Params.DecodingParams.StopTokenIDs = []uint32{1, 1} },
		"too many stops":     func(g *GenerationContext) { g.Params.DecodingParams.StopSequences = make([]string, 65535) },
		"too many IDs":       func(g *GenerationContext) { g.Params.DecodingParams.StopTokenIDs = make([]uint32, 65535) },
		"large model":        func(g *GenerationContext) { g.ModelID = strings.Repeat("x", 32<<20) },
		"escaped payload": func(g *GenerationContext) {
			g.Params.DecodingParams.StopSequences = []string{strings.Repeat("\x01", 6<<20)}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			g := goldenGenerationContext()
			mutate(&g)
			if _, err := g.Digest(); err == nil {
				t.Fatal("invalid generation context accepted")
			}
		})
	}
}

func TestGenerationContextCanonicalZerosEmptyListsAndEscapes(t *testing.T) {
	g := goldenGenerationContext()
	g.Params.MaxOutputTokens, g.Params.MaxOutputDuration = math.MaxUint64, math.MaxUint64
	g.Params.DecodingParams = DecodingParamsV1{TopPPPM: 1, RepetitionPenaltyPPM: 100000, Seed: math.MaxUint64}
	nilDigest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := g.canonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"stop_sequences":[]`, `"stop_token_ids":[]`, `"sampling_enabled":false`, `"temperature_milli":0`, `"top_k":0`, `"seed":18446744073709551615`, `"model_id":"0x` + strings.Repeat("55", 32) + `"`} {
		if !bytes.Contains(payload, []byte(part)) {
			t.Fatalf("canonical payload missing %s: %s", part, payload)
		}
	}
	g.Params.DecodingParams.StopSequences = []string{}
	g.Params.DecodingParams.StopTokenIDs = []uint32{}
	emptyDigest, err := g.Digest()
	if err != nil || emptyDigest != nilDigest {
		t.Fatalf("nil and empty differ: %v", err)
	}
	// CANONICAL_ENCODING_V1 escapes only '"', '\\', controls and U+2028/U+2029;
	// '/', '<', '>' and '&' are written as themselves.
	g.Params.DecodingParams.StopSequences = []string{"\"\\\b\t\n\f\r\x01/<>&  中"}
	payload, err = g.canonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `"stop_sequences":["\"\\\b\t\n\f\r\u0001/<>&\u2028\u2029` + "\u4e2d" + `"]`
	if !bytes.Contains(payload, []byte(want)) {
		t.Fatalf("canonical payload missing %s: %s", want, payload)
	}
	if _, err := g.Digest(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationContextCloneOwnsStopLists(t *testing.T) {
	g := goldenGenerationContext()
	clone := g.Clone()
	clone.Params.DecodingParams.StopSequences[0] = "changed"
	clone.Params.DecodingParams.StopTokenIDs[0] = 99
	if !reflect.DeepEqual(g, goldenGenerationContext()) {
		t.Fatal("clone aliases original stop lists")
	}
}

func TestTaskOrderFactsExposeGenerationForBothCarriers(t *testing.T) {
	fixture := loadNexusSignedOrderFixture(t)
	var previous *GenerationContext
	for _, carrier := range []string{string(goldenTaskOrderJSON(t)), fixture.OrderEnvelopeHex} {
		hash, facts, err := TaskOrderHashAndFactsEnvelope(carrier)
		if err != nil {
			t.Fatal(err)
		}
		if hash.String() != fixture.TaskHash {
			t.Fatalf("task hash changed: %s", hash)
		}
		if facts.Generation == nil {
			t.Fatal("order generation context missing")
		}
		g := facts.Generation
		if g.ModelID != strings.Repeat("16", 32) || g.ProfileVersion != 3 || g.TaskType != 1 || g.OutputBudgetBucket != 4 || g.Params.SchemaVersion != 1 || g.Params.MaxOutputTokens != 128 || g.Params.MaxOutputDuration != 2000 || g.Params.DecodingParams.Seed != 17 {
			t.Fatalf("wrong context: %+v", g)
		}
		if previous != nil && !reflect.DeepEqual(previous, g) {
			t.Fatalf("carrier contexts differ: %+v / %+v", previous, g)
		}
		previous = g
		encoded, err := json.Marshal(g)
		if err != nil || !bytes.Contains(encoded, []byte(`"generation_params_schema_version":1`)) {
			t.Fatalf("generation JSON = %s, err=%v", encoded, err)
		}
	}
}
