package nodewire

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// goldenTaskOrderJSON is a local V2 regression document. Its task hash was
// independently calculated with H_FIELDS_V1 framing in Node.js. The signed
// carrier tests marshal the same document through the released generated types.
func goldenTaskOrderJSON(t *testing.T) []byte {
	t.Helper()
	address, err := bech32ConvertAndEncode("trueopen", bytes.Repeat([]byte{0x11}, 20))
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	order := map[string]any{
		"schema_version": uint32(2), "chain_id": "trueopen-test-1", "user_address": address,
		"session_id": b64(0x12), "order_sequence": "7", "model_id": "model-task-order", "profile_version": uint32(3),
		"task_type": "TASK_TYPE_TEXT_GENERATION", "input_hash": b64(0x13), "input_size_bytes": "99", "input_bucket": uint32(2), "output_budget_bucket": uint32(4),
		"generation_params": map[string]any{
			"generation_params_schema_version": uint32(1), "max_output_tokens": "128", "max_output_duration": "2000",
			"decoding_params": map[string]any{
				"sampling_enabled": true, "temperature_milli": uint32(700), "top_p_ppm": uint32(900000), "top_k": uint32(40), "seed": "17",
				"presence_penalty_milli": int32(-100), "frequency_penalty_milli": int32(200), "repetition_penalty_ppm": uint32(1050000),
				"stop_sequences": []string{"END", "STOP"}, "stop_token_ids": []uint32{2, 9},
			},
		},
		"price_bid": map[string]any{"atomic_units": "3"}, "max_fee": map[string]any{"atomic_units": "1000"},
		"assignment_priority_fee": map[string]any{"atomic_units": "50"}, "tx_fee_reserve": map[string]any{"atomic_units": "100"},
		"earliest_submit_height": "20", "order_expire_height": "80", "deadline_policy": map[string]any{"latency_class": "DEADLINE_LATENCY_CLASS_STANDARD"},
		"timeout_bucket_version": "6", "session_anchor_height": "10", "session_anchor_block_hash": b64(0x14),
		"builder_set_id": "7", "builder_set_hash": b64(0x15),
	}
	raw, err := json.Marshal(order)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTaskOrderHashJSONMatchesIndependentV2Fixture(t *testing.T) {
	digest, err := TaskOrderHashJSON(string(goldenTaskOrderJSON(t)))
	if err != nil {
		t.Fatalf("TaskOrderHashJSON error = %v", err)
	}
	if got, want := hex.EncodeToString(digest[:]), "55031a8900512370d1ec72c6cf80818785471be0b7355980c8494299c18704f6"; got != want {
		t.Fatalf("TaskOrderHashJSON = %s, want %s", got, want)
	}
}

// TestTaskOrderJSONCarrierStillRequiresEnumNames guards the enum refactor: the
// numbers now live in the struct, but the JSON carrier is ProtoJSON and must go
// on spelling its enums as names.
func TestTaskOrderJSONCarrierStillRequiresEnumNames(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"task_type as number", `"task_type":"TASK_TYPE_TEXT_GENERATION"`, `"task_type":1`},
		{"task_type unknown name", `"task_type":"TASK_TYPE_TEXT_GENERATION"`, `"task_type":"TASK_TYPE_SOMETHING"`},
		{"latency_class as number", `"latency_class":"DEADLINE_LATENCY_CLASS_STANDARD"`, `"latency_class":2`},
		{"latency_class unknown name", `"latency_class":"DEADLINE_LATENCY_CLASS_STANDARD"`, `"latency_class":"DEADLINE_LATENCY_CLASS_INSTANT"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := string(goldenTaskOrderJSON(t))
			if !bytes.Contains([]byte(raw), []byte(tc.from)) {
				t.Fatalf("golden order does not contain %s", tc.from)
			}
			if _, err := TaskOrderHashJSON(string(bytes.Replace([]byte(raw), []byte(tc.from), []byte(tc.to), 1))); err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
		})
	}
}
