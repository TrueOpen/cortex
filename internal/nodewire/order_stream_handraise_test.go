package nodewire_test

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func prereleaseGolden(t *testing.T, path, name string) goldenVector {
	t.Helper()
	data, err := wirevectors.File(path)
	if err != nil {
		t.Fatal(err)
	}
	var file goldenFixture
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	for _, vector := range file.Vectors {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("%s publishes no %s vector", path, name)
	return goldenVector{}
}

func TestHandraisesV030ReproducePublishedVectors(t *testing.T) {
	worker := prereleaseGolden(t, "task/task_domains_v1.json", "worker_handraise_v1")
	workerHandraise := nodewire.WorkerHandraiseV1{
		SchemaVersion:             uint32(fieldUint(t, worker, 0, "schema_version")),
		ChainID:                   fieldString(t, worker, 1, "chain_id"),
		TaskID:                    fieldBytes(t, worker, 2, "task_id"),
		TaskHash:                  fieldBytes(t, worker, 3, "task_hash"),
		ModelID:                   fieldBytes(t, worker, 4, "model_id"),
		ProfileVersion:            uint32(fieldUint(t, worker, 5, "profile_version")),
		Member:                    memberRef(t, worker, 6),
		Duty:                      nodewire.Duty(fieldUint(t, worker, 7, "duty")),
		ServiceAuthorizationNonce: fieldUint(t, worker, 8, "service_authorization_nonce"),
		ExpiryHeight:              fieldUint(t, worker, 9, "expiry_height"),
		RecipientPubkey:           fieldBytes(t, worker, 10, "recipient_pubkey"),
	}
	assertPreimageAndDigest(t, worker, func() ([]byte, error) {
		return nodewire.WorkerHandraiseSigningPreimage(workerHandraise)
	})

	verifier := prereleaseGolden(t, "task/task_domains_v1.json", "verifier_handraise_v1")
	verifierHandraise := nodewire.VerifierHandraiseV1{
		SchemaVersion:             uint32(fieldUint(t, verifier, 0, "schema_version")),
		ChainID:                   fieldString(t, verifier, 1, "chain_id"),
		TaskID:                    fieldBytes(t, verifier, 2, "task_id"),
		VerifyRound:               uint32(fieldUint(t, verifier, 3, "verify_round")),
		InferReceiptHash:          fieldBytes(t, verifier, 4, "infer_receipt_hash"),
		OutputHash:                fieldBytes(t, verifier, 5, "output_hash"),
		ModelID:                   fieldBytes(t, verifier, 6, "model_id"),
		ProfileVersion:            uint32(fieldUint(t, verifier, 7, "profile_version")),
		Member:                    memberRef(t, verifier, 8),
		Duty:                      nodewire.Duty(fieldUint(t, verifier, 9, "duty")),
		ServiceAuthorizationNonce: fieldUint(t, verifier, 10, "service_authorization_nonce"),
		ExpiryHeight:              fieldUint(t, verifier, 11, "expiry_height"),
		RecipientPubkey:           fieldBytes(t, verifier, 12, "recipient_pubkey"),
	}
	assertPreimageAndDigest(t, verifier, func() ([]byte, error) {
		return nodewire.VerifierHandraiseSigningPreimage(verifierHandraise)
	})

	withKey := workerHandraise
	withKey.RecipientPubkey = []byte{2}
	if _, err := nodewire.WorkerHandraiseSigningDigest(withKey); err == nil {
		t.Fatal("a plaintext worker handraise accepted a recipient_pubkey")
	}
	textModel := verifierHandraise
	textModel.ModelID = []byte(hex.EncodeToString(textModel.ModelID))
	if _, err := nodewire.VerifierHandraiseSigningDigest(textModel); err == nil {
		t.Fatal("a verifier handraise accepted a text model_id")
	}
}

func TestOutputStreamHeaderReproducesPublishedVector(t *testing.T) {
	v := prereleaseGolden(t, "task/output_stream_header_v1.json", "output_stream_header_v2_plaintext")
	header := nodewire.OutputStreamHeaderV2{
		ChainID:             fieldString(t, v, 0, "chain_id"),
		TaskHash:            fieldBytes(t, v, 1, "task_hash"),
		Attempt:             uint32(fieldUint(t, v, 2, "attempt")),
		StreamInstance:      uint32(fieldUint(t, v, 3, "stream_instance")),
		UserRecipientPubkey: fieldBytes(t, v, 4, "user_recipient_pubkey"),
		OutputKeyCommitment: fieldBytes(t, v, 5, "output_key_commitment"),
		KeyPackageHash:      fieldBytes(t, v, 6, "key_package_hash"),
	}
	if len(v.Fields) != 7 || v.Domain != nodewire.DomainOutputStreamHeaderV1 {
		t.Fatal("the header vector must be seven fields under TRUEOPEN_OUTPUT_STREAM_HEADER_V1")
	}
	assertPreimageAndDigest(t, v, func() ([]byte, error) { return nodewire.OutputStreamHeaderSigningPreimage(header) })

	nonZero := make([]byte, 32)
	nonZero[31] = 1
	// The fixture's rejected_cases.
	for name, mutate := range map[string]func(*nodewire.OutputStreamHeaderV2){
		"attempt != 0":                   func(h *nodewire.OutputStreamHeaderV2) { h.Attempt = 1 },
		"stream_instance != 1":           func(h *nodewire.OutputStreamHeaderV2) { h.StreamInstance = 2 },
		"nonempty user_recipient_pubkey": func(h *nodewire.OutputStreamHeaderV2) { h.UserRecipientPubkey = []byte{2} },
		"nonzero output_key_commitment":  func(h *nodewire.OutputStreamHeaderV2) { h.OutputKeyCommitment = nonZero },
		"nonzero key_package_hash":       func(h *nodewire.OutputStreamHeaderV2) { h.KeyPackageHash = nonZero },
	} {
		bad := header
		mutate(&bad)
		if _, err := nodewire.OutputStreamHeaderSigningDigest(bad); err == nil {
			t.Errorf("%s: OutputStreamHeaderSigningDigest() error = nil", name)
		}
	}
}

// orderNode is one field of a task order vector. Values stay raw JSON because
// the decoding params carry negative int32s and a "bool" key.
type orderNode struct {
	Name   string          `json:"name"`
	Value  json.RawMessage `json:"value"`
	Bool   *bool           `json:"bool"`
	UTF8   string          `json:"utf8"`
	Hex    string          `json:"hex"`
	Fields []orderNode     `json:"fields"`
}

type orderVector struct {
	Name      string      `json:"name"`
	Fields    []orderNode `json:"fields"`
	DigestHex string      `json:"digest_hex"`
	Mutations []struct {
		FieldPath string `json:"field_path"`
		DigestHex string `json:"digest_hex"`
	} `json:"mutations"`
}

type orderReader struct {
	t      *testing.T
	fields []orderNode
	next   int
}

func (r *orderReader) take(name string) orderNode {
	r.t.Helper()
	if r.next >= len(r.fields) || r.fields[r.next].Name != name {
		r.t.Fatalf("order field %d is not %q", r.next, name)
	}
	r.next++
	return r.fields[r.next-1]
}

func (r *orderReader) u64(name string) uint64 {
	r.t.Helper()
	v, err := strconv.ParseUint(string(r.take(name).Value), 10, 64)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return v
}

func (r *orderReader) i32(name string) int32 {
	r.t.Helper()
	v, err := strconv.ParseInt(string(r.take(name).Value), 10, 32)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return int32(v)
}

func (r *orderReader) bytes(name string) []byte {
	r.t.Helper()
	raw, err := hex.DecodeString(r.take(name).Hex)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	return raw
}

func (r *orderReader) sub(name string) *orderReader {
	return &orderReader{t: r.t, fields: r.take(name).Fields}
}

func parseTaskOrderV3(t *testing.T, vector orderVector) nodewire.TaskOrderV3 {
	t.Helper()
	if len(vector.Fields) != 28 {
		t.Fatalf("%s has %d fields, want 28", vector.Name, len(vector.Fields))
	}
	r := &orderReader{t: t, fields: vector.Fields}
	var o nodewire.TaskOrderV3
	o.SchemaVersion = uint32(r.u64("schema_version"))
	o.ChainID = r.take("chain_id").UTF8
	user, err := nodewire.CanonicalOperatorAddressString("trueopen", r.bytes("user_address"))
	if err != nil {
		t.Fatal(err)
	}
	o.UserAddress = user
	o.SessionID = r.bytes("session_id")
	o.OrderSequence = r.u64("order_sequence")
	o.ModelID = r.bytes("model_id")
	o.ProfileVersion = uint32(r.u64("profile_version"))
	o.TaskType = uint32(r.u64("task_type"))
	o.InputHash = r.bytes("input_hash")
	o.InputSizeBytes = r.u64("input_size_bytes")
	o.InputBucket = uint32(r.u64("input_bucket"))
	o.OutputBudgetBucket = uint32(r.u64("output_budget_bucket"))
	g := r.sub("generation_params")
	o.GenerationParams.SchemaVersion = uint32(g.u64("generation_params_schema_version"))
	o.GenerationParams.MaxOutputTokens = g.u64("max_output_tokens")
	o.GenerationParams.MaxOutputDuration = g.u64("max_output_duration")
	d := g.sub("decoding_params")
	p := &o.GenerationParams.DecodingParams
	p.SamplingEnabled = *d.take("sampling_enabled").Bool
	p.TemperatureMilli = uint32(d.u64("temperature_milli"))
	p.TopPPPM = uint32(d.u64("top_p_ppm"))
	p.TopK = uint32(d.u64("top_k"))
	p.Seed = d.u64("seed")
	p.PresencePenaltyMilli = d.i32("presence_penalty_milli")
	p.FrequencyPenaltyMilli = d.i32("frequency_penalty_milli")
	p.RepetitionPenaltyPPM = uint32(d.u64("repetition_penalty_ppm"))
	stops := d.sub("stop_sequences")
	for i := range int(stops.u64("count")) {
		p.StopSequences = append(p.StopSequences, stops.take("stop_sequences["+strconv.Itoa(i)+"]").UTF8)
	}
	tokens := d.sub("stop_token_ids")
	for i := range int(tokens.u64("count")) {
		p.StopTokenIDs = append(p.StopTokenIDs, uint32(tokens.u64("stop_token_ids["+strconv.Itoa(i)+"]")))
	}
	o.PriceBid = r.sub("price_bid").take("atomic_units").UTF8
	o.MaxFee = r.sub("max_fee").take("atomic_units").UTF8
	o.AssignmentPriorityFee = r.sub("assignment_priority_fee").take("atomic_units").UTF8
	o.TxFeeReserve = r.sub("tx_fee_reserve").take("atomic_units").UTF8
	o.EarliestSubmitHeight = r.u64("earliest_submit_height")
	o.OrderExpireHeight = r.u64("order_expire_height")
	o.LatencyClass = uint32(r.sub("deadline_policy").u64("latency_class"))
	o.TimeoutBucketVersion = r.u64("timeout_bucket_version")
	o.SessionAnchorHeight = r.u64("session_anchor_height")
	o.SessionAnchorBlockHash = r.bytes("session_anchor_block_hash")
	o.BuilderSetID = r.take("builder_set_id").UTF8
	o.BuilderSetHash = r.bytes("builder_set_hash")
	o.PayloadMode = uint32(r.u64("payload_mode"))
	o.InputKeyCommitment = r.bytes("input_key_commitment")
	o.UserRecipientPubkey = r.bytes("user_recipient_pubkey")
	return o
}

func TestTaskOrderV3ReproducesPublishedVectors(t *testing.T) {
	data, err := wirevectors.File("task/task_order_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []orderVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, vector := range file.Vectors {
		if len(vector.Fields) != 28 {
			continue // the ORDER_OPENING_V2 vectors are not a Cortex derivation
		}
		order := parseTaskOrderV3(t, vector)
		digest, err := nodewire.TaskOrderV3Hash(order)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if hex.EncodeToString(digest[:]) != vector.DigestHex {
			t.Fatalf("%s = %x, published %s", vector.Name, digest, vector.DigestHex)
		}
		// Integer mutations bump one field by one; each must reproduce the
		// published digest, which pins that field's position and width.
		mutated := map[string]func(*nodewire.TaskOrderV3){
			"order_sequence":         func(o *nodewire.TaskOrderV3) { o.OrderSequence++ },
			"profile_version":        func(o *nodewire.TaskOrderV3) { o.ProfileVersion++ },
			"input_size_bytes":       func(o *nodewire.TaskOrderV3) { o.InputSizeBytes++ },
			"input_bucket":           func(o *nodewire.TaskOrderV3) { o.InputBucket++ },
			"output_budget_bucket":   func(o *nodewire.TaskOrderV3) { o.OutputBudgetBucket++ },
			"order_expire_height":    func(o *nodewire.TaskOrderV3) { o.OrderExpireHeight++ },
			"timeout_bucket_version": func(o *nodewire.TaskOrderV3) { o.TimeoutBucketVersion++ },
			"session_anchor_height":  func(o *nodewire.TaskOrderV3) { o.SessionAnchorHeight++ },
		}
		for _, mutation := range vector.Mutations {
			mutate, ok := mutated[mutation.FieldPath]
			if !ok {
				continue
			}
			bumped := order
			mutate(&bumped)
			got, err := nodewire.TaskOrderV3Hash(bumped)
			if err != nil {
				t.Fatalf("%s %s: %v", vector.Name, mutation.FieldPath, err)
			}
			if hex.EncodeToString(got[:]) != mutation.DigestHex {
				t.Fatalf("%s mutation %s = %x, published %s", vector.Name, mutation.FieldPath, got, mutation.DigestHex)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no published mutation was reproduced")
	}
}

func TestTaskOrderV3RefusesNonPlaintextOrders(t *testing.T) {
	data, err := wirevectors.File("task/task_order_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []orderVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	order := parseTaskOrderV3(t, file.Vectors[0])
	nonZero := make([]byte, 32)
	nonZero[0] = 1
	for name, mutate := range map[string]func(*nodewire.TaskOrderV3){
		"encrypted payload mode":         func(o *nodewire.TaskOrderV3) { o.PayloadMode = 2 },
		"nonzero input_key_commitment":   func(o *nodewire.TaskOrderV3) { o.InputKeyCommitment = nonZero },
		"nonempty user_recipient_pubkey": func(o *nodewire.TaskOrderV3) { o.UserRecipientPubkey = []byte{2} },
		"V2 schema version":              func(o *nodewire.TaskOrderV3) { o.SchemaVersion = 2 },
		"text model id":                  func(o *nodewire.TaskOrderV3) { o.ModelID = []byte("hf-Qwen/Qwen3-8B") },
	} {
		bad := order
		mutate(&bad)
		if _, err := nodewire.TaskOrderV3Hash(bad); err == nil {
			t.Errorf("%s: TaskOrderV3Hash() error = nil", name)
		}
	}
}
