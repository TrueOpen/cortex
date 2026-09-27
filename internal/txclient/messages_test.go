package txclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestKeeperMessageKindsUseCanonicalTypeURLs pins every type URL Cortex can emit
// to the rpc request name the frozen task.v1.Msg / hub.v1.Msg services
// register. A rename upstream must break this test, not a devnet transaction.
func TestKeeperMessageKindsUseCanonicalTypeURLs(t *testing.T) {
	tests := []struct {
		kind Kind
		want string
	}{
		{MsgRegisterModelProfile, "/hub.v1.MsgRegisterModelProfile"},
		{MsgDeclareModelSupport, "/hub.v1.MsgDeclareModelSupport"},
		{MsgBatchConfirmModelSupport, "/hub.v1.MsgBatchConfirmModelSupport"},
		{MsgSubmitInferReceipt, "/task.v1.MsgSubmitInferReceipt"},
		{MsgSubmitVerifyCommit, "/task.v1.MsgSubmitVerifyCommit"},
		{MsgSubmitVerifyResult, "/task.v1.MsgSubmitVerifyResult"},
		{MsgSettleTask, "/task.v1.MsgSettleTask"},
		{MsgSweepDeadline, "/task.v1.MsgSweepDeadline"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("kind = %q, want %q", got, tt.want)
		}
		if !tt.kind.Valid() {
			t.Errorf("kind %q is not valid", tt.kind)
		}
	}
}

func TestModelSupportUsesCurrentOperatorOnlyNodeProtoJSON(t *testing.T) {
	message := DeclareModelSupportMessage{
		OperatorAddress: "trueopen1operator", ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
		InferenceCapability: true, VerificationCapability: true,
	}
	payload, err := MarshalMessage(MsgDeclareModelSupport, message)
	if err != nil {
		t.Fatalf("MarshalMessage returned error: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	wantFields := []string{"operator_address", "model_id", "inference_capability", "verification_capability"}
	if len(object) != len(wantFields) {
		t.Fatalf("fields = %v, want exactly %v", object, wantFields)
	}
	for _, field := range wantFields {
		if _, ok := object[field]; !ok {
			t.Fatalf("missing field %q in %s", field, payload)
		}
	}
	var decoded DeclareModelSupportMessage
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded != message {
		t.Fatalf("decoded = %#v, want %#v", decoded, message)
	}
	for name, raw := range map[string]string{"quoted": `"7"`, "zero padded": `07`, "negative": `-1`, "overflow": `4294967296`} {
		t.Run(name, func(t *testing.T) {
			var value ProtoUint32
			if err := json.Unmarshal([]byte(raw), &value); err == nil {
				t.Fatalf("Unmarshal(%s) error = nil, want uint32 rejection", raw)
			}
		})
	}
}

func TestRegisterModelProfileUsesCurrentNestedProtoJSON(t *testing.T) {
	message := validRegisterModelProfileMessage()
	payload, err := MarshalMessage(MsgRegisterModelProfile, message)
	if err != nil {
		t.Fatalf("MarshalMessage returned error: %v", err)
	}
	var envelope struct {
		ProposerAddress     string                     `json:"proposer_address"`
		Profile             map[string]json.RawMessage `json:"profile"`
		RegistrantSignature json.RawMessage            `json:"registrant_signature"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if envelope.ProposerAddress != message.ProposerAddress || string(envelope.Profile["profile_version"]) != `1` || string(envelope.Profile["challenge_open_window_blocks"]) != `"1800"` {
		t.Fatalf("registration envelope = %s", payload)
	}
	wantHash, _ := json.Marshal(base64.StdEncoding.EncodeToString(bytesOf(0xab, 32)))
	if string(envelope.Profile["manifest_hash"]) != string(wantHash) {
		t.Fatalf("manifest_hash = %s, want %s", envelope.Profile["manifest_hash"], wantHash)
	}
	if envelope.RegistrantSignature != nil {
		t.Fatal("retired registrant_signature present")
	}
	var decoded RegisterModelProfileMessage
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded.Profile.ManifestHash.Hex() != strings.Repeat("ab", 32) {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestRegisterModelProfileRejectsIncompleteOrNonCanonicalProjection(t *testing.T) {
	tests := map[string]func(*RegisterModelProfileMessage){
		"top k mismatch":           func(message *RegisterModelProfileMessage) { message.Profile.RequiredTopK++ },
		"invalid previous version": func(message *RegisterModelProfileMessage) { message.Profile.PreviousProfileVersion = 1 },
		"missing challenge window": func(message *RegisterModelProfileMessage) { message.Profile.ChallengeOpenWindowBlocks = 0 },
		"wrong fee denom":          func(message *RegisterModelProfileMessage) { message.Profile.RegistrationFee.Denom = "uatom" },
		"missing evidence schema": func(message *RegisterModelProfileMessage) {
			message.Profile.VerificationProfile.EvidenceSchema = EvidenceSchemaMessage{}
		},
		"unsupported task type": func(message *RegisterModelProfileMessage) {
			message.Profile.TaskTypes = []string{"TASK_TYPE_UNSPECIFIED"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			message := validRegisterModelProfileMessage()
			mutate(&message)
			if _, err := MarshalMessage(MsgRegisterModelProfile, message); err == nil {
				t.Fatal("MarshalMessage error = nil, want projection rejection")
			}
		})
	}
}

func TestValidateModelProfileProjectionDoesNotRequireTransactionSignature(t *testing.T) {
	message := validRegisterModelProfileMessage()
	if err := ValidateModelProfileProjection(message.Profile); err != nil {
		t.Fatalf("ValidateModelProfileProjection returned error: %v", err)
	}
	message.Profile.RequiredTopK++
	if err := ValidateModelProfileProjection(message.Profile); err == nil {
		t.Fatal("ValidateModelProfileProjection error = nil, want projection rejection")
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

// TestMarshalKeeperMessageUsesProtoJSONFieldNames walks every frozen Task
// message field by field: the payload must carry exactly the frozen field names
// and nothing else, uint32 fields must be JSON numbers and uint64 fields must be
// decimal strings.
func TestMarshalKeeperMessageUsesProtoJSONFieldNames(t *testing.T) {
	tests := []struct {
		name     string
		kind     Kind
		value    any
		required []string
		nested   string
		fields   []string
	}{
		{name: "register current model profile", kind: MsgRegisterModelProfile, value: validRegisterModelProfileMessage(), required: []string{"proposer_address", "profile"}},
		{name: "model support", kind: MsgDeclareModelSupport, value: DeclareModelSupportMessage{
			OperatorAddress: "trueopen1operator", ModelID: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
			InferenceCapability: true, VerificationCapability: true,
		}, required: []string{"operator_address", "model_id", "inference_capability", "verification_capability"}},
		{
			name: "submit infer receipt", kind: MsgSubmitInferReceipt, value: validSubmitInferReceiptMessage(),
			required: []string{"receipt", "submitter_address"}, nested: "receipt",
			fields: []string{
				"schema_version", "chain_id", "task_id", "task_hash", "worker_operator_address",
				"service_authorization_nonce", "generation_params_digest", "output_hash",
				"output_size_bytes", "required_evidence_commitments", "expiry_height", "service_signature", "generated_token_count", "output_leaf_count",
				"output_key_commitment", "worker_token_key_commitment", "worker_value_key_commitment", "ciphertext_output_root",
			},
		},
		{
			name: "submit verify commit", kind: MsgSubmitVerifyCommit, value: validSubmitVerifyCommitMessage(),
			required: []string{"commit", "submitter_address"}, nested: "commit",
			fields: []string{
				"schema_version", "chain_id", "task_id", "verify_round", "verifier_operator_address",
				"service_authorization_nonce", "commit_hash", "expiry_height", "service_signature",
			},
		},
		{
			name: "submit verify result", kind: MsgSubmitVerifyResult, value: validSubmitVerifyResultMessage(),
			required: []string{"receipt", "submitter_address"}, nested: "receipt",
			fields: []string{
				"schema_version", "chain_id", "task_id", "verify_round", "verifier_operator_address",
				"service_authorization_nonce", "generation_params_digest", "metric_root", "metric_summary",
				"aggregate_proof_hash", "verifier_evidence_bundle_hash", "verifier_evidence_manifest_size_bytes", "salt", "expiry_height", "service_signature",
				"verifier_value_root", "metric_leaf_count", "verifier_evidence_key_commitment",
			},
		},
		{
			name: "settle task", kind: MsgSettleTask,
			value:    SettleTaskMessage{TaskID: ProtoBytes32(strings.Repeat("ab", 32)), SubmitterAddress: "trueopen1settler"},
			required: []string{"task_id", "submitter_address"},
		},
		{
			name: "sweep deadline", kind: MsgSweepDeadline,
			value: SweepDeadlineMessage{
				Locator:          DeadlineLocatorMessage{Task: &TaskDeadlineLocatorMessage{TaskID: ProtoBytes32(strings.Repeat("ab", 32)), DeadlineKind: DeadlineKindWorkerInfer}},
				SubmitterAddress: "trueopen1settler",
			},
			required: []string{"locator", "submitter_address"}, nested: "locator", fields: []string{"task"},
		},
	}

	uint32Fields := map[string]bool{"schema_version": true, "verify_round": true, "profile_version": true}
	uint64Fields := map[string]bool{"service_authorization_nonce": true, "output_size_bytes": true, "expiry_height": true, "encoded_size_bytes": true}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := MarshalMessage(tt.kind, tt.value)
			if err != nil {
				t.Fatalf("MarshalMessage() error = %v", err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(payload, &object); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			for _, field := range tt.required {
				if _, ok := object[field]; !ok {
					t.Errorf("payload missing %q: %s", field, payload)
				}
			}
			if len(tt.required) > 0 && len(object) != len(tt.required) {
				t.Errorf("payload fields = %d, want exactly %v: %s", len(object), tt.required, payload)
			}
			if tt.nested == "" {
				return
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(object[tt.nested], &body); err != nil {
				t.Fatalf("Unmarshal(%s) error = %v", tt.nested, err)
			}
			if len(body) != len(tt.fields) {
				t.Errorf("%s fields = %v, want exactly %v", tt.nested, body, tt.fields)
			}
			for _, field := range tt.fields {
				raw, ok := body[field]
				if !ok {
					t.Errorf("%s missing frozen field %q: %s", tt.nested, field, object[tt.nested])
					continue
				}
				if uint32Fields[field] && raw[0] == '"' {
					t.Errorf("%s.%s = %s, want a ProtoJSON uint32 number", tt.nested, field, raw)
				}
				if uint64Fields[field] && raw[0] != '"' {
					t.Errorf("%s.%s = %s, want a ProtoJSON uint64 decimal string", tt.nested, field, raw)
				}
			}
		})
	}
}

func TestRegisterMessagesRejectObsoleteAndNonCanonicalFields(t *testing.T) {
	legacyCombined := `{"model_id":"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a","profile_version":"v1","manifest_hash":"` + strings.Repeat("ab", 32) + `"}`
	if err := ValidateMessagePayload(MsgRegisterModelProfile, []byte(legacyCombined)); err == nil {
		t.Fatal("legacy flat combined registration payload was accepted")
	}
}

func TestMarshalKeeperMessageRejectsWrongTypeAndMissingFields(t *testing.T) {
	if _, err := MarshalMessage(MsgSubmitVerifyCommit, SweepDeadlineMessage{}); err == nil {
		t.Fatalf("MarshalMessage() error = nil, want kind/type mismatch")
	}
	if _, err := MarshalMessage(MsgSubmitVerifyCommit, SubmitVerifyCommitMessage{}); err == nil {
		t.Fatalf("MarshalMessage() error = nil, want required field error")
	}
}

// TestVerifierTaskMessagesBindStableOperatorIdentity keeps the two identities
// separate: verifier_operator_address inside the frozen body is the stable
// operator, while submitter_address is the current Cortex service account.
func TestVerifierTaskMessagesBindStableOperatorIdentity(t *testing.T) {
	commit := validSubmitVerifyCommitMessage()
	commit.Commit.VerifierOperatorAddress = "trueopen1operator"
	commit.SubmitterAddress = "trueopen1service"
	result := validSubmitVerifyResultMessage()
	result.Receipt.VerifierOperatorAddress = "trueopen1operator"
	result.SubmitterAddress = "trueopen1service"
	for _, test := range []struct {
		kind  Kind
		value any
	}{
		{MsgSubmitVerifyCommit, commit},
		{MsgSubmitVerifyResult, result},
	} {
		if _, err := MarshalMessage(test.kind, test.value); err != nil {
			t.Fatalf("MarshalMessage(%s) rejected separate current service and stable operator identities: %v", test.kind, err)
		}
	}
}

// TestRetiredTaskMessagesHaveNoTypedEncoderOrDecoder covers every task.v1
// name the frozen tx.proto de-registers: none of them may encode, decode or
// broadcast.
//
// MsgSubmitFullResultReveal is in the list for a slightly different reason than
// the rest: it was registered once and then removed by keeper-interface-contract.md §10.9a,
// which reserved its msg number 18 as "must not be reused". Cortex carried a
// Kind, a typed message, a validator and a Keeper confirmation branch for it long
// after the chain stopped accepting it, which read like a live route. This case
// is what keeps it from being reintroduced.
func TestRetiredTaskMessagesHaveNoTypedEncoderOrDecoder(t *testing.T) {
	for _, kind := range []Kind{
		"/task.v1.MsgSubmitFullResultReveal",
		"/task.v1.MsgInferReceiptCommitOnly",
		"/task.v1.MsgCommit",
		"/task.v1.MsgResult",
		"/task.v1.MsgWorkerReveal",
		"/task.v1.MsgSettle",
		"/task.v1.MsgSweepExpiredTask",
		"/task.v1.MsgChallengeCommit",
		"/task.v1.MsgChallengeResult",
		"/task.v1.MsgSubmitChallengeFullResultReveal",
		"/task.v1.MsgOutputHashMismatchProof",
		"/task.v1.MsgSubmitFraudProof",
		"/task.v1.MsgSubmitFaultProof",
		"/task.v1.MsgSubmitVerdictFraudProof",
	} {
		if kind.Valid() {
			t.Fatalf("de-registered Task kind %s unexpectedly registered", kind)
		}
		if _, err := MarshalMessage(kind, struct{}{}); err == nil {
			t.Fatalf("MarshalMessage(%s) unexpectedly succeeded", kind)
		}
		if err := ValidateMessagePayload(kind, []byte(`{}`)); err == nil {
			t.Fatalf("ValidateMessagePayload(%s) unexpectedly succeeded", kind)
		}
	}
}

func TestValidateRequestRejectsUnknownAndLegacyPayloadFields(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"task_id":"task-1","sweep_kind":"VERIFY_DEADLINE","chain_verdict":"PASS"}`),
		[]byte(`{"version":"settlement-envelope-v1","task_id":"task-1"}`),
		[]byte("not-json"),
	} {
		if err := ValidateRequest(Request{TaskID: "task-1", Kind: MsgSweepDeadline, Payload: payload}); err == nil {
			t.Fatalf("ValidateRequest accepted non-canonical payload %s", payload)
		}
	}
}

func TestModelSupportMessagesRejectLegacyRoleAndDetachedSignatureFields(t *testing.T) {
	for name, legacyDeclare := range map[string][]byte{
		"role":               []byte(`{"operator_address":"trueopen1operator","provider_address":"node-1","role":"WORKER","model_id":"0101010101010101010101010101010101010101010101010101010101010101","profile_version":1,"inference_capability":true,"verification_capability":false}`),
		"detached signature": []byte(`{"operator_address":"trueopen1operator","model_id":"0101010101010101010101010101010101010101010101010101010101010101","profile_version":1,"inference_capability":true,"verification_capability":false,"support_signature":"` + strings.Repeat("ab", 64) + `"}`),
	} {
		if err := ValidateMessagePayload(MsgDeclareModelSupport, legacyDeclare); err == nil {
			t.Fatalf("%s declaration was accepted", name)
		}
	}
	legacyBatch := []byte(`{"submitter_address":"trueopen1operator","epoch_index":"7","confirmations":[{"worker_address":"node-1","support_mode":"WORKER","supported_profiles":[{"model_id":"0101010101010101010101010101010101010101010101010101010101010101","profile_version":"v1"}],"worker_signature":"` + strings.Repeat("ab", 64) + `"}]}`)
	if err := ValidateMessagePayload(MsgBatchConfirmModelSupport, legacyBatch); err == nil {
		t.Fatal("legacy role-bearing support confirmation was accepted")
	}
	// Support is model-scoped: a declaration naming a profile is refused.
	withProfile := []byte(`{"operator_address":"trueopen1operator","model_id":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `","profile_version":1,"inference_capability":true,"verification_capability":false}`)
	if err := ValidateMessagePayload(MsgDeclareModelSupport, withProfile); err == nil {
		t.Fatal("a profile-scoped support declaration was accepted")
	}
}

func TestBatchModelSupportRejectsNonCanonicalOrdering(t *testing.T) {
	signature := strings.Repeat("ab", 64)
	confirmation := func(nodeID string, models ...ProtoBytes32) ModelSupportConfirmation {
		return ModelSupportConfirmation{OperatorAddress: nodeID, SupportedModels: models, ServiceAuthorizationNonce: 3, ExpiryHeight: 101, ServiceSignature: ProtoBytes(signature)}
	}
	tests := []struct {
		name          string
		confirmations []ModelSupportConfirmation
	}{
		{
			name: "unsorted confirmations",
			confirmations: []ModelSupportConfirmation{
				confirmation("worker-b", ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")),
				confirmation("worker-a", ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")),
			},
		},
		{
			name: "duplicate confirmations",
			confirmations: []ModelSupportConfirmation{
				confirmation("worker-a", ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")),
				confirmation("worker-a", ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")),
			},
		},
		{
			name: "unsorted models",
			confirmations: []ModelSupportConfirmation{
				confirmation("worker-a",
					ProtoBytes32("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
					ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
				),
			},
		},
		{
			name: "duplicate models",
			confirmations: []ModelSupportConfirmation{
				confirmation("worker-a",
					ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
					ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
				),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MarshalMessage(MsgBatchConfirmModelSupport, BatchConfirmModelSupportMessage{
				SubmitterAddress: "trueopen1submitter",
				EpochIndex:       7,
				Confirmations:    tt.confirmations,
			})
			if err == nil {
				t.Fatalf("MarshalMessage accepted non-canonical ordering")
			}
		})
	}
}

// TestSubmitInferReceiptRefusesUnavailableHash32 pins the chain encoder's
// fail-closed gate on the two Hash32 fields Cortex has no source for. Both the
// unset field and 32 zero bytes must be refused with the field's own sentinel:
// the frozen wire frames a Hash32 unconditionally, so it has no "absent" value,
// and a zero hash is shape-valid all the way into a signed transaction. The
// sentinel identity is what the caller uses to tell "Cortex cannot know this yet"
// from "this message is malformed", so errors.Is has to keep working through
// MarshalMessage.
func TestSubmitInferReceiptRefusesUnavailableHash32(t *testing.T) {
	zero := ProtoBytes32(strings.Repeat("00", 32))
	for _, tc := range []struct {
		name   string
		mutate func(*InferReceiptMessage)
		want   error
	}{
		{"unset task_hash", func(r *InferReceiptMessage) { r.TaskHash = "" }, ErrTaskHashUnavailable},
		{"zero task_hash", func(r *InferReceiptMessage) { r.TaskHash = zero }, ErrTaskHashUnavailable},
		{"unset generation_params_digest", func(r *InferReceiptMessage) { r.GenerationParamsDigest = "" }, ErrGenerationParamsDigestUnavailable},
		{"zero generation_params_digest", func(r *InferReceiptMessage) { r.GenerationParamsDigest = zero }, ErrGenerationParamsDigestUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := validSubmitInferReceiptMessage()
			tc.mutate(&message.Receipt)
			payload, err := MarshalMessage(MsgSubmitInferReceipt, message)
			if err == nil {
				t.Fatalf("MarshalMessage encoded %s: %s", tc.name, payload)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	// The same rule applies to the other frozen wire carrying
	// generation_params_digest; the sentinel documents itself as covering both.
	result := validSubmitVerifyResultMessage()
	result.Receipt.GenerationParamsDigest = zero
	if _, err := MarshalMessage(MsgSubmitVerifyResult, result); !errors.Is(err, ErrGenerationParamsDigestUnavailable) {
		t.Fatalf("verify result error = %v, want ErrGenerationParamsDigestUnavailable", err)
	}
}
