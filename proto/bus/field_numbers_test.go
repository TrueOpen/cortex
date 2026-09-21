package bus_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
	bustaskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
)

// Pin the active task-control field numbers from wire v0.4.0.
func TestMirrorFieldNumbersAreFrozen(t *testing.T) {
	assert := func(m proto.Message, want map[string]int32) {
		t.Helper()
		fields := m.ProtoReflect().Descriptor().Fields()
		if fields.Len() != len(want) {
			t.Fatalf("%s has %d fields, want %d", m.ProtoReflect().Descriptor().FullName(), fields.Len(), len(want))
		}
		for name, number := range want {
			field := fields.ByName(protoreflect.Name(name))
			if field == nil {
				t.Fatalf("%s lacks field %s", m.ProtoReflect().Descriptor().FullName(), name)
			}
			if int32(field.Number()) != number {
				t.Fatalf("%s.%s = field %d, want %d", m.ProtoReflect().Descriptor().FullName(), name, field.Number(), number)
			}
		}
	}
	assert(&busv1.BusEnvelopeV1{}, map[string]int32{
		"schema_version": 1, "chain_id": 2, "subject": 3, "kind": 4,
		"sender_participant_type": 5, "sender_operator_address": 6,
		"service_authorization_nonce": 7, "message_id": 8, "nonce": 9,
		"issued_at_unix_ms": 10, "expires_at_unix_ms": 11, "payload_type": 12,
		"payload": 13, "payload_digest": 14, "service_signature": 15,
	})
	assert(&bustaskv1.WorkerHandraiseV1{}, map[string]int32{
		"schema_version": 1, "chain_id": 2, "task_id": 3, "task_hash": 4,
		"model_id": 5, "profile_version": 6, "member": 7, "duty": 8,
		"service_authorization_nonce": 9, "expiry_height": 10, "service_signature": 11,
	})
	assert(&bustaskv1.VerifierHandraiseV1{}, map[string]int32{
		"schema_version": 1, "chain_id": 2, "task_id": 3, "verify_round": 4,
		"infer_receipt_hash": 5, "output_hash": 6, "model_id": 7, "profile_version": 8,
		"member": 9, "duty": 10, "service_authorization_nonce": 11,
		"expiry_height": 12, "service_signature": 13,
	})
	assert(&bustaskv1.ResultReceiptV2{}, map[string]int32{
		"schema_version": 1, "chain_id": 2, "task_id": 3, "verify_round": 4,
		"verifier_operator_address": 5, "service_authorization_nonce": 6,
		"generation_params_digest": 7, "metric_root": 8, "metric_summary": 9,
		"aggregate_proof_hash": 10, "verifier_evidence_bundle_hash": 11,
		"verifier_evidence_manifest_size_bytes": 12, "salt": 13,
		"expiry_height": 14, "service_signature": 15,
	})
	assert(&bustaskv1.SignedOrderV2{}, map[string]int32{
		"order": 1, "signature_scheme": 2, "user_signature": 3,
	})
}
