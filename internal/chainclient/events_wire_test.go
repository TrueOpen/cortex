package chainclient

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestWireV040EventEnvelopeBindsCodeAndPayload(t *testing.T) {
	id := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	attributes := map[string]string{"schema_version": "1", "event_code": "PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED", "block_height": "90", "primary_locator": `{"task":{"taskId":"` + id + `"}}`, "payload": `{"workerAssignmentFinalized":{"taskId":"` + id + `","sessionId":"` + id + `","winnerWorker":"worker"}}`}
	got := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes})
	if !got.Known || got.Type != KeeperEventAssignmentFinalized || got.TaskID == "" || got.Error != "" {
		t.Fatalf("identity = %+v", got)
	}
	attributes["event_code"] = "PROTOCOL_EVENT_CODE_V1_RESULT_ACCEPTED"
	if mismatch := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes}); mismatch.Error == "" {
		t.Fatal("accepted code/payload mismatch")
	}
}

func TestWireV040EventEnvelopeRejectsMalformedIdentity(t *testing.T) {
	id := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	for name, changes := range map[string]map[string]string{
		"schema":             {"schema_version": "2"},
		"code":               {"event_code": "99999"},
		"height":             {"block_height": "0"},
		"payload":            {"payload": `{"workerAssignmentFinalized":{"taskId":"AA=="}}`},
		"absent locator":     {"primary_locator": "{}"},
		"mismatched locator": {"primary_locator": `{"task":{"taskId":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			attributes := map[string]string{"schema_version": "1", "event_code": "11", "block_height": "90", "primary_locator": `{"task":{"taskId":"` + id + `"}}`, "payload": `{"workerAssignmentFinalized":{"taskId":"` + id + `","sessionId":"` + id + `","winnerWorker":"worker"}}`}
			for key, value := range changes {
				attributes[key] = value
			}
			got := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes})
			if !got.Known || got.Error == "" {
				t.Fatalf("identity = %+v", got)
			}
		})
	}
}

func TestWireV040EventEnvelopeCometProjectionAndQuarantine(t *testing.T) {
	id := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	raw := cometEvent{Type: "hub.v1.ProtocolEventEnvelopeV1", Attributes: []cometAttribute{
		{Key: "schema_version", Value: "1"}, {Key: "event_code", Value: `"PROTOCOL_EVENT_CODE_V1_WORKER_ASSIGNMENT_FINALIZED"`},
		{Key: "block_height", Value: `"90"`}, {Key: "primary_locator", Value: `{"task":{"taskId":"` + id + `"}}`},
		{Key: "payload", Value: `{"workerAssignmentFinalized":{"taskId":"` + id + `","sessionId":"` + id + `","winnerWorker":"worker","inferDeadline":"100"}}`},
	}}
	for _, height := range []uint64{90, 91} {
		events, err := parseCometEvents(MessageNameEventIdentifier(), "chain", height, 0, "", []cometEvent{raw})
		if err != nil || len(events) != 1 {
			t.Fatalf("events = %+v, error=%v", events, err)
		}
		if events[0].Quarantined != (height != 90) || events[0].InferDeadlineHeight != 100 || events[0].Worker != "worker" {
			t.Fatalf("event = %+v", events[0])
		}
	}
}

func TestWireV040RetiredEventIsUnknown(t *testing.T) {
	got := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "task.v1.EventFullResultRevealAccepted"})
	if got.Known {
		t.Fatal("recognized retired event")
	}
}

func TestWireV041WorkerEvidenceEventProjectsWithoutTaskTransition(t *testing.T) {
	id := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	attributes := map[string]string{
		"schema_version": "1", "event_code": "PROTOCOL_EVENT_CODE_V1_WORKER_EVIDENCE_ACCEPTED", "block_height": "90",
		"primary_locator": `{"task":{"taskId":"` + id + `"}}`,
		"payload":         `{"workerEvidenceAccepted":{"taskId":"` + id + `","workerOperatorAddress":"worker","evidenceDigest":"` + id + `","faultId":"` + id + `","seq":"3","acceptedHeight":"90"}}`,
	}
	got := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes})
	if !got.Known || got.Error != "" || got.Type != KeeperEventProtocolProjection || got.TaskID == "" || got.SessionID != "" || got.Attributes["seq"] != "3" || got.Attributes["accepted_height"] != "90" {
		t.Fatalf("identity=%+v", got)
	}
	attributes["event_code"] = "PROTOCOL_EVENT_CODE_V1_INFER_RECEIPT_ACCEPTED"
	if mismatch := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes}); mismatch.Error == "" {
		t.Fatal("accepted worker evidence under another event code")
	}
}

func TestWireV041InferReceiptEventPreservesLeafAndTokenCounts(t *testing.T) {
	id := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	attributes := map[string]string{
		"schema_version": "1", "event_code": "12", "block_height": "90",
		"primary_locator": `{"task":{"taskId":"` + id + `"}}`,
		"payload":         `{"inferReceiptAccepted":{"taskId":"` + id + `","sessionId":"` + id + `","worker":"worker","generatedTokenCount":"37","outputLeafCount":"4"}}`,
	}
	got := MessageNameEventIdentifier().Identify(RawChainEvent{ABCIType: "hub.v1.ProtocolEventEnvelopeV1", Attributes: attributes})
	if got.Error != "" || got.Type != KeeperEventInferReceiptAccepted || got.Attributes["generated_token_count"] != "37" || got.Attributes["output_leaf_count"] != "4" {
		t.Fatalf("identity=%+v", got)
	}
}
