package chainclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func releasedEventTypes() map[string]KeeperEventType {
	known := map[string]KeeperEventType{}
	for _, message := range []proto.Message{&hubv1.ProtocolEventPayloadV1{}, &taskv1.TaskProtocolEventPayloadV1{}} {
		fields := message.ProtoReflect().Descriptor().Fields()
		for i := 0; i < fields.Len(); i++ {
			known[string(fields.Get(i).Message().FullName())] = KeeperEventProtocolProjection
		}
	}
	for name, kind := range map[string]KeeperEventType{
		"task.v1.EventWorkerHandraisesAccepted":    KeeperEventAssignAcceptedPendingRandomness,
		"task.v1.EventWorkerAssignmentFinalized":   KeeperEventAssignmentFinalized,
		"task.v1.EventAssignmentFailed":            KeeperEventAssignmentFailed,
		"task.v1.EventVerifierAssignmentFinalized": KeeperEventOpenVerifyAccepted,
		"task.v1.EventInferReceiptAccepted":        KeeperEventInferReceiptAccepted,
		"task.v1.EventCommitAccepted":              KeeperEventCommitAccepted,
		"task.v1.EventResultAccepted":              KeeperEventResultCredentialAccepted,
		"task.v1.EventRevealPhaseStarted":          KeeperEventRevealPhaseStarted,
		"task.v1.EventCommitDeadlineClosed":        KeeperEventCommitDeadlineClosed,
		"task.v1.EventWorkerTimeout":               KeeperEventWorkerTimeout,
		"task.v1.EventVerifyOpenTimeout":           KeeperEventVerifyOpenDeadlineClosed,
		"task.v1.EventTaskSettled":                 KeeperEventSettleAccepted,
		"task.v1.EventTaskFailureClassUpdated":     KeeperEventTaskFailureClassUpdated,
		"task.v1.EventDeadlineSwept":               KeeperEventDeadlineSwept,
		"hub.v1.EventFaultRecorded":                KeeperEventFaultRecorded,
		"hub.v1.EventFreezeSignalSubmitted":        KeeperEventFreezeSignalSubmitted,
		"hub.v1.EventEmergencyFreezeAccepted":      KeeperEventEmergencyFreezeAccepted,
		"hub.v1.EventModelProfileRegistered":       KeeperEventModelProfileRegistered,
		"hub.v1.EventModelProfileStateChanged":     KeeperEventModelProfileStateChanged,
		"hub.v1.EventModelSupportUpdated":          KeeperEventModelSupportUpdated,
		"hub.v1.EventModelSupportActivated":        KeeperEventModelSupportUpdated,
		"hub.v1.EventBuilderSetUpdated":            KeeperEventBuilderSetUpdated,
	} {
		if _, ok := known[name]; !ok {
			panic("event missing from released descriptor: " + name)
		}
		known[name] = kind
	}
	return known
}

func identifyProtocolEnvelope(raw RawChainEvent) EventIdentity {
	identity := EventIdentity{Known: true, Type: KeeperEventProtocolProjection}
	invalid := func(err error) EventIdentity { identity.Error = err.Error(); return identity }
	if raw.Attributes["schema_version"] != "1" {
		return invalid(fmt.Errorf("protocol event schema_version must be 1"))
	}
	code, ok := sharedv1.ProtocolEventCodeV1_value[raw.Attributes["event_code"]]
	if !ok {
		parsed, err := strconv.ParseInt(raw.Attributes["event_code"], 10, 32)
		if err != nil {
			return invalid(err)
		}
		code = int32(parsed)
	}
	if _, ok := sharedv1.ProtocolEventCodeV1_name[code]; !ok || code == 0 {
		return invalid(fmt.Errorf("unknown protocol event code %d", code))
	}
	height, err := strconv.ParseUint(raw.Attributes["block_height"], 10, 64)
	if err != nil || height == 0 {
		return invalid(fmt.Errorf("protocol event block height is required"))
	}
	identity.BlockHeight = height
	var wrapper proto.Message = &taskv1.TaskProtocolEventPayloadV1{}
	field := wrapper.ProtoReflect().Descriptor().Fields().ByNumber(protoreflect.FieldNumber(code))
	if field == nil {
		wrapper = &hubv1.ProtocolEventPayloadV1{}
		field = wrapper.ProtoReflect().Descriptor().Fields().ByNumber(protoreflect.FieldNumber(code))
	}
	if field == nil {
		return invalid(fmt.Errorf("event code %d has no released payload", code))
	}
	if err := protojson.Unmarshal([]byte(raw.Attributes["payload"]), wrapper); err != nil {
		return invalid(fmt.Errorf("decode protocol payload: %w", err))
	}
	value := wrapper.ProtoReflect()
	if selected := value.WhichOneof(value.Descriptor().Oneofs().Get(0)); selected == nil || selected.Number() != field.Number() {
		return invalid(fmt.Errorf("protocol event code does not match payload"))
	}
	payload := value.Get(field).Message().Interface()
	var locator hubv1.ProtocolEventPrimaryLocatorV1
	if err := protojson.Unmarshal([]byte(raw.Attributes["primary_locator"]), &locator); err != nil {
		return invalid(fmt.Errorf("decode protocol primary locator: %w", err))
	}
	locatorValue := locator.ProtoReflect()
	locatorField := locatorValue.WhichOneof(locatorValue.Descriptor().Oneofs().Get(0))
	if locatorField == nil {
		return invalid(fmt.Errorf("protocol event primary locator is required"))
	}
	locatorMessage := locatorValue.Get(locatorField).Message()
	payloadFields := payload.ProtoReflect().Descriptor().Fields()
	if taskField := payloadFields.ByName("task_id"); taskField != nil && payload.ProtoReflect().Has(taskField) && locator.GetTask() == nil && locator.GetTaskRound() == nil {
		return invalid(fmt.Errorf("task event primary locator must identify its task"))
	}
	if taskField := payloadFields.ByName("task_id"); taskField == nil || !payload.ProtoReflect().Has(taskField) {
		if sessionField := payloadFields.ByName("session_id"); sessionField != nil && payload.ProtoReflect().Has(sessionField) && locator.GetSession() == nil {
			return invalid(fmt.Errorf("session event primary locator must identify its session"))
		}
	}
	for _, message := range []protoreflect.Message{payload.ProtoReflect(), locatorMessage} {
		for _, name := range []protoreflect.Name{"task_id", "session_id"} {
			idField := message.Descriptor().Fields().ByName(name)
			if idField == nil || idField.HasOptionalKeyword() && !message.Has(idField) {
				continue
			}
			id := message.Get(idField).Bytes()
			if len(id) != 32 {
				return invalid(fmt.Errorf("protocol event %s must be 32 bytes", name))
			}
			canonical := hex.EncodeToString(id)
			target := &identity.TaskID
			if name == "session_id" {
				target = &identity.SessionID
			}
			if *target != "" && *target != canonical {
				return invalid(fmt.Errorf("protocol event primary locator %s does not match payload", name))
			}
			*target = canonical
		}
	}
	if round := locator.GetTaskRound(); round != nil {
		payloadRound := payload.ProtoReflect().Descriptor().Fields().ByName("verify_round")
		if round.VerifyRound == 0 || payloadRound == nil || uint32(payload.ProtoReflect().Get(payloadRound).Uint()) != round.VerifyRound {
			return invalid(fmt.Errorf("protocol event primary locator round does not match payload"))
		}
	}
	if profile := locator.GetProfile(); profile != nil {
		model := payloadFields.ByName("model_id")
		version := payloadFields.ByName("profile_version")
		if model == nil || version == nil || len(profile.ModelId) != 32 || profile.ProfileVersion == 0 || !bytes.Equal(payload.ProtoReflect().Get(model).Bytes(), profile.ModelId) || uint32(payload.ProtoReflect().Get(version).Uint()) != profile.ProfileVersion {
			return invalid(fmt.Errorf("protocol event primary locator profile does not match payload"))
		}
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(payload)
	if err != nil {
		return invalid(err)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &values); err != nil {
		return invalid(err)
	}
	attributes := make(map[string]string, len(raw.Attributes)+len(values))
	for _, key := range []string{"schema_version", "event_code", "block_height", "tx_hash", "msg_index", "event_index", "primary_locator", "payload"} {
		if value, ok := raw.Attributes[key]; ok {
			attributes[key] = value
		}
	}
	for key, value := range values {
		var text string
		if json.Unmarshal(value, &text) != nil {
			text = string(value)
		}
		attributes[key] = text
	}
	// model_id is a Hash32 that Cortex keys on as canonical hex everywhere else;
	// ProtoJSON would leave it base64 here.
	if model := payloadFields.ByName("model_id"); model != nil && model.Kind() == protoreflect.BytesKind && !model.IsList() {
		if raw := payload.ProtoReflect().Get(model).Bytes(); len(raw) == 32 {
			attributes["model_id"] = hex.EncodeToString(raw)
		}
	}
	identity.Type = keeperABCIEventTypes[string(field.Message().FullName())]
	identity.Attributes = attributes
	return identity
}
