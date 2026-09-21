package chainclient

import "testing"

// The chain types session_id and task_id as protobuf `bytes` and emits them
// through the Cosmos SDK typed-event API, so ProtoJSON presents them base64.
// These two values are the real pair observed on a devnet block; the task_id is
// verbatim the one that used to stop every node reading that block with
// "Keeper QueryTask task_id must be 32-byte hex".
const (
	observedBase64TaskID    = "S44s30HT6/upDQMFQnIYQS3woYjb12xwccbfNlaXOPw="
	observedHexTaskID       = "4b8e2cdf41d3ebfba90d0305427218412df0a188dbd76c7071c6df36569738fc"
	observedBase64SessionID = "EjRWeJq83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vA="
	observedHexSessionID    = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
)

// Identification owns the chain's encoding, and the form it hands down is the
// one every other layer already speaks: canonical lowercase hex, the same
// hex.EncodeToString the Keeper query layer applies to the identical 32 bytes
// and the same form Nexus publishes. Without this, a task-bearing event carried
// base64 into a Keeper query that only accepts hex.
func TestIdentifyNormalizesProtoJSONBytesIdentityToCanonicalHex(t *testing.T) {
	identity := MessageNameEventIdentifier().Identify(RawChainEvent{
		ABCIType: "task.v1.EventWorkerAssignmentFinalized",
		Attributes: map[string]string{
			"session_id":    observedBase64SessionID,
			"task_id":       observedBase64TaskID,
			"winner_worker": "trueopen1node",
		},
	})
	if !identity.Known || identity.Type != KeeperEventAssignmentFinalized {
		t.Fatalf("identity = %#v, want the recognized assignment event", identity)
	}
	if identity.TaskID != observedHexTaskID {
		t.Fatalf("task_id = %q, want canonical hex %q", identity.TaskID, observedHexTaskID)
	}
	if identity.SessionID != observedHexSessionID {
		t.Fatalf("session_id = %q, want canonical hex %q", identity.SessionID, observedHexSessionID)
	}
}

// The conversion has to be a no-op on anything that is not the chain's own
// 32-byte encoding: an id already in canonical hex must survive byte for byte
// (or the value would stop matching the Keeper snapshot it is compared against),
// and an opaque identifier must not be rewritten into something that merely
// looks like a hash.
func TestCanonicalEventHash32LeavesEverythingElseUntouched(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "canonical hex", value: observedHexTaskID, want: observedHexTaskID},
		{name: "uppercase hex", value: "4B8E2CDF41D3EBFBA90D0305427218412DF0A188DBD76C7071C6DF36569738FC", want: observedHexTaskID},
		{name: "unpadded base64", value: "S44s30HT6/upDQMFQnIYQS3woYjb12xwccbfNlaXOPw", want: observedHexTaskID},
		{name: "empty", value: "", want: ""},
		{name: "opaque test id", value: "task-1", want: "task-1"},
		{name: "url alphabet is not the chain's", value: "S44s30HT6_upDQMFQnIYQS3woYjb12xwccbfNlaXOPw=", want: "S44s30HT6_upDQMFQnIYQS3woYjb12xwccbfNlaXOPw="},
		{name: "base64 of the wrong width", value: "EjRWeJq83vASNFZ4mrze8A==", want: "EjRWeJq83vASNFZ4mrze8A=="},
		{name: "hex of the wrong width", value: "4b8e2cdf41d3ebfb", want: "4b8e2cdf41d3ebfb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CanonicalEventHash32(test.value); got != test.want {
				t.Fatalf("CanonicalEventHash32(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

// syntheticABCIType stands in for the wire type of a future envelope-shaped
// protocol event. It is deliberately not a guess at what the frozen contract's
// envelope will actually present -- see the migration seam note in
// events_identity.go -- only a type string that shares nothing with today's
// typed-event message names.
const syntheticABCIType = "cortex.test.v1.SyntheticProtocolEventEnvelope"

// syntheticIdentification is an alternative identification layer. It answers the
// same two questions from a wire shape with no message name and with the
// task/session locator under different attribute keys, which is what makes it a
// real test of the seam rather than of the map behind it.
type syntheticIdentification struct{}

func (syntheticIdentification) Identify(raw RawChainEvent) EventIdentity {
	if raw.ABCIType != syntheticABCIType {
		return MessageNameEventIdentifier().Identify(raw)
	}
	identity := EventIdentity{
		TaskID:    raw.Attributes["locator_task_id"],
		SessionID: raw.Attributes["locator_session_id"],
	}
	if raw.Attributes["synthetic_event"] == "assignment_finalized" {
		identity.Type = KeeperEventAssignmentFinalized
		identity.Known = true
	}
	return identity
}

// Identification is separated from handling so the coming envelope+code decoder
// replaces one layer. This asserts the separation holds: the same protocol fact
// carried by an unrelated wire encoding produces the same internal event, and
// only the retained wire evidence differs.
func TestParseCometEventsIdentifiesProtocolEventThroughAlternativeLayer(t *testing.T) {
	typed, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 41, 0, "tx-1", []cometEvent{{
		Type: "task.v1.EventWorkerAssignmentFinalized",
		Attributes: []cometAttribute{
			{Key: "session_id", Value: "session-1"},
			{Key: "task_id", Value: "task-1"},
			{Key: "winner_worker", Value: "trueopen1node"},
		},
	}})
	if err != nil || len(typed) != 1 {
		t.Fatalf("parseCometEvents(message name) = %#v err=%v, want one event", typed, err)
	}
	synthetic, err := parseCometEvents(syntheticIdentification{}, "trueopen-devnet-1", 41, 0, "tx-1", []cometEvent{{
		Type: syntheticABCIType,
		Attributes: []cometAttribute{
			{Key: "locator_session_id", Value: "session-1"},
			{Key: "locator_task_id", Value: "task-1"},
			{Key: "synthetic_event", Value: "assignment_finalized"},
			{Key: "winner_worker", Value: "trueopen1node"},
		},
	}})
	if err != nil || len(synthetic) != 1 {
		t.Fatalf("parseCometEvents(synthetic) = %#v err=%v, want one event", synthetic, err)
	}

	want, got := typed[0], synthetic[0]
	if got.Type != want.Type || !got.Known || got.TaskID != want.TaskID || got.SessionID != want.SessionID {
		t.Fatalf("synthetic identity = %#v, want the same protocol event as %#v", got, want)
	}
	if got.Worker != want.Worker || got.ContractVersion != want.ContractVersion || got.Position != want.Position {
		t.Fatalf("synthetic event = %#v, want the same handling inputs as %#v", got, want)
	}
	if got.Quarantined || want.Quarantined {
		t.Fatalf("events quarantined: synthetic=%q typed=%q", got.QuarantineReason, want.QuarantineReason)
	}
	if got.RawType != syntheticABCIType {
		t.Fatalf("synthetic raw type = %q, want the wire type retained as evidence", got.RawType)
	}
}

// An identification layer that claims nothing must leave the event unrecognized
// rather than inventing a kind: unrecognized events are carried for the cursor
// and audit trail, and no handler may act on them.
func TestParseCometEventsCarriesEventUnclaimedByIdentificationLayer(t *testing.T) {
	events, err := parseCometEvents(syntheticIdentification{}, "trueopen-devnet-1", 42, 0, "tx-2", []cometEvent{{
		Type:       syntheticABCIType,
		Attributes: []cometAttribute{{Key: "synthetic_event", Value: "not_registered"}},
	}})
	if err != nil || len(events) != 1 {
		t.Fatalf("parseCometEvents = %#v err=%v, want the unclaimed event carried", events, err)
	}
	if events[0].Known || events[0].RawType != syntheticABCIType {
		t.Fatalf("event = %#v, want unrecognized with its wire type retained", events[0])
	}
}
