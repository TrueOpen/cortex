package chainclient

import (
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
)

// Chain events are identified from the wire v0.4.1 payload descriptor registry.

// RawChainEvent is one chain event exactly as the node presented it: the ABCI
// event type plus its decoded attributes. It is the only wire-shaped value the
// identification layer sees.
//
// Attributes is the live map that also becomes KeeperEvent.Attributes, so an
// identifier must treat it as read-only: mutating it rewrites the event the
// handlers and the persisted digest see.
type RawChainEvent struct {
	ABCIType   string
	Attributes map[string]string
}

// EventIdentity is the identification layer's answer for one RawChainEvent:
// which internal protocol event kind it is, whether this binary recognises it at
// all, and which task/session it concerns.
type EventIdentity struct {
	Attributes  map[string]string
	Error       string
	BlockHeight uint64
	Type        KeeperEventType
	Known       bool
	TaskID      string
	SessionID   string
}

// EventIdentifier decides which protocol event a raw chain event is and which
// task/session it concerns. It is the only layer that knows how the chain
// encodes that answer; see the migration seam note above.
type EventIdentifier interface {
	Identify(RawChainEvent) EventIdentity
}

// MessageNameEventIdentifier returns the identification layer Cortex ships:
// a match on the protobuf fully qualified message name that Node's typed events
// put in the ABCI event type. CometEventClient uses it unless a caller supplies
// its own.
func MessageNameEventIdentifier() EventIdentifier { return messageNameIdentification{} }

type messageNameIdentification struct{}

func (messageNameIdentification) Identify(raw RawChainEvent) EventIdentity {
	if raw.ABCIType == "hub.v1.ProtocolEventEnvelopeV1" {
		return identifyProtocolEnvelope(raw)
	}
	eventType, known := keeperEventTypeFromABCI(raw.ABCIType)
	return EventIdentity{
		Type:      eventType,
		Known:     known,
		TaskID:    CanonicalEventHash32(raw.Attributes["task_id"]),
		SessionID: CanonicalEventHash32(raw.Attributes["session_id"]),
	}
}

// CanonicalEventHash32 converts one chain-event identity attribute into the
// single form the rest of Cortex -- and Nexus -- speaks: canonical lowercase
// 32-byte hex.
//
// The chain types session_id and task_id as protobuf `bytes`, and a Cosmos SDK
// typed event is a ProtoJSON fragment, so `bytes` arrives base64-encoded:
// `S44s30HT6/upDQMFQnIYQS3woYjb12xwccbfNlaXOPw=`. Every other layer that names
// the same 32 bytes writes them as hex -- the Keeper query layer
// (`hex.EncodeToString(core.TaskId)`, query_task_v1.go), the task identity
// derivation (identity.TaskIDString), and Nexus itself (`hex.EncodeToString` in
// its ingress task-id derivation). Identification is the only layer that knows
// how the chain encodes its answer, so the conversion belongs here and nothing
// below it changes.
//
// Leaving base64 through is what wedged real nodes: QueryTask refused it with
// "task_id must be 32-byte hex", a permanent error, and the poller never
// advanced its cursor past that block.
//
// The two encodings cannot be confused. 32 bytes of base64 is 44 characters and
// hex is 64, and hex is tried first, so a canonical hex id is never re-read as
// base64 of 48 bytes. Only standard-alphabet base64 is accepted -- padded and
// unpadded -- because that is what ProtoJSON emits; the URL alphabet is not, so
// an opaque identifier containing `-` or `_` is never silently rewritten.
// Anything that is neither encoding (a test's `task-1`, an id shape nobody has
// seen yet) passes through untouched, leaving identification lossless and
// letting the layers below decide what to do about it.
func CanonicalEventHash32(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) == 0 {
		return value
	}
	if raw, err := hex.DecodeString(trimmed); err == nil && len(raw) == 32 {
		return hex.EncodeToString(raw)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if raw, err := encoding.DecodeString(trimmed); err == nil && len(raw) == 32 {
			return hex.EncodeToString(raw)
		}
	}
	return value
}

func keeperEventTypeFromABCI(raw string) (KeeperEventType, bool) {
	value, ok := keeperABCIEventTypes[raw]
	if !ok {
		return KeeperEventType(raw), false
	}
	return value, true
}

// abciEventTypeRecognized reports whether the message-name identification layer
// claims this raw ABCI type. Validate uses it to tell an event this binary has
// no field contract for from one it does know but whose caller built without the
// recognition flag.
func abciEventTypeRecognized(abciType string) bool {
	if abciType == "hub.v1.ProtocolEventEnvelopeV1" {
		return true
	}
	_, ok := keeperABCIEventTypes[abciType]
	return ok
}

// keeperABCIEventTypes maps Cosmos SDK typed-event names to internal
// classifications. Node emits custom events only through the typed-event API,
// so the ABCI type is the protobuf fully qualified message name. There is no
// snake-case mirror and no raw-attribute fallback to fall back on.
var keeperABCIEventTypes = releasedEventTypes()

// KnownKeeperEventTypes returns the unique current raw event classifications.
// Reconciler tests use this to require an explicit runtime disposition whenever
// the identification layer's allowlist grows.
//
// It derives from the shipped message-name layer, and so does
// abciEventTypeRecognized below. A second identifier that recognises kinds this
// map does not name would not widen either, so the migration must re-express
// both over the active identifier rather than this map.
func KnownKeeperEventTypes() []KeeperEventType {
	seen := make(map[KeeperEventType]struct{}, len(keeperABCIEventTypes))
	for _, eventType := range keeperABCIEventTypes {
		seen[eventType] = struct{}{}
	}
	out := make([]KeeperEventType, 0, len(seen))
	for eventType := range seen {
		out = append(out, eventType)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
