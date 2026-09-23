package builderclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bussharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const BusEnvelopeSchemaVersion uint32 = 1

// BusEnvelopeMaxBytes bounds one inbound frame before any decoding. NATS caps
// payloads at 1 MiB by default and every task-control message is orders of
// magnitude smaller.
const BusEnvelopeMaxBytes = 1 << 20

var ErrBusEnvelopeAuthenticationUnavailable = errors.New("Nexus BusEnvelope authentication contract is unavailable")

// BusEnvelopeAuthenticator authenticates one inbound frame. Authentication is
// stateful: it claims a durable replay key, so exactly one call may be made per
// frame received from the wire.
type BusEnvelopeAuthenticator interface {
	// Authenticate may be called concurrently by independent NATS subscription
	// callbacks and therefore must be safe for concurrent use.
	//
	// subject is the NATS subject the frame was delivered on, which the
	// implementation binds against the subject inside the envelope: a signature
	// minted for one subject must not be accepted on another.
	Authenticate(ctx context.Context, subject string, envelope BusEnvelope) error
}

type BusEnvelopeAuthenticatorFunc func(context.Context, string, BusEnvelope) error

func (f BusEnvelopeAuthenticatorFunc) Authenticate(ctx context.Context, subject string, envelope BusEnvelope) error {
	return f(ctx, subject, envelope)
}

type BusEnvelopeSigner interface {
	SignEnvelope(BusEnvelope) ([]byte, error)
}

type BusEnvelopeSignerFunc func(BusEnvelope) ([]byte, error)

func (f BusEnvelopeSignerFunc) SignEnvelope(envelope BusEnvelope) ([]byte, error) {
	return f(envelope)
}

type BusMessageKind string

// The eight kinds of the bus.v1 contract (TrueOpen/wire proto/bus/v1,
// TrueOpen/nexus#52). The vocabulary is a closed set on both sides of this bus.
// OPEN_TASK from the retired JSON contract is now ORDER_BROADCAST: the broadcast
// carries the complete user-signed order exactly once.
const (
	KindOrderBroadcast           BusMessageKind = "ORDER_BROADCAST"
	KindWorkerHandraise          BusMessageKind = "WORKER_HANDRAISE"
	KindOpenVerify               BusMessageKind = "OPEN_VERIFY"
	KindVerifierHandraise        BusMessageKind = "VERIFIER_HANDRAISE"
	KindWorkerAssignmentNotify   BusMessageKind = "WORKER_ASSIGNMENT_NOTIFY"
	KindOutputAvailable          BusMessageKind = "OUTPUT_AVAILABLE"
	KindVerifierAssignmentNotify BusMessageKind = "VERIFIER_ASSIGNMENT_NOTIFY"
	KindVerifyResult             BusMessageKind = "VERIFY_RESULT"
)

// BusParticipantType is envelope field 5: the key-domain namespace a receiver
// queries for the sender's current service key. The TRUEOPEN_BUS_ENVELOPE_V2
// envelope has no sender_role field; the participant type is the whole sender
// identity axis, and task duty travels inside the signed payloads.
type BusParticipantType string

const (
	ParticipantBuilder BusParticipantType = "BUILDER"
	ParticipantCortex  BusParticipantType = "CORTEX"
)

func (p BusParticipantType) wire() (bussharedv1.ParticipantType, error) {
	switch p {
	case ParticipantBuilder:
		return bussharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, nil
	case ParticipantCortex:
		return bussharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, nil
	default:
		return bussharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED,
			fmt.Errorf("Nexus BusEnvelope participant type %q is not on the wire enum", p)
	}
}

func participantFromWire(value bussharedv1.ParticipantType) (BusParticipantType, error) {
	switch value {
	case bussharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		return ParticipantBuilder, nil
	case bussharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX:
		return ParticipantCortex, nil
	default:
		return "", fmt.Errorf("Nexus BusEnvelope sender_participant_type %d is not a known domain", value)
	}
}

// BusSubjectTier is the transport guarantee the contract assigns a subject:
// Core is best-effort lowest-latency plain NATS, JetStream is at-least-once
// with dedup and redelivery.
type BusSubjectTier string

const (
	TierCore      BusSubjectTier = "CORE"
	TierJetStream BusSubjectTier = "JETSTREAM"
)

type busSubjectSpec struct {
	prefix      string
	placeholder string // "model_id" or "task_id"
	kind        BusMessageKind
	wireKind    busv1.BusMessageKind
	payloadType busv1.BusPayloadType
	tier        BusSubjectTier
	// senders is the participant-type column: which key domains may sign this
	// kind. The V2 envelope has no role axis.
	senders    []BusParticipantType
	newPayload func() proto.Message
}

// busSubjectSpecs is the single table binding a subject to its kind, its wire
// enum values, its transport tier and its admissible sender domains. The
// kind -> payload_type column is the frozen mapping documented on
// bus.v1.BusPayloadType; wire's bus package enforces the same map
// inside Verify, and TestBusSubjectTableMatchesWireContract pins this table
// against it.
//
// nexus.builder-prepare.* is deliberately absent: it is Builder -> Builder
// coordination that Cortex neither publishes nor receives.
var busSubjectSpecs = []busSubjectSpec{
	{
		prefix: "trueopen.task.open.", placeholder: "model_id", kind: KindOrderBroadcast,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_ORDER_BROADCAST,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_ORDER_BROADCAST_V1,
		tier:        TierCore,
		senders:     []BusParticipantType{ParticipantBuilder},
		newPayload:  func() proto.Message { return &busv1.OrderBroadcastV1{} },
	},
	{
		prefix: "trueopen.handraise.worker.", placeholder: "task_id", kind: KindWorkerHandraise,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_WORKER_HANDRAISE,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_WORKER_HANDRAISE_V1,
		tier:        TierCore,
		senders:     []BusParticipantType{ParticipantCortex},
		newPayload:  func() proto.Message { return &bustaskv1.WorkerHandraiseV1{} },
	},
	{
		prefix: "trueopen.verify.open.", placeholder: "task_id", kind: KindOpenVerify,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_OPEN_VERIFY,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_OPEN_VERIFY_V1,
		tier:        TierCore,
		senders:     []BusParticipantType{ParticipantBuilder},
		newPayload:  func() proto.Message { return &busv1.OpenVerifyV1{} },
	},
	{
		prefix: "trueopen.handraise.verifier.", placeholder: "task_id", kind: KindVerifierHandraise,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_VERIFIER_HANDRAISE,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_VERIFIER_HANDRAISE_V1,
		tier:        TierCore,
		senders:     []BusParticipantType{ParticipantCortex},
		newPayload:  func() proto.Message { return &bustaskv1.VerifierHandraiseV1{} },
	},
	{
		prefix: "trueopen.worker-assignment.", placeholder: "task_id", kind: KindWorkerAssignmentNotify,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_WORKER_ASSIGNMENT_NOTIFY,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_WORKER_ASSIGNMENT_NOTIFY_V1,
		tier:        TierJetStream,
		senders:     []BusParticipantType{ParticipantBuilder},
		newPayload:  func() proto.Message { return &busv1.WorkerAssignmentNotifyV1{} },
	},
	{
		// Cortex publishes the CORTEX row; the BUILDER row is here because
		// Cortex also receives this kind. The sender must still agree with the
		// on-chain winner / Open Task selection, which the consumer checks.
		prefix: "trueopen.output-avail.", placeholder: "task_id", kind: KindOutputAvailable,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_OUTPUT_AVAILABLE,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_OUTPUT_AVAILABLE_V1,
		tier:        TierJetStream,
		senders:     []BusParticipantType{ParticipantCortex, ParticipantBuilder},
		newPayload:  func() proto.Message { return &busv1.OutputAvailableV1{} },
	},
	{
		prefix: "trueopen.verifier-assignment.", placeholder: "task_id", kind: KindVerifierAssignmentNotify,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_VERIFIER_ASSIGNMENT_NOTIFY,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_VERIFIER_ASSIGNMENT_NOTIFY_V1,
		tier:        TierJetStream,
		senders:     []BusParticipantType{ParticipantBuilder},
		newPayload:  func() proto.Message { return &busv1.VerifierAssignmentNotifyV1{} },
	},
	{
		prefix: "trueopen.verify-result.", placeholder: "task_id", kind: KindVerifyResult,
		wireKind:    busv1.BusMessageKind_BUS_MESSAGE_KIND_VERIFY_RESULT,
		payloadType: busv1.BusPayloadType_BUS_PAYLOAD_TYPE_VERIFY_RESULT_V1,
		tier:        TierJetStream,
		senders:     []BusParticipantType{ParticipantCortex},
		newPayload:  func() proto.Message { return &bustaskv1.ResultReceiptV2{} },
	},
}

// BusSubjectTierForSubject reports the transport tier of a contract subject.
// An unknown subject has no tier: it is not on this bus.
func BusSubjectTierForSubject(subject string) (BusSubjectTier, bool) {
	spec, ok := busSubjectSpecForSubject(subject)
	if !ok {
		return "", false
	}
	return spec.tier, true
}

// BusContractSubjectPrefixes returns the contract subject prefixes in table
// order, so the subscription and validation paths cannot keep a second,
// drifting copy of the list.
func BusContractSubjectPrefixes() []string {
	out := make([]string, 0, len(busSubjectSpecs))
	for _, spec := range busSubjectSpecs {
		out = append(out, spec.prefix)
	}
	return out
}

// KindForSubject returns the wire kind and an empty payload message for a
// contract subject. It is the single subject-to-kind dispatch table for both
// envelope validation and message processing.
func KindForSubject(subject string) (BusMessageKind, proto.Message, bool) {
	spec, ok := busSubjectSpecForSubject(subject)
	if !ok {
		return "", nil, false
	}
	return spec.kind, spec.newPayload(), true
}

func busSubjectSpecForSubject(subject string) (busSubjectSpec, bool) {
	trimmed := strings.TrimSpace(subject)
	for _, spec := range busSubjectSpecs {
		if strings.HasPrefix(trimmed, spec.prefix) {
			return spec, true
		}
	}
	return busSubjectSpec{}, false
}

func busSubjectSpecForKind(kind BusMessageKind) (busSubjectSpec, bool) {
	for _, spec := range busSubjectSpecs {
		if spec.kind == kind {
			return spec, true
		}
	}
	return busSubjectSpec{}, false
}

func busSubjectSpecForWireKind(kind busv1.BusMessageKind) (busSubjectSpec, bool) {
	for _, spec := range busSubjectSpecs {
		if spec.wireKind == kind {
			return spec, true
		}
	}
	return busSubjectSpec{}, false
}

// BusSubjectSendersForKind returns the participant-type column of the frozen
// table for a kind: the domains that may sign it. It exists so the inbound
// authenticator can derive its admissible set from the contract instead of
// keeping a second, narrower copy in configuration — which is how the
// Worker-published half of OUTPUT_AVAILABLE became unauthenticable.
//
// The returned slice is a copy: the table is the contract and a caller must not
// be able to edit it.
func BusSubjectSendersForKind(kind BusMessageKind) ([]BusParticipantType, bool) {
	spec, ok := busSubjectSpecForKind(kind)
	if !ok {
		return nil, false
	}
	return append([]BusParticipantType(nil), spec.senders...), true
}

// validateSenderParticipant refuses a (kind, participant type) pair that is not
// a row of the sender table.
func validateSenderParticipant(kind BusMessageKind, participant BusParticipantType) error {
	spec, ok := busSubjectSpecForKind(kind)
	if !ok {
		return fmt.Errorf("Nexus BusEnvelope kind %q is not in the subject table", kind)
	}
	for _, sender := range spec.senders {
		if sender == participant {
			return nil
		}
	}
	return fmt.Errorf("Nexus BusEnvelope kind %q does not admit sender_participant_type %q", kind, participant)
}

// BusEnvelope is the decoded TRUEOPEN_BUS_ENVELOPE_V2 frame: the 15 fields of
// bus.v1.BusEnvelopeV1 with the enums mapped onto this package's closed
// string sets. Payload holds the exact transmitted bytes; PayloadDigest is
// SHA-256 over exactly those bytes and enters the signing projection in the
// payload body's place.
//
// The raw proto frame is persisted before this structure is decoded, so
// unsupported future schemas and rejected messages remain auditable.
type BusEnvelope struct {
	SchemaVersion             uint32
	ChainID                   string
	Subject                   string
	Kind                      BusMessageKind
	SenderParticipantType     BusParticipantType
	SenderOperatorAddress     string
	ServiceAuthorizationNonce uint64
	MessageID                 string
	Nonce                     []byte
	IssuedAtUnixMs            int64
	ExpiresAtUnixMs           int64
	Payload                   []byte
	PayloadDigest             []byte
	Signature                 []byte
}

// signingFields maps the envelope onto wire's 13-field signing projection.
// The byte layout, field order and digest rule are owned by
// github.com/TrueOpen/wire/bus; this package never re-implements them.
func (e BusEnvelope) signingFields() (bus.Fields, error) {
	spec, ok := busSubjectSpecForKind(e.Kind)
	if !ok {
		return bus.Fields{}, fmt.Errorf("Nexus BusEnvelope kind %q is not in the subject table", e.Kind)
	}
	participant, err := e.SenderParticipantType.wire()
	if err != nil {
		return bus.Fields{}, err
	}
	if e.IssuedAtUnixMs < 0 || e.ExpiresAtUnixMs < 0 {
		return bus.Fields{}, fmt.Errorf("Nexus BusEnvelope timestamps must not be negative")
	}
	return bus.Fields{
		SchemaVersion:             e.SchemaVersion,
		ChainID:                   e.ChainID,
		Subject:                   e.Subject,
		Kind:                      int32(spec.wireKind),
		SenderParticipantType:     int32(participant),
		SenderOperatorAddress:     e.SenderOperatorAddress,
		ServiceAuthorizationNonce: e.ServiceAuthorizationNonce,
		MessageID:                 e.MessageID,
		Nonce:                     e.Nonce,
		IssuedAtUnixMS:            uint64(e.IssuedAtUnixMs),
		ExpiresAtUnixMS:           uint64(e.ExpiresAtUnixMs),
		PayloadType:               int32(spec.payloadType),
		PayloadDigest:             e.PayloadDigest,
	}, nil
}

type EnvelopeValidation struct {
	ActualSubject string
	ChainID       string
	Kind          BusMessageKind
	Now           time.Time
}

// UnsignedEnvelopeInput is what a publisher supplies. Fields 12 (payload type),
// 14 (payload digest), 8 (message id) and 9 (nonce) are absent on purpose:
// NewUnsignedBusEnvelope derives all four, so no call site can disagree with
// the tables they come from.
type UnsignedEnvelopeInput struct {
	Kind    BusMessageKind
	ChainID string
	Subject string
	// SenderOperatorAddress is field 6, the sender's stable bech32 protocol
	// identity. It is not the service address: the envelope never carries a
	// public key or a service address.
	SenderOperatorAddress string
	SenderParticipantType BusParticipantType
	// ServiceAuthorizationNonce is field 7: the authorization_nonce of the
	// sender's current ServiceKey binding, which the receiver compares against
	// the binding it resolves at verification time. It must come from a
	// committed Keeper read of this node's own binding, never a local counter.
	// Zero is the absent value everywhere this repository reads it, so zero is
	// a refusal rather than a nonce.
	ServiceAuthorizationNonce uint64
	IssuedAt                  time.Time
	ExpiresAt                 time.Time
	Random                    io.Reader
}

// NewUnsignedBusEnvelope serializes the payload exactly once and derives every
// table-owned field. The payload bytes it stores are the bytes that will be
// transmitted, persisted for retries, and committed by payload_digest; no
// later step may re-marshal them.
func NewUnsignedBusEnvelope(input UnsignedEnvelopeInput, payload proto.Message) (BusEnvelope, error) {
	issuedAt := input.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	expiresAt := input.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = issuedAt.Add(30 * time.Second)
	}
	random := input.Random
	if random == nil {
		random = rand.Reader
	}
	spec, ok := busSubjectSpecForKind(input.Kind)
	if !ok {
		return BusEnvelope{}, fmt.Errorf("Nexus BusEnvelope kind %q is not in the subject table", input.Kind)
	}
	if err := validateSenderParticipant(input.Kind, input.SenderParticipantType); err != nil {
		return BusEnvelope{}, err
	}
	if payload == nil {
		return BusEnvelope{}, fmt.Errorf("Nexus %s payload is required", input.Kind)
	}
	want := spec.newPayload()
	if proto.MessageName(want) != proto.MessageName(payload) {
		return BusEnvelope{}, fmt.Errorf("Nexus %s payload must be %s, got %s",
			input.Kind, proto.MessageName(want), proto.MessageName(payload))
	}
	messageID, err := newBusMessageIDV7(random, issuedAt)
	if err != nil {
		return BusEnvelope{}, err
	}
	if err := validateBusMessageIDV7(messageID); err != nil {
		return BusEnvelope{}, err
	}
	nonce := make([]byte, bus.NonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return BusEnvelope{}, fmt.Errorf("generate Nexus envelope nonce: %w", err)
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return BusEnvelope{}, fmt.Errorf("marshal Nexus %s payload: %w", input.Kind, err)
	}
	if len(payloadBytes) == 0 {
		return BusEnvelope{}, fmt.Errorf("Nexus %s payload marshalled to zero bytes", input.Kind)
	}
	digest := bus.PayloadDigest(payloadBytes)
	envelope := BusEnvelope{
		SchemaVersion:             BusEnvelopeSchemaVersion,
		ChainID:                   strings.TrimSpace(input.ChainID),
		Subject:                   strings.TrimSpace(input.Subject),
		Kind:                      input.Kind,
		SenderParticipantType:     input.SenderParticipantType,
		SenderOperatorAddress:     strings.TrimSpace(input.SenderOperatorAddress),
		ServiceAuthorizationNonce: input.ServiceAuthorizationNonce,
		MessageID:                 messageID,
		Nonce:                     nonce,
		IssuedAtUnixMs:            issuedAt.UnixMilli(),
		ExpiresAtUnixMs:           expiresAt.UnixMilli(),
		Payload:                   payloadBytes,
		PayloadDigest:             append([]byte(nil), digest[:]...),
	}
	if err := envelope.Validate(EnvelopeValidation{
		ActualSubject: input.Subject,
		ChainID:       input.ChainID,
		Kind:          input.Kind,
		Now:           issuedAt,
	}); err != nil {
		return BusEnvelope{}, err
	}
	return envelope, nil
}

func EncodeBusEnvelope(envelope BusEnvelope) ([]byte, error) {
	if err := envelope.Validate(EnvelopeValidation{
		ActualSubject: envelope.Subject,
		ChainID:       envelope.ChainID,
		Kind:          envelope.Kind,
		Now:           time.UnixMilli(envelope.IssuedAtUnixMs),
	}); err != nil {
		return nil, err
	}
	spec, _ := busSubjectSpecForKind(envelope.Kind)
	participant, err := envelope.SenderParticipantType.wire()
	if err != nil {
		return nil, err
	}
	wire := &busv1.BusEnvelopeV1{
		SchemaVersion:             envelope.SchemaVersion,
		ChainId:                   envelope.ChainID,
		Subject:                   envelope.Subject,
		Kind:                      spec.wireKind,
		SenderParticipantType:     participant,
		SenderOperatorAddress:     envelope.SenderOperatorAddress,
		ServiceAuthorizationNonce: envelope.ServiceAuthorizationNonce,
		MessageId:                 envelope.MessageID,
		Nonce:                     envelope.Nonce,
		IssuedAtUnixMs:            uint64(envelope.IssuedAtUnixMs),
		ExpiresAtUnixMs:           uint64(envelope.ExpiresAtUnixMs),
		PayloadType:               spec.payloadType,
		Payload:                   envelope.Payload,
		PayloadDigest:             envelope.PayloadDigest,
		ServiceSignature:          envelope.Signature,
	}
	return proto.Marshal(wire)
}

func EncodeAuthenticatedBusMessage(input UnsignedEnvelopeInput, payload proto.Message, signer BusEnvelopeSigner) ([]byte, error) {
	if signer == nil {
		return nil, ErrBusEnvelopeAuthenticationUnavailable
	}
	envelope, err := NewUnsignedBusEnvelope(input, payload)
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("sign Nexus BusEnvelope: %w", err)
	}
	if len(signature) != bus.SignatureSize {
		return nil, fmt.Errorf("sign Nexus BusEnvelope: signature must be %d bytes, got %d",
			bus.SignatureSize, len(signature))
	}
	envelope.Signature = append([]byte(nil), signature...)
	return EncodeBusEnvelope(envelope)
}

// EncodeUnsignedBusMessage exists for the trusted transport postures
// (trusted_nats_dev, fake bus) that authenticate at the NATS boundary instead
// of per frame. It refuses unless the caller states that posture explicitly.
func EncodeUnsignedBusMessage(input UnsignedEnvelopeInput, payload proto.Message, allowUnsigned bool) ([]byte, error) {
	if !allowUnsigned {
		return nil, ErrBusEnvelopeAuthenticationUnavailable
	}
	envelope, err := NewUnsignedBusEnvelope(input, payload)
	if err != nil {
		return nil, err
	}
	return EncodeBusEnvelope(envelope)
}

func DecodeBusEnvelope(data []byte) (BusEnvelope, error) {
	if len(data) == 0 {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: empty frame")
	}
	if len(data) > BusEnvelopeMaxBytes {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: frame exceeds %d bytes", BusEnvelopeMaxBytes)
	}
	var wire busv1.BusEnvelopeV1
	if err := proto.Unmarshal(data, &wire); err != nil {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: %w", err)
	}
	if unknown := wire.ProtoReflect().GetUnknown(); len(unknown) > 0 {
		// The frozen contract admits no unknown envelope fields: extra fields
		// mean the peer is speaking a different field table. Nested payload
		// messages are deliberately not deep-checked; the signature binds the
		// exact payload bytes and the chain re-derives every fact from the
		// frozen shapes.
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: unknown envelope fields")
	}
	spec, ok := busSubjectSpecForWireKind(wire.GetKind())
	if !ok {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: kind %d is not in the subject table", wire.GetKind())
	}
	if wire.GetPayloadType() != spec.payloadType {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: payload_type %d does not match kind %s",
			wire.GetPayloadType(), spec.kind)
	}
	participant, err := participantFromWire(wire.GetSenderParticipantType())
	if err != nil {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: %w", err)
	}
	const maxInt64 = uint64(1)<<63 - 1
	if wire.GetIssuedAtUnixMs() > maxInt64 || wire.GetExpiresAtUnixMs() > maxInt64 {
		return BusEnvelope{}, fmt.Errorf("decode Nexus BusEnvelope: timestamp overflows")
	}
	envelope := BusEnvelope{
		SchemaVersion:             wire.GetSchemaVersion(),
		ChainID:                   wire.GetChainId(),
		Subject:                   wire.GetSubject(),
		Kind:                      spec.kind,
		SenderParticipantType:     participant,
		SenderOperatorAddress:     wire.GetSenderOperatorAddress(),
		ServiceAuthorizationNonce: wire.GetServiceAuthorizationNonce(),
		MessageID:                 wire.GetMessageId(),
		Nonce:                     wire.GetNonce(),
		IssuedAtUnixMs:            int64(wire.GetIssuedAtUnixMs()),
		ExpiresAtUnixMs:           int64(wire.GetExpiresAtUnixMs()),
		Payload:                   wire.GetPayload(),
		PayloadDigest:             wire.GetPayloadDigest(),
		Signature:                 wire.GetServiceSignature(),
	}
	if err := envelope.validateWireShape(); err != nil {
		return BusEnvelope{}, err
	}
	return envelope, nil
}

// validateWireShape enforces presence at decode: every projection field must
// carry a value on a task-control message.
//
// A zero service_authorization_nonce is treated as absent, not as a value: it
// is a Keeper read and this repository already uses zero as "unavailable" for
// it. Emitting or accepting zero would put a field on the wire that
// authenticates nothing.
func (e BusEnvelope) validateWireShape() error {
	switch {
	case e.SchemaVersion == 0:
		return fmt.Errorf("decode Nexus BusEnvelope: schema_version is required")
	case strings.TrimSpace(e.ChainID) == "":
		return fmt.Errorf("decode Nexus BusEnvelope: chain_id is required")
	case strings.TrimSpace(e.Subject) == "":
		return fmt.Errorf("decode Nexus BusEnvelope: subject is required")
	case e.Kind == "":
		return fmt.Errorf("decode Nexus BusEnvelope: kind is required")
	case e.SenderParticipantType == "":
		return fmt.Errorf("decode Nexus BusEnvelope: sender_participant_type is required")
	case strings.TrimSpace(e.SenderOperatorAddress) == "":
		return fmt.Errorf("decode Nexus BusEnvelope: sender_operator_address is required")
	case e.ServiceAuthorizationNonce == 0:
		return fmt.Errorf("decode Nexus BusEnvelope: service_authorization_nonce is required")
	case strings.TrimSpace(e.MessageID) == "":
		return fmt.Errorf("decode Nexus BusEnvelope: message_id is required")
	case len(e.Nonce) != bus.NonceSize:
		return fmt.Errorf("decode Nexus BusEnvelope: nonce must contain %d bytes, got %d",
			bus.NonceSize, len(e.Nonce))
	case e.IssuedAtUnixMs == 0:
		return fmt.Errorf("decode Nexus BusEnvelope: issued_at_unix_ms is required")
	case e.ExpiresAtUnixMs == 0:
		return fmt.Errorf("decode Nexus BusEnvelope: expires_at_unix_ms is required")
	case len(e.PayloadDigest) != sha256.Size:
		return fmt.Errorf("decode Nexus BusEnvelope: payload_digest must contain %d bytes, got %d",
			sha256.Size, len(e.PayloadDigest))
	case len(e.Payload) == 0:
		return fmt.Errorf("decode Nexus BusEnvelope: payload is required")
	default:
		return nil
	}
}

// DecodePayload decodes the exact transmitted payload bytes into dst and
// refuses unknown top-level fields. It must only run after the frame
// authenticated: the contract has receivers decode only after the signature
// verifies.
func (e BusEnvelope) DecodePayload(dst proto.Message) error {
	if err := proto.Unmarshal(e.Payload, dst); err != nil {
		return fmt.Errorf("decode Nexus %s payload: %w", e.Kind, err)
	}
	if unknown := dst.ProtoReflect().GetUnknown(); len(unknown) > 0 {
		return fmt.Errorf("decode Nexus %s payload: unknown payload fields", e.Kind)
	}
	return nil
}

// ValidateEnvelopeIntrinsics checks everything about a frame that is true or
// false without reference to what the caller expected: the wire shape, the
// fields the contract fixes to a constant, the internal agreement between
// kind, participant type and subject, and the payload digest against the
// exact transmitted payload bytes.
//
// It is separate from Validate because the inbound authenticator has no
// expected kind to compare against - it accepts whatever the subject
// legitimately carries - yet it must still refuse a frame that contradicts
// itself. Both paths call this, so neither can drift into enforcing less than
// the other.
func (e BusEnvelope) ValidateEnvelopeIntrinsics() error {
	if err := e.validateWireShape(); err != nil {
		return err
	}
	switch {
	case e.SchemaVersion != BusEnvelopeSchemaVersion:
		return fmt.Errorf("Nexus BusEnvelope schema_version = %d, want %d", e.SchemaVersion, BusEnvelopeSchemaVersion)
	case e.IssuedAtUnixMs <= 0:
		return fmt.Errorf("Nexus BusEnvelope issued_at_unix_ms is required")
	case e.ExpiresAtUnixMs <= e.IssuedAtUnixMs:
		return fmt.Errorf("Nexus BusEnvelope expires_at_unix_ms must be after issued_at_unix_ms")
	}
	if err := validateSenderParticipant(e.Kind, e.SenderParticipantType); err != nil {
		return err
	}
	// payload_digest is on the wire (field 14) and derived from the payload, so
	// the two can disagree. Recompute over the EXACT transmitted bytes and
	// compare; the signing projection commits the recomputed value, so without
	// this check on the receive path the transmitted field would be
	// unconstrained.
	digest := bus.PayloadDigest(e.Payload)
	if !bytes.Equal(e.PayloadDigest, digest[:]) {
		return fmt.Errorf("Nexus BusEnvelope payload_digest does not commit the transmitted payload")
	}
	return validateEnvelopeSubjectPlaceholder(e)
}

// Validate is the structural half of the fixed verification order: shape and
// schema, then the actual subject and kind, then chain id and expiry. It runs
// before the signature, and nothing may advance on a failure.
func (e BusEnvelope) Validate(want EnvelopeValidation) error {
	now := want.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := e.ValidateEnvelopeIntrinsics(); err != nil {
		return err
	}
	switch {
	case e.Kind != want.Kind:
		return fmt.Errorf("Nexus BusEnvelope kind = %q, want %q", e.Kind, want.Kind)
	case e.ChainID != strings.TrimSpace(want.ChainID):
		return fmt.Errorf("Nexus BusEnvelope chain_id = %q, want %q", e.ChainID, strings.TrimSpace(want.ChainID))
	case e.Subject != strings.TrimSpace(want.ActualSubject):
		return fmt.Errorf("Nexus BusEnvelope subject = %q, actual %q", e.Subject, strings.TrimSpace(want.ActualSubject))
	case now.UnixMilli() > e.ExpiresAtUnixMs:
		return fmt.Errorf("Nexus BusEnvelope expired at %d", e.ExpiresAtUnixMs)
	}
	return nil
}

// newBusMessageIDV7 mints field 8, a UUIDv7 string. UUIDv7 is time-ordered by
// construction: a receiver can bound how far back a replay window has to
// reach, and stored ids sort by issue time without a second column.
//
// Layout per RFC 9562: 48-bit big-endian Unix milliseconds, 4-bit version 7,
// 12 random bits, 2-bit variant 0b10, 62 random bits. The timestamp is the
// envelope's own issued_at so the id and field 10 cannot disagree.
func newBusMessageIDV7(random io.Reader, issuedAt time.Time) (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", fmt.Errorf("generate Nexus envelope message id: %w", err)
	}
	millis := issuedAt.UnixMilli()
	if millis < 0 {
		return "", fmt.Errorf("Nexus envelope issued_at %s precedes the UUIDv7 epoch", issuedAt.Format(time.RFC3339))
	}
	if millis >= 1<<48 {
		return "", fmt.Errorf("Nexus envelope issued_at %s exceeds the 48-bit UUIDv7 timestamp", issuedAt.Format(time.RFC3339))
	}
	raw[0] = byte(millis >> 40)
	raw[1] = byte(millis >> 32)
	raw[2] = byte(millis >> 24)
	raw[3] = byte(millis >> 16)
	raw[4] = byte(millis >> 8)
	raw[5] = byte(millis)
	raw[6] = (raw[6] & 0x0f) | 0x70
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// validateBusMessageIDV7 refuses field 8 unless it is a lowercase hyphenated
// UUID whose version nibble is 7 and whose variant bits are 0b10. It runs only
// where Cortex mints an id; the receive path bounds freshness with the
// timestamp fields and treats the id as an opaque dedup key.
func validateBusMessageIDV7(id string) error {
	if len(id) != 36 {
		return fmt.Errorf("Nexus BusEnvelope message_id %q is not a 36-character UUID", id)
	}
	for i, r := range id {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return fmt.Errorf("Nexus BusEnvelope message_id %q is not a hyphenated UUID", id)
			}
		default:
			if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
				return fmt.Errorf("Nexus BusEnvelope message_id %q must be lowercase hex", id)
			}
		}
	}
	if id[14] != '7' {
		return fmt.Errorf("Nexus BusEnvelope message_id %q is UUID version %c, want 7", id, id[14])
	}
	switch id[19] {
	case '8', '9', 'a', 'b':
	default:
		return fmt.Errorf("Nexus BusEnvelope message_id %q does not carry the RFC 9562 variant bits", id)
	}
	return nil
}

func validateEnvelopeSubjectPlaceholder(e BusEnvelope) error {
	spec, ok := busSubjectSpecForSubject(e.Subject)
	if !ok || spec.kind != e.Kind {
		return fmt.Errorf("Nexus BusEnvelope kind %q is inconsistent with subject %q", e.Kind, e.Subject)
	}
	placeholder := strings.TrimPrefix(e.Subject, spec.prefix)
	// A single token: no further levels and no wildcard. Without the '.'
	// rejection a sender could address trueopen.output-avail.<task>.<anything>
	// and still match the prefix, which is how a subject outside the closed
	// set gets treated as one inside it.
	if placeholder == "" || strings.ContainsAny(placeholder, ".*>") {
		return fmt.Errorf("Nexus BusEnvelope subject placeholder is invalid")
	}
	return nil
}
