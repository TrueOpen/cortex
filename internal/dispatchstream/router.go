package dispatchstream

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// Handler receives authenticated business frames. Returning an error that
// builderclient.IsRetryable reports leaves the frame unacked: the session
// drops the connection and the Builder redelivers it after reconnect. Any
// other error (including builderclient.Permanent) is logged and the frame is
// acked, because it would fail identically on redelivery.
type Handler interface {
	HandleFrame(ctx context.Context, from string /*builder operator*/, frame *nexusv1.DispatchStreamFrameV1) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, from string, frame *nexusv1.DispatchStreamFrameV1) error

func (f HandlerFunc) HandleFrame(ctx context.Context, from string, frame *nexusv1.DispatchStreamFrameV1) error {
	return f(ctx, from, frame)
}

// variant is the DispatchStreamFrameV1 `message` oneof field number.
type variant int32

const (
	variantBinding               variant = 3
	variantHandraise             variant = 4
	variantHandraiseRoot         variant = 5
	variantOffer                 variant = 6
	variantAccept                variant = 7
	variantReject                variant = 8
	variantInputRequest          variant = 9
	variantInputResponse         variant = 10
	variantRevoke                variant = 11
	variantRecordResult          variant = 12
	variantOpenVerify            variant = 13
	variantVerifierHandraise     variant = 14
	variantVerifierAssignment    variant = 15
	variantVerifyResultSubmitted variant = 16
	variantAck                   variant = 17
	variantKeepalive             variant = 18
)

// Frame field numbers outside the oneof.
const (
	frameNonceField  protowire.Number = 1
	frameCursorField protowire.Number = 2
	// DispatchStreamRequest/Response both wrap the frame as field 1.
	envelopeFrameField protowire.Number = 1
)

func (v variant) control() bool {
	return v == variantBinding || v == variantAck || v == variantKeepalive
}

// fromCortex lists the business variants this side sends.
func (v variant) fromCortex() bool {
	switch v {
	case variantHandraise, variantAccept, variantReject, variantInputRequest,
		variantVerifierHandraise, variantVerifyResultSubmitted:
		return true
	}
	return false
}

// fromBuilder lists the business variants a Builder sends.
func (v variant) fromBuilder() bool {
	switch v {
	case variantHandraiseRoot, variantOffer, variantInputResponse, variantRevoke,
		variantRecordResult, variantOpenVerify, variantVerifierAssignment:
		return true
	}
	return false
}

var frameOneof = (&nexusv1.DispatchStreamFrameV1{}).ProtoReflect().Descriptor().Oneofs().ByName("message")

// variantOf maps an inner message to the oneof field carrying its type.
func variantOf(msg proto.Message) (variant, error) {
	if msg == nil {
		return 0, fmt.Errorf("dispatchstream: nil message")
	}
	name := msg.ProtoReflect().Descriptor().FullName()
	fields := frameOneof.Fields()
	for i := 0; i < fields.Len(); i++ {
		if f := fields.Get(i); f.Message() != nil && f.Message().FullName() == name {
			return variant(f.Number()), nil
		}
	}
	return 0, fmt.Errorf("dispatchstream: %s is not a DispatchStreamFrameV1 variant", name)
}

// inner returns the selected oneof variant and its message.
func inner(frame *nexusv1.DispatchStreamFrameV1) (variant, proto.Message, bool) {
	m := frame.ProtoReflect()
	f := m.WhichOneof(frameOneof)
	if f == nil {
		return 0, nil, false
	}
	return variant(f.Number()), m.Get(f).Message().Interface(), true
}

// encodeFrame builds DispatchStreamFrameV1 bytes around an already encoded
// inner message, so a replayed business message goes out byte-for-byte as it
// was first persisted (the contract forbids altering retained messages).
func encodeFrame(nonce []byte, cursor uint64, v variant, payload []byte) []byte {
	var b []byte
	b = protowire.AppendTag(b, frameNonceField, protowire.BytesType)
	b = protowire.AppendBytes(b, nonce)
	if cursor != 0 {
		b = protowire.AppendTag(b, frameCursorField, protowire.VarintType)
		b = protowire.AppendVarint(b, cursor)
	}
	b = protowire.AppendTag(b, protowire.Number(v), protowire.BytesType)
	return protowire.AppendBytes(b, payload)
}

// encodeControl builds a control frame (cursor 0) around a control message.
func encodeControl(nonce []byte, msg proto.Message) ([]byte, error) {
	v, err := variantOf(msg)
	if err != nil {
		return nil, err
	}
	raw, err := dispatchwire.Raw(msg)
	if err != nil {
		return nil, err
	}
	return encodeFrame(nonce, 0, v, raw), nil
}

// wrapEnvelope wraps frame bytes as DispatchStreamRequest{frame}.
func wrapEnvelope(frame []byte) []byte {
	b := protowire.AppendTag(nil, envelopeFrameField, protowire.BytesType)
	return protowire.AppendBytes(b, frame)
}

// unwrapEnvelope strictly extracts the frame bytes from a
// DispatchStreamResponse: exactly one field 1, length-delimited, nothing else.
// The wrapper is outside wire's tables, so this is the only check it gets;
// the frame itself then goes through dispatch.ValidateMessage.
func unwrapEnvelope(raw []byte) ([]byte, error) {
	var frame []byte
	found := false
	for b := raw; len(b) > 0; {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("dispatchstream: response envelope: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num != envelopeFrameField || typ != protowire.BytesType {
			return nil, fmt.Errorf("dispatchstream: response envelope carries unexpected field %d", num)
		}
		if found {
			return nil, fmt.Errorf("dispatchstream: response envelope repeats its frame")
		}
		v, m := protowire.ConsumeBytes(b)
		if m < 0 {
			return nil, fmt.Errorf("dispatchstream: response envelope: %w", protowire.ParseError(m))
		}
		frame, found, b = v, true, b[m:]
	}
	if !found {
		return nil, fmt.Errorf("dispatchstream: response envelope has no frame")
	}
	return frame, nil
}
