package dispatchstream

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

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

// variantName is the full protobuf name of a variant's message.
func variantName(v variant) string {
	f := frameOneof.Fields().ByNumber(protowire.Number(v))
	if f == nil || f.Message() == nil {
		return ""
	}
	return string(f.Message().FullName())
}

// innerRaw returns the received bytes of the selected oneof message, taken
// from frame bytes that already passed dispatch.ValidateMessage (so the field
// occurs exactly once and is length-delimited).
func innerRaw(frame []byte, v variant) ([]byte, error) {
	for b := frame; len(b) > 0; {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == protowire.Number(v) && typ == protowire.BytesType {
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			return val, nil
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		b = b[m:]
	}
	return nil, fmt.Errorf("dispatchstream: frame has no variant %d", v)
}

// maxEnvelopeBytes bounds one received DispatchStreamResponse: wire caps the
// frame at dispatch.MaxMessageBytes and the envelope adds only field 1's tag
// and length prefix.
var maxEnvelopeBytes = protowire.SizeTag(envelopeFrameField) + protowire.SizeVarint(dispatch.MaxMessageBytes) + dispatch.MaxMessageBytes

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

// rawFrame carries one stream message's protobuf bytes untouched.
type rawFrame struct{ b []byte }

// rawCodec replaces connect's "proto" codec for this client so the session
// sees the exact bytes the Builder sent and sends exactly the bytes it built.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	f, ok := v.(*rawFrame)
	if !ok {
		return nil, fmt.Errorf("dispatchstream: raw codec cannot marshal %T", v)
	}
	return f.b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	f, ok := v.(*rawFrame)
	if !ok {
		return fmt.Errorf("dispatchstream: raw codec cannot unmarshal into %T", v)
	}
	f.b = append([]byte(nil), data...) // connect reuses its read buffers
	return nil
}
