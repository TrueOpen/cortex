package nodewire

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/TrueOpen/cortex/internal/codec"
)

// SignedOrderV2 is parsed strictly: unknown fields, duplicate singular fields
// and mismatched protobuf wire types are rejected before deriving task_hash.
const (
	signedOrderFieldOrder            = 1
	signedOrderFieldSignatureScheme  = 2
	signedOrderFieldUserSignature    = 3
	signedOrderFieldSignatureChainID = 4

	signedOrderSignatureScheme = "eip712"
	signedOrderSignatureLen    = 65
)

// signedOrderV2 is a decoded carrier: the order the user signed, and the
// signature metadata that travels beside it rather than inside it. task_hash is
// derived from the TaskOrderV3 fields alone, so none of this metadata reaches
// task identity -- the same order signed under another chain id is the same
// task, and no replay or dedup decision may say otherwise.
type signedOrderV2 struct {
	order            taskOrderV3
	signatureScheme  string
	userSignature    []byte
	signatureChainID uint64
}

// TaskOrderHashSignedOrderHex is TaskOrderHashAndFactsSignedOrderHex without the
// facts, for callers that only need the identity.
func TaskOrderHashSignedOrderHex(value string) (codec.Hash, error) {
	digest, _, err := TaskOrderHashAndFactsSignedOrderHex(value)
	return digest, err
}

// TaskOrderHashAndFactsSignedOrderHex decodes the SignedOrderV2 carrier and
// returns the canonical task_hash of the order it wraps, plus the facts the
// caller cross-checks the surrounding payload against. The returned facts carry
// SignatureScheme and UserSignature, which the JSON carrier cannot supply.
func TaskOrderHashAndFactsSignedOrderHex(value string) (codec.Hash, TaskOrderFacts, error) {
	if value == "" {
		return codec.Hash{}, TaskOrderFacts{}, fmt.Errorf("SignedOrderV2 carrier is empty")
	}
	if value != strings.ToLower(value) {
		return codec.Hash{}, TaskOrderFacts{}, fmt.Errorf("SignedOrderV2 carrier must be lowercase hex")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return codec.Hash{}, TaskOrderFacts{}, fmt.Errorf("SignedOrderV2 carrier must be lowercase hex: %w", err)
	}
	carrier, err := decodeSignedOrderV2(raw)
	if err != nil {
		return codec.Hash{}, TaskOrderFacts{}, err
	}
	digest, err := taskOrderHash(carrier.order)
	if err != nil {
		return codec.Hash{}, TaskOrderFacts{}, err
	}
	facts := taskOrderFacts(carrier.order)
	facts.SignatureScheme, facts.UserSignature = carrier.signatureScheme, hex.EncodeToString(carrier.userSignature)
	facts.SignatureChainID = carrier.signatureChainID
	return digest, facts, nil
}

func decodeSignedOrderV2(raw []byte) (signedOrderV2, error) {
	var (
		carrier   signedOrderV2
		seenOrder bool
	)
	err := walkProtoMessage("SignedOrderV2", raw, func(field protoField) error {
		switch field.number {
		case signedOrderFieldOrder:
			nested, err := field.message()
			if err != nil {
				return err
			}
			decoded, err := decodeTaskOrderV3(nested)
			if err != nil {
				return err
			}
			carrier.order, seenOrder = decoded, true
			return nil
		case signedOrderFieldSignatureScheme:
			return field.assignString(&carrier.signatureScheme)
		case signedOrderFieldUserSignature:
			return field.assignBytes(&carrier.userSignature)
		case signedOrderFieldSignatureChainID:
			if err := field.uint64(&carrier.signatureChainID); err != nil {
				return err
			}
			// The signing wallet picks this value, so it is bounded rather than
			// trusted: 1..MaxInt64, with an explicitly encoded 0 refused as
			// malformed. A carrier that omits the field was signed when the
			// chain's own EVM chain id was the authoritative domain, and stays
			// legal so orders in flight across the upgrade still decode.
			if carrier.signatureChainID == 0 || carrier.signatureChainID > math.MaxInt64 {
				return fmt.Errorf("SignedOrderV2 signature_chain_id must be in 1..%d", int64(math.MaxInt64))
			}
			return nil
		}
		return fmt.Errorf("SignedOrderV2 carries unknown field %d", field.number)
	})
	if err != nil {
		return signedOrderV2{}, err
	}
	if !seenOrder {
		return signedOrderV2{}, fmt.Errorf("SignedOrderV2 carries no order")
	}
	// EIP-712 signatures are recoverable R||S||V with canonical low-S.
	if carrier.signatureScheme != signedOrderSignatureScheme {
		return signedOrderV2{}, fmt.Errorf("SignedOrderV2 signature_scheme must be %q", signedOrderSignatureScheme)
	}
	if len(carrier.userSignature) != signedOrderSignatureLen {
		return signedOrderV2{}, fmt.Errorf("SignedOrderV2 user_signature must be %d bytes", signedOrderSignatureLen)
	}
	if carrier.userSignature[64] != 27 && carrier.userSignature[64] != 28 {
		return signedOrderV2{}, fmt.Errorf("SignedOrderV2 user_signature recovery id must be 27 or 28")
	}
	orderN, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	r, s := new(big.Int).SetBytes(carrier.userSignature[:32]), new(big.Int).SetBytes(carrier.userSignature[32:64])
	if r.Sign() == 0 || r.Cmp(orderN) >= 0 || s.Sign() == 0 || s.Cmp(new(big.Int).Rsh(orderN, 1)) > 0 {
		return signedOrderV2{}, fmt.Errorf("SignedOrderV2 user_signature must contain valid r and low-S")
	}
	return carrier, nil
}

// decodeTaskOrderV3 reads the 28 fields of TaskOrderV3 in their proto wire
// types. Absent fields keep their proto3 zero value; taskOrderHash
// rejects every zero the frozen scope forbids, so an order that omits a required
// field fails there rather than needing a presence bit here.
func decodeTaskOrderV3(raw []byte) (taskOrderV3, error) {
	var order taskOrderV3
	err := walkProtoMessage("TaskOrderV3", raw, func(field protoField) error {
		switch field.number {
		case 1:
			return field.uint32(&order.SchemaVersion)
		case 2:
			return field.assignString(&order.ChainID)
		case 3:
			return field.assignString(&order.UserAddress)
		case 4:
			return field.assignBytes((*[]byte)(&order.SessionID))
		case 5:
			return field.uint64((*uint64)(&order.OrderSequence))
		case 6:
			return field.assignBytes((*[]byte)(&order.ModelID))
		case 7:
			return field.uint32(&order.ProfileVersion)
		case 8:
			return field.uint32((*uint32)(&order.TaskType))
		case 9:
			return field.assignBytes((*[]byte)(&order.InputHash))
		case 10:
			return field.uint64((*uint64)(&order.InputSizeBytes))
		case 11:
			return field.uint32(&order.InputBucket)
		case 12:
			return field.uint32(&order.OutputBudgetBucket)
		case 13:
			nested, err := field.message()
			if err != nil {
				return err
			}
			order.GenerationParams, err = decodeGenerationParamsV1(nested)
			return err
		case 14, 15, 16, 17:
			nested, err := field.message()
			if err != nil {
				return err
			}
			amount, err := decodeAmount(nested)
			if err != nil {
				return err
			}
			targets := []*taskOrderAmount{
				&order.PriceBid, &order.MaxFee,
				&order.AssignmentPriorityFee, &order.TxFeeReserve,
			}
			*targets[field.number-14] = amount
			return nil
		case 18:
			return field.uint64((*uint64)(&order.EarliestSubmitHeight))
		case 19:
			return field.uint64((*uint64)(&order.OrderExpireHeight))
		case 20:
			nested, err := field.message()
			if err != nil {
				return err
			}
			order.DeadlinePolicy, err = decodeDeadlinePolicyV1(nested)
			return err
		case 21:
			return field.uint64((*uint64)(&order.TimeoutBucketVersion))
		case 22:
			return field.uint64((*uint64)(&order.SessionAnchorHeight))
		case 23:
			return field.assignBytes((*[]byte)(&order.SessionAnchorBlockHash))
		case 24:
			return field.assignString(&order.BuilderSetID)
		case 25:
			return field.assignBytes((*[]byte)(&order.BuilderSetHash))
		case 26:
			return field.uint32((*uint32)(&order.PayloadMode))
		case 27:
			return field.assignBytes((*[]byte)(&order.InputKeyCommitment))
		case 28:
			return field.assignBytes((*[]byte)(&order.UserRecipientPubkey))
		}
		return fmt.Errorf("TaskOrderV3 carries unknown field %d", field.number)
	})
	if err != nil {
		return taskOrderV3{}, err
	}
	return order, nil
}

func decodeGenerationParamsV1(raw []byte) (taskOrderGenerationParams, error) {
	var params taskOrderGenerationParams
	err := walkProtoMessage("GenerationParamsV1", raw, func(field protoField) error {
		switch field.number {
		case 1:
			return field.uint32(&params.SchemaVersion)
		case 2:
			return field.uint64((*uint64)(&params.MaxOutputTokens))
		case 3:
			return field.uint64((*uint64)(&params.MaxOutputDuration))
		case 4:
			nested, err := field.message()
			if err != nil {
				return err
			}
			params.DecodingParams, err = decodeDecodingParamsV1(nested)
			return err
		}
		return fmt.Errorf("GenerationParamsV1 carries unknown field %d", field.number)
	})
	return params, err
}

func decodeDecodingParamsV1(raw []byte) (taskOrderDecodingParams, error) {
	var params taskOrderDecodingParams
	err := walkProtoMessage("DecodingParamsV1", raw, func(field protoField) error {
		switch field.number {
		case 1:
			return field.bool(&params.SamplingEnabled)
		case 2:
			return field.uint32(&params.TemperatureMilli)
		case 3:
			return field.uint32(&params.TopPPPM)
		case 4:
			return field.uint32(&params.TopK)
		case 5:
			return field.uint64((*uint64)(&params.Seed))
		case 6:
			return field.int32(&params.PresencePenaltyMilli)
		case 7:
			return field.int32(&params.FrequencyPenaltyMilli)
		case 8:
			return field.uint32(&params.RepetitionPenaltyPPM)
		case 9:
			value, err := field.string()
			if err != nil {
				return err
			}
			params.StopSequences = append(params.StopSequences, value)
			return nil
		case 10:
			// repeated uint32: packed is what a proto3 encoder emits, but the
			// unpacked spelling is equally valid on the wire and decodes to the
			// same list, so both are read. Order is preserved either way, and
			// taskOrderGenerationFrame still requires it to be sorted and unique.
			values, err := field.repeatedUint32()
			if err != nil {
				return err
			}
			params.StopTokenIDs = append(params.StopTokenIDs, values...)
			return nil
		}
		return fmt.Errorf("DecodingParamsV1 carries unknown field %d", field.number)
	})
	return params, err
}

func decodeAmount(raw []byte) (taskOrderAmount, error) {
	var amount taskOrderAmount
	err := walkProtoMessage("Amount", raw, func(field protoField) error {
		if field.number == 1 {
			return field.assignString(&amount.AtomicUnits)
		}
		return fmt.Errorf("Amount carries unknown field %d", field.number)
	})
	return amount, err
}

func decodeDeadlinePolicyV1(raw []byte) (taskOrderDeadlinePolicy, error) {
	var policy taskOrderDeadlinePolicy
	err := walkProtoMessage("DeadlinePolicyV1", raw, func(field protoField) error {
		if field.number == 1 {
			return field.uint32((*uint32)(&policy.LatencyClass))
		}
		return fmt.Errorf("DeadlinePolicyV1 carries unknown field %d", field.number)
	})
	return policy, err
}

// protoField is one decoded tag plus its payload. Accessors name the frozen
// table's type for the field, so reading a field through the wrong accessor is a
// decode error rather than a silent reinterpretation.
type protoField struct {
	message_ string
	number   protowire.Number
	typ      protowire.Type
	varint   uint64
	raw      []byte
	repeated bool
}

func (f protoField) wrongType(want string) error {
	return fmt.Errorf("%s field %d is not a %s on the wire", f.message_, f.number, want)
}

func (f protoField) message() ([]byte, error) {
	if f.typ != protowire.BytesType {
		return nil, f.wrongType("message")
	}
	return f.raw, nil
}

func (f protoField) bytes() ([]byte, error) {
	if f.typ != protowire.BytesType {
		return nil, f.wrongType("bytes")
	}
	return f.raw, nil
}

func (f protoField) string() (string, error) {
	if f.typ != protowire.BytesType {
		return "", f.wrongType("string")
	}
	if !utf8.Valid(f.raw) {
		return "", fmt.Errorf("%s field %d is not valid UTF-8", f.message_, f.number)
	}
	return string(f.raw), nil
}

func (f protoField) assignString(target *string) error {
	value, err := f.string()
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func (f protoField) assignBytes(target *[]byte) error {
	value, err := f.bytes()
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func (f protoField) uint64(target *uint64) error {
	if f.typ != protowire.VarintType {
		return f.wrongType("varint")
	}
	*target = f.varint
	return nil
}

func (f protoField) uint32(target *uint32) error {
	if f.typ != protowire.VarintType {
		return f.wrongType("varint")
	}
	if f.varint > math.MaxUint32 {
		return fmt.Errorf("%s field %d exceeds uint32", f.message_, f.number)
	}
	*target = uint32(f.varint)
	return nil
}

func (f protoField) int32(target *int32) error {
	if f.typ != protowire.VarintType {
		return f.wrongType("varint")
	}
	// proto3 encodes a negative int32 as the sign-extended 64-bit varint, so the
	// only accepted encodings are the ones that round-trip through int32.
	value := int32(int64(f.varint))
	if uint64(int64(value)) != f.varint {
		return fmt.Errorf("%s field %d is not a sign-extended int32", f.message_, f.number)
	}
	*target = value
	return nil
}

func (f protoField) bool(target *bool) error {
	if f.typ != protowire.VarintType {
		return f.wrongType("varint")
	}
	if f.varint > 1 {
		return fmt.Errorf("%s field %d is not a canonical bool", f.message_, f.number)
	}
	*target = f.varint == 1
	return nil
}

func (f protoField) repeatedUint32() ([]uint32, error) {
	if f.typ == protowire.VarintType {
		if f.varint > math.MaxUint32 {
			return nil, fmt.Errorf("%s field %d exceeds uint32", f.message_, f.number)
		}
		return []uint32{uint32(f.varint)}, nil
	}
	if f.typ != protowire.BytesType {
		return nil, f.wrongType("packed varint")
	}
	var values []uint32
	for rest := f.raw; len(rest) > 0; {
		value, size := protowire.ConsumeVarint(rest)
		if size < 0 {
			return nil, fmt.Errorf("%s field %d has a malformed packed varint: %w", f.message_, f.number, protowire.ParseError(size))
		}
		if value > math.MaxUint32 {
			return nil, fmt.Errorf("%s field %d exceeds uint32", f.message_, f.number)
		}
		values, rest = append(values, uint32(value)), rest[size:]
	}
	return values, nil
}

// repeatedProtoFields lists the field numbers that may legitimately appear more
// than once, per message. Everything else is singular, and a second occurrence
// is a decode error.
var repeatedProtoFields = map[string]map[protowire.Number]bool{
	"DecodingParamsV1": {9: true, 10: true},
}

func walkProtoMessage(message string, raw []byte, visit func(protoField) error) error {
	seen := map[protowire.Number]bool{}
	for len(raw) > 0 {
		number, typ, size := protowire.ConsumeTag(raw)
		if size < 0 {
			return fmt.Errorf("%s is not a well-formed proto message: %w", message, protowire.ParseError(size))
		}
		raw = raw[size:]
		field := protoField{message_: message, number: number, typ: typ, repeated: repeatedProtoFields[message][number]}
		switch typ {
		case protowire.VarintType:
			field.varint, size = protowire.ConsumeVarint(raw)
		case protowire.BytesType:
			field.raw, size = protowire.ConsumeBytes(raw)
		default:
			// Nothing in the frozen §5.13 table is fixed32, fixed64 or a group,
			// so a field that arrives as one is refused instead of skipped: this
			// decoder has no unknown-field bucket to put it in.
			return fmt.Errorf("%s field %d uses unsupported wire type %d", message, number, typ)
		}
		if size < 0 {
			return fmt.Errorf("%s field %d is truncated: %w", message, number, protowire.ParseError(size))
		}
		raw = raw[size:]
		if seen[number] && !field.repeated {
			return fmt.Errorf("%s field %d appears more than once", message, number)
		}
		seen[number] = true
		if err := visit(field); err != nil {
			return err
		}
	}
	return nil
}
