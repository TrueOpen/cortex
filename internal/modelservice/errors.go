package modelservice

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The model boundary has exactly three kinds of failure, and the difference
// between them is what the scheduler does next -- not how severe they look.
//
// Until now a caller could only tell them apart by matching the message text,
// and nothing did: every failure took the same road, RetryCount++ and another
// full generation. A deterministic refusal therefore spent the whole retry
// budget re-asking a question whose answer cannot change, and on a real vLLM
// node each of those attempts is a multi-minute occupation of the only GPU the
// node has. That is the loop this classification exists to break: the class is
// the scheduler's instruction, carried on the error itself so it survives
// wrapping and needs no string comparison.
//
// The three are deliberately not a severity ladder:
//
//   - FaultTransient       the same call may succeed later. Retry it.
//   - FaultDeterministic   the same inputs reproduce it. Re-running the model
//     changes nothing, so stop calling the model and say why.
//   - FaultRegenerationForbidden  re-running the model is not merely useless,
//     it is unsafe: signed material naming the previous run's bytes already
//     exists, and a second run would sign different bytes for one task.
//
// FaultUnclassified is the default for an unmarked error and keeps the previous
// behaviour (bounded retries), because an error nobody has classified is not
// evidence that retrying is pointless.
type FaultClass uint8

const (
	FaultUnclassified FaultClass = iota
	FaultTransient
	FaultDeterministic
	FaultRegenerationForbidden
)

func (c FaultClass) String() string {
	switch c {
	case FaultTransient:
		return "transient"
	case FaultDeterministic:
		return "deterministic"
	case FaultRegenerationForbidden:
		return "regeneration-forbidden"
	default:
		return "unclassified"
	}
}

// Fault codes for the generation-evidence contract. They are stable operator
// -facing identifiers: a runbook, a dashboard and a durable halt record all name
// the same string, so renaming one is a breaking change to all three.
const (
	// FaultCodeTokenBudgetExceeded: the model returned more generated tokens
	// than the task's frozen max_output_tokens. The receipt would commit to a
	// generation the order never authorised.
	FaultCodeTokenBudgetExceeded = "GENERATION_TOKEN_BUDGET_EXCEEDED"
	// FaultCodeTokenEvidenceCountMismatch: the trace's generated_token_count and
	// the per-token evidence it carries disagree. Nothing about the budget is
	// decided here -- the count itself is not trustworthy yet.
	FaultCodeTokenEvidenceCountMismatch = "GENERATION_TOKEN_EVIDENCE_COUNT_MISMATCH"
	// FaultCodeTokenCountNegative: a negative generated_token_count. Its own
	// code because it is a decode-shaped fault, not an arithmetic one.
	FaultCodeTokenCountNegative = "GENERATION_TOKEN_COUNT_NEGATIVE"
	// FaultCodeTraceUndecodable: the trace artifact is not a decodable envelope.
	FaultCodeTraceUndecodable = "GENERATION_TRACE_UNDECODABLE"
	// FaultCodeTraceGenerationContext: the trace carries a generation context
	// that does not re-derive the task's frozen generation_params_digest.
	FaultCodeTraceGenerationContext = "GENERATION_TRACE_CONTEXT_INVALID"
	// FaultCodeTraceIdentityMismatch: the trace names a different model or
	// profile version than the task does.
	FaultCodeTraceIdentityMismatch = "GENERATION_TRACE_IDENTITY_MISMATCH"
	// FaultCodeTraceOutputMismatch: the output artifact and the trace's own copy
	// of the output are different bytes.
	FaultCodeTraceOutputMismatch = "GENERATION_TRACE_OUTPUT_MISMATCH"
	// FaultCodeTraceTokenIDsHashMismatch: a token-ids hash in the trace does not
	// cover the token vector beside it.
	FaultCodeTraceTokenIDsHashMismatch = "GENERATION_TRACE_TOKEN_IDS_HASH_MISMATCH"
	// FaultCodeTraceNegativeTokenID: a negative token id in the trace.
	FaultCodeTraceNegativeTokenID = "GENERATION_TRACE_NEGATIVE_TOKEN_ID"
	// FaultCodeCheckpointMismatch: the checkpoint artifact contradicts the trace
	// it is supposed to summarise.
	FaultCodeCheckpointMismatch = "GENERATION_CHECKPOINT_MISMATCH"
	// FaultCodeFinishReasonUnsupported: the engine's finish reason cannot be
	// mapped onto a frozen FinishReasonV1 under the task's own parameters.
	FaultCodeFinishReasonUnsupported = "GENERATION_FINISH_REASON_UNSUPPORTED"
	// FaultCodeFinishReasonInconsistent: the finish reason contradicts the
	// generated tokens under the task's parameters (05 section 8.3).
	FaultCodeFinishReasonInconsistent = "GENERATION_FINISH_REASON_INCONSISTENT"
	// FaultCodeResponseEvidenceDisagreement: the InferResponse's own count or
	// finish reason contradicts the evidence artifacts it produced.
	FaultCodeResponseEvidenceDisagreement = "GENERATION_RESPONSE_EVIDENCE_DISAGREEMENT"
	// FaultCodeOutputFramesAlreadySigned: this task already has signed output
	// stream frames, so a fresh generation would sign a different prefix under
	// one task hash. Raised by the Worker, not by a model call — the code lives
	// here so every fault code an operator can see has one registry.
	FaultCodeOutputFramesAlreadySigned = "OUTPUT_FRAMES_ALREADY_SIGNED"
)

// FaultField is one scalar diagnostic value carried by a Fault.
//
// Values are scalars only, and that is a rule rather than a convenience: this
// text reaches logs, the admin socket and a durable halt record. Prompts, model
// input, output text, signatures and key material must never be placed here.
// Counts, limits, lengths, identifiers and hashes are what belongs.
type FaultField struct {
	Key   string
	Value string
}

// FaultStr, FaultUint and FaultInt build a FaultField. They exist so that a call
// site reads as a list of measurements rather than a list of Sprintf calls.
func FaultStr(key, value string) FaultField { return FaultField{Key: key, Value: value} }
func FaultUint(key string, v uint64) FaultField {
	return FaultField{Key: key, Value: strconv.FormatUint(v, 10)}
}
func FaultInt(key string, v int) FaultField {
	return FaultField{Key: key, Value: strconv.Itoa(v)}
}

// Fault is a classified model-service failure. It wraps the underlying error so
// errors.Is/errors.As keep working through it, and it is itself discoverable
// with errors.As after any number of fmt.Errorf("%w") wrappings.
type Fault struct {
	Class  FaultClass
	Code   string
	Fields []FaultField
	err    error
}

func (f *Fault) Error() string {
	if f == nil {
		return "<nil model fault>"
	}
	var b strings.Builder
	if f.err != nil {
		b.WriteString(f.err.Error())
	}
	b.WriteString(" [")
	b.WriteString(f.Code)
	for _, field := range f.Fields {
		b.WriteByte(' ')
		b.WriteString(field.Key)
		b.WriteByte('=')
		b.WriteString(field.Value)
	}
	b.WriteByte(']')
	return b.String()
}

func (f *Fault) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.err
}

// NewFault classifies err. A nil err yields nil so the constructors can be used
// inline on a call that may not have failed.
func NewFault(class FaultClass, code string, err error, fields ...FaultField) error {
	if err == nil {
		return nil
	}
	return &Fault{Class: class, Code: code, Fields: fields, err: err}
}

// Transient marks a failure the same call may recover from.
func Transient(code string, err error, fields ...FaultField) error {
	return NewFault(FaultTransient, code, err, fields...)
}

// Deterministic marks a failure the same inputs reproduce. The caller must stop
// re-running the model rather than spend its retry budget on it.
func Deterministic(code string, err error, fields ...FaultField) error {
	return NewFault(FaultDeterministic, code, err, fields...)
}

// RegenerationForbidden marks a failure whose remedy must not be another
// generation, because signed material already names the previous run's bytes.
func RegenerationForbidden(code string, err error, fields ...FaultField) error {
	return NewFault(FaultRegenerationForbidden, code, err, fields...)
}

// ClassOf reports the class of err, looking through every wrapping layer.
//
// The pre-existing retryableError is read as FaultTransient rather than being
// migrated: it already marks exactly that, it is produced on the HTTP path in
// two places and by the gRPC transport, and re-spelling it would be a rename
// with no reader. A Fault found first wins, so an explicit classification always
// outranks the inferred one.
func ClassOf(err error) FaultClass {
	if err == nil {
		return FaultUnclassified
	}
	var fault *Fault
	if errors.As(err, &fault) {
		return fault.Class
	}
	var retryable retryableError
	if errors.As(err, &retryable) {
		return FaultTransient
	}
	return FaultUnclassified
}

// FaultCode is the stable code of err, or "" when it carries no Fault.
func FaultCode(err error) string {
	var fault *Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// FaultFields are the structured diagnostics of err, or nil.
func FaultFields(err error) []FaultField {
	var fault *Fault
	if errors.As(err, &fault) {
		return fault.Fields
	}
	return nil
}

// IsDeterministic reports a failure that re-running the model reproduces.
func IsDeterministic(err error) bool { return ClassOf(err) == FaultDeterministic }

// IsRegenerationForbidden reports a failure whose remedy must not be another
// generation.
func IsRegenerationForbidden(err error) bool { return ClassOf(err) == FaultRegenerationForbidden }

// FaultSummary renders the class and code of err for a log line, and "" when it
// carries neither. It never includes the message, which the caller is already
// printing.
func FaultSummary(err error) string {
	class := ClassOf(err)
	code := FaultCode(err)
	switch {
	case code != "":
		return fmt.Sprintf("%s/%s", class, code)
	case class != FaultUnclassified:
		return class.String()
	default:
		return ""
	}
}
