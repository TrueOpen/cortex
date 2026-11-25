package chainclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The queries in this file belong to the Verifier-panel audit contract (wire
// v0.6.3-verifier-flow.1). The generated bindings in proto/ predate it, so the
// few fields Cortex needs are read from the wire encoding directly; every
// field number below is the contract's. A chain that does not serve a query
// answers ErrQueryUnsupported, which callers treat as "the feature is off".

// ErrQueryUnsupported is a chain that does not implement the query.
var ErrQueryUnsupported = errors.New("Keeper query is not supported by this chain")

// Pause reason bits of WorkerQuota.pause_reasons.
const (
	PauseReasonLateSubmission uint32 = 1
	PauseReasonUnbonding      uint32 = 2
	PauseReasonJailed         uint32 = 4
)

// WorkerQuotaSnapshot is hub.v1.QueryWorkerQuotaResponse.
type WorkerQuotaSnapshot struct {
	Period         uint64
	Quota          uint64
	ReservedValue  uint64
	SettledValue   uint64
	Remaining      uint64
	Enforced       bool
	DispatchPaused bool
	PauseReasons   uint32
}

// PauseReasonNames spells the pause bits, in bit order.
func PauseReasonNames(bits uint32) []string {
	var out []string
	for _, r := range []struct {
		bit  uint32
		name string
	}{{PauseReasonLateSubmission, "late_submission"}, {PauseReasonUnbonding, "unbonding"}, {PauseReasonJailed, "jailed"}} {
		if bits&r.bit != 0 {
			out = append(out, r.name)
		}
	}
	if rest := bits &^ (PauseReasonLateSubmission | PauseReasonUnbonding | PauseReasonJailed); rest != 0 {
		out = append(out, fmt.Sprintf("unknown(%d)", rest))
	}
	return out
}

// WorkerQuota reads the Worker's order quota and pause state for the current
// settlement period.
func (c *KeeperABCIClient) WorkerQuota(ctx context.Context, operatorAddress string) (WorkerQuotaSnapshot, error) {
	request := protowire.AppendTag(nil, 1, protowire.BytesType)
	request = protowire.AppendString(request, strings.TrimSpace(operatorAddress))
	raw, err := c.queryRaw(ctx, hubQuery+"WorkerQuota", request)
	if err != nil {
		return WorkerQuotaSnapshot{}, err
	}
	return decodeWorkerQuota(raw)
}

func decodeWorkerQuota(raw []byte) (WorkerQuotaSnapshot, error) {
	var s WorkerQuotaSnapshot
	err := walkFields(raw, func(num protowire.Number, typ protowire.Type, varint uint64, _ []byte) {
		if typ != protowire.VarintType {
			return
		}
		switch num {
		case 1:
			s.Period = varint
		case 2:
			s.Quota = varint
		case 3:
			s.ReservedValue = varint
		case 4:
			s.SettledValue = varint
		case 5:
			s.Remaining = varint
		case 6:
			s.Enforced = varint != 0
		case 7:
			s.DispatchPaused = varint != 0
		case 8:
			s.PauseReasons = uint32(varint)
		}
	})
	if err != nil {
		return WorkerQuotaSnapshot{}, fmt.Errorf("decode Keeper WorkerQuota response: %w", err)
	}
	return s, nil
}

// PanelAssignment is one task.v1.AnchorPanelAssignmentV1: an open panel round
// the operator is a member of and has not voted in.
type PanelAssignment struct {
	TaskID             string // lowercase hex
	PanelRound         uint32
	Kind               uint32 // AnchorPanelRoundKindV1
	AssignmentHeight   uint64
	VoteDeadlineHeight uint64
	// Audit is the AnchorAuditState row exactly as the chain encoded it. The
	// Verifier program decodes it; Cortex only carries it.
	Audit            []byte
	ModelID          string // lowercase hex
	ProfileVersion   uint32
	RegistrationHash string // lowercase hex
}

// PanelAssignments pages through the operator's open panel assignments.
func (c *KeeperABCIClient) PanelAssignments(ctx context.Context, operatorAddress string) ([]PanelAssignment, error) {
	const pageLimit, maxPages = 200, 64
	var out []PanelAssignment
	var startAfter []byte
	for page := 0; page < maxPages; page++ {
		request := protowire.AppendTag(nil, 1, protowire.BytesType)
		request = protowire.AppendString(request, strings.TrimSpace(operatorAddress))
		if len(startAfter) != 0 {
			request = protowire.AppendTag(request, 2, protowire.BytesType)
			request = protowire.AppendBytes(request, startAfter)
		}
		request = protowire.AppendTag(request, 3, protowire.VarintType)
		request = protowire.AppendVarint(request, pageLimit)
		raw, err := c.queryRaw(ctx, taskQuery+"AnchorPanelAssignments", request)
		if err != nil {
			return nil, err
		}
		rows, next, err := decodePanelAssignments(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(next) == 0 {
			return out, nil
		}
		startAfter = next
	}
	return out, nil
}

func decodePanelAssignments(raw []byte) (rows []PanelAssignment, next []byte, err error) {
	var inner error
	err = walkFields(raw, func(num protowire.Number, typ protowire.Type, _ uint64, b []byte) {
		if typ != protowire.BytesType {
			return
		}
		switch num {
		case 1:
			row, e := decodePanelAssignment(b)
			if e != nil {
				inner = e
				return
			}
			rows = append(rows, row)
		case 2:
			next = append([]byte(nil), b...)
		}
	})
	if err == nil {
		err = inner
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decode Keeper AnchorPanelAssignments response: %w", err)
	}
	return rows, next, nil
}

func decodePanelAssignment(raw []byte) (PanelAssignment, error) {
	var a PanelAssignment
	err := walkFields(raw, func(num protowire.Number, typ protowire.Type, varint uint64, b []byte) {
		switch {
		case num == 1 && typ == protowire.BytesType:
			a.TaskID = hex.EncodeToString(b)
		case num == 2 && typ == protowire.VarintType:
			a.PanelRound = uint32(varint)
		case num == 3 && typ == protowire.VarintType:
			a.Kind = uint32(varint)
		case num == 4 && typ == protowire.VarintType:
			a.AssignmentHeight = varint
		case num == 5 && typ == protowire.VarintType:
			a.VoteDeadlineHeight = varint
		case num == 6 && typ == protowire.BytesType:
			a.Audit = append([]byte(nil), b...)
		case num == 7 && typ == protowire.BytesType:
			a.ModelID = hex.EncodeToString(b)
		case num == 8 && typ == protowire.VarintType:
			a.ProfileVersion = uint32(varint)
		case num == 9 && typ == protowire.BytesType:
			a.RegistrationHash = hex.EncodeToString(b)
		}
	})
	if err != nil {
		return PanelAssignment{}, err
	}
	if len(a.TaskID) != 64 || a.PanelRound == 0 {
		return PanelAssignment{}, fmt.Errorf("panel assignment without a 32-byte task id or a round number")
	}
	return a, nil
}

// walkFields calls visit for every top-level field of a protobuf message.
func walkFields(raw []byte, visit func(num protowire.Number, typ protowire.Type, varint uint64, b []byte)) error {
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return protowire.ParseError(n)
		}
		raw = raw[n:]
		switch typ {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			visit(num, typ, v, nil)
			raw = raw[m:]
		case protowire.BytesType:
			b, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			visit(num, typ, 0, b)
			raw = raw[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, raw)
			if m < 0 {
				return protowire.ParseError(m)
			}
			raw = raw[m:]
		}
	}
	return nil
}

// queryRaw issues an ABCI query whose messages are not in the generated
// bindings: the request is sent as encoded and the response returned as
// received.
func (c *KeeperABCIClient) queryRaw(ctx context.Context, serviceMethod string, request []byte) ([]byte, error) {
	req, resp := &emptypb.Empty{}, &emptypb.Empty{}
	req.ProtoReflect().SetUnknown(request)
	if err := c.query(ctx, serviceMethod, 0, req, resp); err != nil {
		if unsupportedQuery(err) {
			return nil, fmt.Errorf("%w: %s", ErrQueryUnsupported, serviceMethod)
		}
		return nil, err
	}
	return resp.ProtoReflect().GetUnknown(), nil
}

func unsupportedQuery(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Unimplemented") || strings.Contains(text, "unknown query path") ||
		strings.Contains(text, "unknown service") || strings.Contains(text, "unknown method")
}
