package txclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Phase 1 dispatch Msgs Cortex submits itself (CD §8.6, §8.7). Their payloads
// are ProtoJSON of the generated task.v1 types, not hand-mirrored structs:
// they embed signed SignedOrderV2 / DispatchTicketV1 / DispatchAcceptV1 whose
// every field must reach the chain as signed.
const MsgClaimDispatchCompensation Kind = "/task.v1.MsgClaimDispatchCompensation"

var dispatchKinds = map[Kind]func() proto.Message{
	MsgClaimDispatchCompensation: func() proto.Message { return &taskv1.MsgClaimDispatchCompensation{} },
}

func isDispatchKind(k Kind) bool { _, ok := dispatchKinds[k]; return ok }

// MarshalDispatchMessage validates msg as kind and returns its ProtoJSON with
// proto field names, compacted: protojson randomises whitespace, so compacting
// keeps one message at one payload digest.
func MarshalDispatchMessage(kind Kind, msg proto.Message) ([]byte, error) {
	if !isDispatchKind(kind) {
		return nil, fmt.Errorf("%q is not a dispatch Msg kind", kind)
	}
	if want := strings.TrimPrefix(string(kind), "/"); dispatchwire.Name(msg) != want {
		return nil, fmt.Errorf("%s payload is a %s", kind, dispatchwire.Name(msg))
	}
	if err := validateDispatchMessage(kind, msg); err != nil {
		return nil, err
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func validateDispatchPayload(kind Kind, payload []byte) error {
	msg := dispatchKinds[kind]()
	if err := protojson.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("invalid %s ProtoJSON payload: %w", kind, err)
	}
	return validateDispatchMessage(kind, msg)
}

func validateDispatchMessage(kind Kind, msg proto.Message) error {
	switch m := msg.(type) {
	case *taskv1.MsgClaimDispatchCompensation:
		return validateClaimDispatchCompensation(m)
	}
	return fmt.Errorf("unsupported dispatch Msg %s", kind)
}

// validateClaimDispatchCompensation checks the parts of KC §10.2 step 1 that
// need no chain: the accept names this ticket, its task and its target, and
// both carry signatures.
func validateClaimDispatchCompensation(m *taskv1.MsgClaimDispatchCompensation) error {
	if err := requireStrings(m.GetSubmitterAddress()); err != nil {
		return fmt.Errorf("claim submitter_address: %w", err)
	}
	t, a := m.GetTicket(), m.GetAccept()
	if m.GetOrder().GetOrder() == nil || t == nil || a == nil {
		return fmt.Errorf("a compensation claim carries the order, the ticket and the accept")
	}
	th, err := dispatchwire.Digest(t)
	if err != nil {
		return fmt.Errorf("claim ticket: %w", err)
	}
	switch {
	case !bytes.Equal(a.GetDispatchTicketHash(), th[:]):
		return fmt.Errorf("claim accept names ticket %x, the ticket hashes to %x", a.GetDispatchTicketHash(), th)
	case !bytes.Equal(a.GetTaskId(), t.GetTaskId()) || !bytes.Equal(a.GetTaskHash(), t.GetTaskHash()):
		return fmt.Errorf("claim accept and ticket name different tasks")
	case !proto.Equal(a.GetMember(), t.GetTarget()):
		return fmt.Errorf("claim accept member is not the ticket target")
	case len(a.GetServiceSignature()) != 64 || len(t.GetBuilderServiceSignature()) == 0:
		return fmt.Errorf("claim accept and ticket must both be signed")
	}
	return nil
}
