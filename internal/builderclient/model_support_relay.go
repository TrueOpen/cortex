package builderclient

import (
	"context"
	"encoding/hex"
	"fmt"

	"connectrpc.com/connect"

	"github.com/TrueOpen/cortex/internal/codec"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

// SubmitModelSupportConfirmationRequest hands one service-signed daily support
// confirmation to a Builder, which batches it into MsgBatchConfirmModelSupport
// and pays the fee (wire docs/MODEL_SUPPORT_RELAY.md).
type SubmitModelSupportConfirmationRequest struct {
	// EpochIndex is the epoch the confirmation was signed for.
	EpochIndex uint64
	// Confirmation is the protobuf binary of one hub.v1.ModelSupportConfirmationV1.
	Confirmation []byte
	// SigningDigest is the TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1 digest the
	// service key signed; the Builder must echo it.
	SigningDigest codec.Hash
}

// ModelSupportRelayAck is the Builder's acceptance into its relay queue, or its
// report that the chain already holds the same material. It is not an inclusion
// receipt and does not say any model row was refreshed.
type ModelSupportRelayAck struct {
	Idempotent    bool
	SigningDigest codec.Hash
}

// ModelSupportRelayClient is the IngressAPI call for the support relay. It is
// separate from TaskDataClient because it belongs to no Task.
type ModelSupportRelayClient interface {
	SubmitModelSupportConfirmation(context.Context, string, SubmitModelSupportConfirmationRequest) (ModelSupportRelayAck, error)
}

func (c *ConnectTaskDataClient) SubmitModelSupportConfirmation(ctx context.Context, endpoint string, request SubmitModelSupportConfirmationRequest) (ModelSupportRelayAck, error) {
	if len(request.Confirmation) == 0 {
		return ModelSupportRelayAck{}, Permanent(fmt.Errorf("model support relay requires a signed confirmation"))
	}
	if request.SigningDigest == (codec.Hash{}) {
		return ModelSupportRelayAck{}, Permanent(fmt.Errorf("model support relay requires the confirmation signing digest"))
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return ModelSupportRelayAck{}, err
	}
	req := connect.NewRequest(&nexusv1.SubmitModelSupportConfirmationRequest{
		EpochIndex:   request.EpochIndex,
		Confirmation: append([]byte(nil), request.Confirmation...),
	})
	c.authorize(req.Header())
	response, err := client.SubmitModelSupportConfirmation(ctx, req)
	if err != nil {
		return ModelSupportRelayAck{}, classifyConnectError(nexusv1connect.IngressAPISubmitModelSupportConfirmationProcedure, err)
	}
	// Only relay_accepted=true acknowledges anything; the echoed digest binds the
	// acknowledgement to the material this node signed.
	if response == nil || response.Msg == nil || !response.Msg.RelayAccepted ||
		response.Msg.ConfirmationSigningDigest != ToIngressHash32(hex.EncodeToString(request.SigningDigest[:])) {
		return ModelSupportRelayAck{}, fmt.Errorf("model support relay acknowledgment has wrong confirmation signing digest")
	}
	return ModelSupportRelayAck{Idempotent: response.Msg.Idempotent, SigningDigest: request.SigningDigest}, nil
}
