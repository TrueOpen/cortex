package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// NexusModelSupportRelay hands a service-signed daily support confirmation to a
// Builder over IngressAPI SubmitModelSupportConfirmation (wire
// docs/MODEL_SUPPORT_RELAY.md); the Builder batches it into
// MsgBatchConfirmModelSupport and pays the fee. It is how a node whose signer
// cannot build Cosmos transactions keeps its support fresh.
//
// Builders are tried in configuration order and the first acceptance ends the
// call. One queued entry is all the chain needs, and offering the same material
// to a second Builder would only race it into another batch.
type NexusModelSupportRelay struct {
	client    builderclient.ModelSupportRelayClient
	endpoints BuilderEndpointResolver
	builders  []string
}

func NewNexusModelSupportRelay(client builderclient.ModelSupportRelayClient, endpoints BuilderEndpointResolver, builders []string) (*NexusModelSupportRelay, error) {
	switch {
	case client == nil:
		return nil, fmt.Errorf("model support relay requires a Nexus ingress client")
	case endpoints == nil:
		return nil, fmt.Errorf("model support relay requires a Builder endpoint resolver")
	case len(builders) == 0:
		return nil, fmt.Errorf("model support relay requires at least one Builder")
	}
	return &NexusModelSupportRelay{client: client, endpoints: endpoints, builders: append([]string(nil), builders...)}, nil
}

// RelaySupportConfirmation returns nil once a Builder accepted the material
// into its queue (or reported the chain already holds it). That is not an
// on-chain refresh; see SupportRenewer.
func (r *NexusModelSupportRelay) RelaySupportConfirmation(ctx context.Context, epoch uint64, confirmation []byte, signingDigest codec.Hash) error {
	request := builderclient.SubmitModelSupportConfirmationRequest{EpochIndex: epoch, Confirmation: confirmation, SigningDigest: signingDigest}
	var refusals []error
	for _, builder := range r.builders {
		err := dialBuilder(ctx, r.endpoints, builder, func(ctx context.Context, endpoint BuilderEndpoint) error {
			_, err := r.client.SubmitModelSupportConfirmation(ctx, endpoint.Endpoint, request)
			return err
		})
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		refusals = append(refusals, fmt.Errorf("Builder %s: %w", builder, err))
	}
	return errors.Join(refusals...)
}
