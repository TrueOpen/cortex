package dispatchstream

import (
	"context"
	"fmt"
	"io"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// newBinding draws a fresh stream nonce and returns the signed binding frame
// bytes together with the nonce every later frame must echo.
func (s *Session) newBinding(ctx context.Context) ([]byte, []byte, error) {
	nonce := make([]byte, dispatch.StreamNonceSize)
	if _, err := io.ReadFull(s.cfg.Rand, nonce); err != nil {
		return nil, nil, fmt.Errorf("dispatchstream: stream nonce: %w", err)
	}
	authNonce, err := s.cfg.AuthNonce(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatchstream: service authorization nonce: %w", err)
	}
	b := &nexusv1.DispatchStreamBindingV1{
		SchemaVersion:             dispatch.StreamSchemaVersion,
		ChainId:                   s.cfg.ChainID,
		BuilderOperator:           s.cfg.BuilderOperator,
		CortexOperator:            s.cfg.CortexOperator,
		ServiceAuthorizationNonce: authNonce,
		StreamNonce:               nonce,
	}
	if err := dispatchwire.SignBinding(ctx, b, s.cfg.Sign); err != nil {
		return nil, nil, err
	}
	frame, err := encodeControl(nonce, b)
	if err != nil {
		return nil, nil, err
	}
	return frame, nonce, nil
}
