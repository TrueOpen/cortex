package modelservice

import (
	"errors"
	"fmt"
	"strings"
)

var ErrRuntimeTransportUnavailable = errors.New("modelservice runtime transport unavailable")

type RuntimeTransportConfig struct {
	Kind     string
	Endpoint string
	TLS      GRPCTLS
}

type NoopTransport struct {
	Reason string
}

func NewTransport(cfg RuntimeTransportConfig) (Transport, error) {
	kind := strings.ToLower(strings.TrimSpace(cfg.Kind))
	endpoint := strings.TrimSpace(cfg.Endpoint)

	switch kind {
	case "", "fake", "local":
		return nil, nil
	case "grpc":
		if endpoint == "" {
			return nil, fmt.Errorf("%w: grpc endpoint unavailable", ErrRuntimeTransportUnavailable)
		}
		return NewGRPCTransportTLS(endpoint, cfg.TLS)
	default:
		return nil, fmt.Errorf("%w: unknown transport kind %q", ErrRuntimeTransportUnavailable, kind)
	}
}
