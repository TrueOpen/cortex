package modelservice

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNewTransport(t *testing.T) {
	t.Run("empty kind selects no runtime transport", func(t *testing.T) {
		transport, err := NewTransport(RuntimeTransportConfig{
			Kind:     " \t\n ",
			Endpoint: " ignored ",
		})
		if err != nil {
			t.Fatalf("NewTransport returned error: %v", err)
		}
		if transport != nil {
			t.Fatalf("NewTransport returned transport %T, want nil", transport)
		}
	})

	t.Run("fake kind selects no runtime transport", func(t *testing.T) {
		transport, err := NewTransport(RuntimeTransportConfig{
			Kind:     " fake ",
			Endpoint: " ignored ",
		})
		if err != nil {
			t.Fatalf("NewTransport returned error: %v", err)
		}
		if transport != nil {
			t.Fatalf("NewTransport returned transport %T, want nil", transport)
		}
	})

	t.Run("local kind is case insensitive and selects no runtime transport", func(t *testing.T) {
		transport, err := NewTransport(RuntimeTransportConfig{
			Kind:     " LOCAL ",
			Endpoint: " ignored ",
		})
		if err != nil {
			t.Fatalf("NewTransport returned error: %v", err)
		}
		if transport != nil {
			t.Fatalf("NewTransport returned transport %T, want nil", transport)
		}
	})

	t.Run("grpc kind returns live transport with endpoint", func(t *testing.T) {
		transport, err := NewTransport(RuntimeTransportConfig{
			Kind:     " GRPC ",
			Endpoint: " localhost:50051 ",
		})
		if err != nil {
			t.Fatalf("NewTransport returned error: %v", err)
		}
		if transport == nil {
			t.Fatalf("NewTransport returned nil transport")
		}
	})

	t.Run("unknown kind is unavailable with kind context", func(t *testing.T) {
		transport, err := NewTransport(RuntimeTransportConfig{
			Kind:     " unix ",
			Endpoint: " ignored ",
		})
		if transport != nil {
			t.Fatalf("NewTransport returned transport %T, want nil", transport)
		}
		if !errors.Is(err, ErrRuntimeTransportUnavailable) {
			t.Fatalf("NewTransport error = %v, want ErrRuntimeTransportUnavailable", err)
		}
		if !strings.Contains(err.Error(), "unix") {
			t.Fatalf("NewTransport error = %q, want unknown kind context", err.Error())
		}
	})
}

func TestNoopTransportInvoke(t *testing.T) {
	t.Run("returns sentinel error", func(t *testing.T) {
		err := (NoopTransport{}).Invoke(context.Background(), "Health", HealthRequest{}, &HealthResponse{})
		if !errors.Is(err, ErrRuntimeTransportUnavailable) {
			t.Fatalf("Invoke error = %v, want ErrRuntimeTransportUnavailable", err)
		}
	})

	t.Run("wraps reason with sentinel error", func(t *testing.T) {
		err := (NoopTransport{Reason: "grpc transport not linked"}).Invoke(context.Background(), "Health", HealthRequest{}, &HealthResponse{})
		if !errors.Is(err, ErrRuntimeTransportUnavailable) {
			t.Fatalf("Invoke error = %v, want ErrRuntimeTransportUnavailable", err)
		}
		if !strings.Contains(err.Error(), "grpc transport not linked") {
			t.Fatalf("Invoke error = %q, want reason context", err.Error())
		}
	})
}
