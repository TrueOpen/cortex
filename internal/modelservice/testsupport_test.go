package modelservice

import (
	"context"
	"fmt"
	"strings"
)

// Declarations only tests use, kept out of the production binary.

func (t NoopTransport) Invoke(_ context.Context, _ string, _ any, _ any) error {
	reason := strings.TrimSpace(t.Reason)
	if reason == "" {
		return ErrRuntimeTransportUnavailable
	}
	return fmt.Errorf("%w: %s", ErrRuntimeTransportUnavailable, reason)
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
