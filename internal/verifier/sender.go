package verifier

import (
	"context"
	"fmt"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// FrameSender delivers Verifier messages to Builders. Phase 1 carries them on
// every DispatchStream the node holds (internal/dispatchstream); the Phase 0
// bus subjects are retired.
type FrameSender interface {
	SendVerifierHandraise(context.Context, *taskv1.VerifierHandraiseV1) error
}

// NewFrameSenderGuard refuses a nil sender so a Verifier can never sign a
// handraise it has no way to deliver.
func NewFrameSenderGuard(s FrameSender) (FrameSender, error) {
	if s == nil {
		return nil, fmt.Errorf("verifier frame sender is required")
	}
	return s, nil
}
