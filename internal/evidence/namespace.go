package evidence

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
)

// DropNamespace retires one evidence namespace no chain fact will ever
// reference: the per-ticket scope of a dispatch ticket that was never
// recorded (S6 GC). The directory moves to trash, then the index rows go, in
// that order under the artifact lock, as Cleanup does; the next Sweep
// reclaims the bytes. Idempotent. Task namespaces of recorded work keep the
// operator-confirmed Cleanup.
func (s *Store) DropNamespace(ctx context.Context, key codec.Hash) error {
	if s.index == nil {
		return fmt.Errorf("evidence metadata store is required")
	}
	return s.index.WithArtifactLock(func() error {
		if _, err := trashTaskDirectory(s.root, key); err != nil {
			return fmt.Errorf("trash evidence namespace %x: %w", key, err)
		}
		return s.index.CleanupEvidence(ctx, key)
	})
}
