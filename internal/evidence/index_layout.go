package evidence

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

// LayoutStoreIndex adapts a store.Store to the MetadataStore and
// MetadataEnumerator interfaces using the internal/store/layout helpers.
type LayoutStoreIndex struct{ Store *store.Store }

var _ MetadataStore = (*LayoutStoreIndex)(nil)
var _ MetadataEnumerator = (*LayoutStoreIndex)(nil)

func (l *LayoutStoreIndex) PutEvidence(ctx context.Context, taskHash codec.Hash, evidence layout.Evidence) error {
	return layout.MergeEvidence(ctx, l.Store, layout.StoredHash(taskHash), evidence)
}

func (l *LayoutStoreIndex) Evidence(ctx context.Context, taskHash codec.Hash) (layout.Evidence, error) {
	return layout.GetEvidenceRecord(ctx, l.Store, layout.StoredHash(taskHash))
}

func (l *LayoutStoreIndex) MergeEvidence(ctx context.Context, taskHash codec.Hash, mutate func(layout.Evidence, bool) (layout.Evidence, error)) (layout.Evidence, error) {
	return layout.MergeEvidenceFn(ctx, l.Store, layout.StoredHash(taskHash), func(existing layout.Evidence, exists bool) (layout.Evidence, error) {
		return mutate(existing, exists)
	})
}

func (l *LayoutStoreIndex) DeleteEvidence(ctx context.Context, taskHash codec.Hash) error {
	return layout.DeleteEvidence(ctx, l.Store, layout.StoredHash(taskHash))
}

func (l *LayoutStoreIndex) CleanupEvidence(ctx context.Context, taskHash codec.Hash) error {
	return layout.CleanupBatch(ctx, l.Store, layout.StoredHash(taskHash))
}

func (l *LayoutStoreIndex) ListEvidenceChallenges(ctx context.Context, taskHash codec.Hash) ([]string, error) {
	return layout.ListChallenges(ctx, l.Store, layout.StoredHash(taskHash))
}

func (l *LayoutStoreIndex) WithArtifactLock(fn func() error) error {
	return l.Store.WithArtifactLock(fn)
}

func (l *LayoutStoreIndex) ListEvidence(ctx context.Context) ([]layout.EvidenceEntry, error) {
	return layout.ListEvidence(ctx, l.Store)
}

// AdvanceEvidenceRetention monotonically advances retention heights.
func (l *LayoutStoreIndex) AdvanceEvidenceRetention(ctx context.Context, taskHash codec.Hash, finalityHeight, cleanupHeight uint64) (bool, error) {
	advanced := false
	_, err := layout.MergeEvidenceFn(ctx, l.Store, layout.StoredHash(taskHash), func(existing layout.Evidence, exists bool) (layout.Evidence, error) {
		if !exists {
			return layout.Evidence{}, store.ErrNotFound
		}
		if finalityHeight > existing.FinalityHeight {
			existing.FinalityHeight = finalityHeight
			advanced = true
		}
		if cleanupHeight > existing.CleanupHeight {
			existing.CleanupHeight = cleanupHeight
			advanced = true
		}
		return existing, nil
	})
	if err != nil {
		return false, fmt.Errorf("advance evidence retention: %w", err)
	}
	return advanced, nil
}

// SetEvidenceChallenge opens or closes a challenge lifecycle record.
func (l *LayoutStoreIndex) SetEvidenceChallenge(ctx context.Context, taskHash codec.Hash, challengeID string, open bool) error {
	record := layout.ChallengeLifecycle{LastPosition: layout.Position{Height: 1}, Open: open}
	return layout.UpsertChallenge(ctx, l.Store, layout.StoredHash(taskHash), challengeID, record)
}

// SetEvidenceTerminal marks the evidence record terminal.
func (l *LayoutStoreIndex) SetEvidenceTerminal(ctx context.Context, taskHash codec.Hash) error {
	return layout.MergeEvidence(ctx, l.Store, layout.StoredHash(taskHash), layout.Evidence{TerminalOrSettled: true})
}
