package layout

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/cortex/internal/store"
)

// Declarations only tests use, kept out of the production binary.

// PutDelivery stores a Builder storage confirmation for one data kind. It is
// idempotent by (taskHash, dataKind).
func PutDelivery(ctx context.Context, s *store.Store, taskHash StoredHash, dataKind string, confirmation StorageConfirmation) error {
	key := DeliveryKey(taskHash, dataKind)
	confirmation.SchemaVersion = defaultSchemaVersion(confirmation.SchemaVersion)
	encoded, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("encode delivery: %w", err)
	}
	return s.PutRaw(ctx, key, encoded)
}

// DeliveryKey returns a delivery/ key. For INPUT/OUTPUT there is no selector.
// For EVIDENCE a selector is appended: delivery/<taskHash>/<dataKind>[/<selector>]
func DeliveryKey(taskHash StoredHash, dataKind string, selector ...string) []byte {
	parts := [][]byte{[]byte(deliveryPrefix), taskHash[:], slash(), []byte(dataKind)}
	for _, s := range selector {
		parts = append(parts, slash(), []byte(s))
	}
	return join(parts...)
}
