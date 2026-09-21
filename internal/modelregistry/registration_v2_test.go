package modelregistry

import (
	"context"
	"errors"
	"testing"
)

func TestRegisterRejectsObsoleteSplitRegistrationBeforeWork(t *testing.T) {
	registry := NewRegistry(RegistryConfig{})
	for _, dryRun := range []bool{false, true} {
		_, err := registry.Register(context.Background(), RegisterRequest{
			ModelRegistrationFee:   KeeperRegistrationFeeMin,
			ProfileRegistrationFee: KeeperRegistrationFeeMin,
			DryRun:                 dryRun,
		})
		if !errors.Is(err, ErrKeeperModelRegistrationUnavailable) {
			t.Fatalf("Register(dry_run=%v) error = %v, want obsolete split registration rejection", dryRun, err)
		}
	}
}
