package daemon

import (
	"context"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// Declarations only tests use, kept out of the production binary.

func checkKeeperIdentity(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader, currentHeight uint64) (string, error) {
	serviceAddress, err := checkKeeperCoreIdentity(ctx, identity, reader, currentHeight)
	if err != nil {
		return "", err
	}
	if err := checkKeeperModelReadiness(ctx, identity, reader); err != nil {
		return "", err
	}
	return serviceAddress, nil
}

func checkKeeperCoreIdentity(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader, currentHeight uint64) (string, error) {
	key, err := checkKeeperCoreServiceKey(ctx, identity, reader, currentHeight)
	if err != nil {
		return "", err
	}
	return key.ServiceAddress, nil
}

func newProductionInferExecutor(cfg TaskRunnerConfig, persist func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error) InferExecutor {
	return &productionInferExecutor{cfg: cfg, persist: persist}
}
