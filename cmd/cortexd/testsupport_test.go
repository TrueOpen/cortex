package main

import (
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/observability"
)

// Declarations only tests use, kept out of the production binary.

func runtimeRunners(cfg config.Config, rt *daemon.Runtime) ([]runtimeRunner, func(), error) {
	return runtimeRunnersWithHealth(cfg, rt, nil)
}

func runtimeRunnersWithHealth(cfg config.Config, rt *daemon.Runtime, health *observability.Health) ([]runtimeRunner, func(), error) {
	if rt == nil {
		return nil, func() {}, nil
	}
	taskRunner, err := newTaskRunner(cfg, rt)
	if err != nil {
		return nil, func() {}, err
	}
	return runtimeRunnersWithHealthAndTaskRunner(cfg, rt, health, taskRunner)
}

// dependencyReady reports one dependency from the readiness snapshot /readyz serves.
func dependencyReady(health *observability.Health, name string) bool {
	_, dependencies := health.Readiness()
	return dependencies[name]
}
