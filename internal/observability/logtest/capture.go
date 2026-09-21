// Package logtest provides test-only helpers for code that changes the process
// default logger.
package logtest

import (
	"io"
	"log/slog"
	"testing"
)

type standardLogger interface {
	Writer() io.Writer
	Flags() int
	SetOutput(io.Writer)
	SetFlags(int)
}

// Install replaces the default slog logger for a test and restores every
// process-global logging value that slog.SetDefault changes.
func Install(t testing.TB, logger *slog.Logger, standard standardLogger) {
	t.Helper()
	previousDefault := slog.Default()
	previousWriter := standard.Writer()
	previousFlags := standard.Flags()
	slog.SetDefault(logger)
	t.Cleanup(func() {
		slog.SetDefault(previousDefault)
		standard.SetOutput(previousWriter)
		standard.SetFlags(previousFlags)
	})
}
