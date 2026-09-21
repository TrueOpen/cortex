package logtest

import (
	"bytes"
	"log"
	"log/slog"
	"testing"
)

func TestInstallRestoresSlogAndStandardLogger(t *testing.T) {
	originalDefault := slog.Default()
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(originalDefault)
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	})

	baselineWriter := &bytes.Buffer{}
	baselineLogger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	baselineFlags := log.Ldate | log.Lshortfile
	slog.SetDefault(baselineLogger)
	log.SetOutput(baselineWriter)
	log.SetFlags(baselineFlags)

	t.Run("capture", func(t *testing.T) {
		Install(t, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), log.Default())
	})

	if slog.Default() != baselineLogger {
		t.Fatal("default slog logger was not restored")
	}
	if log.Writer() != baselineWriter {
		t.Fatal("standard logger writer was not restored")
	}
	if got := log.Flags(); got != baselineFlags {
		t.Fatalf("standard logger flags = %d, want %d", got, baselineFlags)
	}
}
