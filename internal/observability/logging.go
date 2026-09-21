package observability

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"time"
)

// LogRecord is a log entry with an explicitly selected source program counter.
type LogRecord struct {
	Level   slog.Level
	Message string
	PC      uintptr
}

// NewTextLogger returns the repository's source-aware text logger.
func NewTextLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if attr.Key != slog.SourceKey {
				return attr
			}
			source, ok := attr.Value.Any().(*slog.Source)
			if !ok || source == nil {
				return attr
			}
			trimmed := *source
			trimmed.File = trimSourcePath(trimmed.File)
			return slog.Any(slog.SourceKey, &trimmed)
		},
	}))
}

// SetDefaultLogger installs the repository's source-aware default logger.
func SetDefaultLogger(w io.Writer) {
	slog.SetDefault(NewTextLogger(w))
}

// CallerPC returns the program counter at the requested caller depth.
func CallerPC(skip int) uintptr {
	var pcs [1]uintptr
	if skip < 0 {
		skip = 0
	}
	if runtime.Callers(callerPCBase+skip, pcs[:]) == 0 {
		return 0
	}
	return pcs[0]
}

// NewLogRecord builds a record attributed to the requested caller depth.
func NewLogRecord(level slog.Level, message string, callerSkip int) LogRecord {
	if callerSkip < 0 {
		callerSkip = 0
	}
	return LogRecord{Level: level, Message: message, PC: CallerPC(callerSkip + 1)}
}

// Emit sends a callback record through the current default logger.
func Emit(record LogRecord, attrs ...slog.Attr) {
	logger := slog.Default()
	ctx := context.Background()
	if !logger.Enabled(ctx, record.Level) {
		return
	}
	entry := slog.NewRecord(time.Now(), record.Level, record.Message, record.PC)
	entry.AddAttrs(attrs...)
	_ = logger.Handler().Handle(ctx, entry)
}

// LogAtDepth emits a record attributed to a caller at callerDepth.
func LogAtDepth(level slog.Level, callerDepth int, message string, attrs ...slog.Attr) {
	if callerDepth < 0 {
		callerDepth = 0
	}
	Emit(NewLogRecord(level, message, callerDepth+1), attrs...)
}

const callerPCBase = 2

func trimSourcePath(file string) string {
	normalized := strings.ReplaceAll(file, "\\", "/")
	parts := strings.Split(normalized, "/")
	for index, part := range parts {
		if part == "cmd" || part == "internal" || part == "scripts" {
			return strings.Join(parts[index:], "/")
		}
	}
	if index := strings.LastIndex(normalized, "/"); index >= 0 {
		return normalized[index+1:]
	}
	return normalized
}
