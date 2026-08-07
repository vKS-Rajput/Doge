// Package logging provides structured, contextual, and redacted logging
// for the workspace.
//
// The logging system is built on Go's standard [log/slog] package.
// It adds three capabilities on top of the stdlib:
//
//  1. Configuration-driven initialization (level, format, redaction)
//  2. Contextual field helpers (WithModule, WithOperation, WithProject)
//  3. Sensitive data redaction via a custom [slog.Handler] wrapper
//
// Usage:
//
//	cfg := logging.Config{Level: "info", Format: "text", RedactSensitive: true}
//	logger := logging.New(cfg, os.Stderr)
//	parserLog := logging.WithModule(logger, "parser")
//	parserLog.Info("file parsed", "artifact_id", id, "observations", count)
//
// The logger uses [*slog.Logger] directly — no custom interface.
// Every Go developer already knows how to use slog.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"
)

// Config holds logging configuration. Typically loaded from workspace.toml
// by the Configuration Manager.
type Config struct {
	// Level is the minimum log level to output.
	// Valid values: "debug", "info", "warn", "error".
	// Defaults to "info" if empty or unrecognized.
	Level string

	// Format is the output format.
	// Valid values: "text" (human-readable), "json" (machine-parseable).
	// Defaults to "text" if empty or unrecognized.
	Format string

	// RedactSensitive enables redaction of sensitive data (passwords,
	// tokens, cookies, API keys) in log output. Should be true in
	// production; may be false during local debugging.
	RedactSensitive bool
}

// ParseLevel converts a string log level name to a [slog.Level].
// Returns [slog.LevelInfo] for empty or unrecognized values.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LevelName returns the canonical string name for a [slog.Level].
func LevelName(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return "debug"
	case level < slog.LevelWarn:
		return "info"
	case level < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// New creates a new configured [*slog.Logger].
//
// If w is nil, output goes to [os.Stderr]. The handler is chosen
// based on cfg.Format: "json" produces JSON Lines output, anything
// else produces human-readable text. If cfg.RedactSensitive is true,
// a [RedactingHandler] wraps the base handler to scrub sensitive values.
func New(cfg Config, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}

	level := ParseLevel(cfg.Level)
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	if cfg.RedactSensitive {
		handler = NewRedactingHandler(handler)
	}

	return slog.New(handler)
}

// NewNop creates a logger that discards all output.
// Useful for tests that don't care about log output.
func NewNop() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// WithModule returns a child logger with the module name attached.
// Every module should call this once during initialization to create
// its logger, ensuring all log lines identify their source module.
func WithModule(logger *slog.Logger, module string) *slog.Logger {
	return logger.With("module", module)
}

// WithOperation returns a child logger with the operation name attached.
// Use this within a module to distinguish different operations
// (e.g., "parse", "store", "resolve").
func WithOperation(logger *slog.Logger, operation string) *slog.Logger {
	return logger.With("operation", operation)
}

// WithProject returns a child logger with the project ID attached.
// Use this for operations scoped to a specific project.
func WithProject(logger *slog.Logger, projectID uuid.UUID) *slog.Logger {
	return logger.With("project_id", projectID.String())
}

// WithWorkspace returns a child logger with the workspace name attached.
func WithWorkspace(logger *slog.Logger, workspace string) *slog.Logger {
	return logger.With("workspace", workspace)
}

// WithEntityID returns a child logger with an entity ID attached.
// Useful for tracing operations on a specific entity.
func WithEntityID(logger *slog.Logger, entityID uuid.UUID) *slog.Logger {
	return logger.With("entity_id", entityID.String())
}
