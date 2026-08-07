package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{name: "debug lowercase", input: "debug", want: slog.LevelDebug},
		{name: "debug uppercase", input: "DEBUG", want: slog.LevelDebug},
		{name: "debug mixed case", input: "Debug", want: slog.LevelDebug},
		{name: "info", input: "info", want: slog.LevelInfo},
		{name: "warn", input: "warn", want: slog.LevelWarn},
		{name: "warning alias", input: "warning", want: slog.LevelWarn},
		{name: "error", input: "error", want: slog.LevelError},
		{name: "empty string defaults to info", input: "", want: slog.LevelInfo},
		{name: "unrecognized defaults to info", input: "invalid", want: slog.LevelInfo},
		{name: "whitespace trimmed", input: "  debug  ", want: slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevelName(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "debug"},
		{slog.LevelInfo, "info"},
		{slog.LevelWarn, "warn"},
		{slog.LevelError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := LevelName(tt.level)
			if got != tt.want {
				t.Errorf("LevelName(%v) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: false}
	logger := New(cfg, &buf)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected output to contain 'key=value', got: %s", output)
	}
}

func TestNew_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "json", RedactSensitive: false}
	logger := New(cfg, &buf)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, `"msg":"test message"`) {
		t.Errorf("expected JSON output with msg field, got: %s", output)
	}
	if !strings.Contains(output, `"key":"value"`) {
		t.Errorf("expected JSON output with key field, got: %s", output)
	}
}

func TestNew_NilWriter_DefaultsToStderr(t *testing.T) {
	// Should not panic with nil writer.
	cfg := Config{Level: "info", Format: "text"}
	logger := New(cfg, nil)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "warn", Format: "text"}
	logger := New(cfg, &buf)

	logger.Info("should not appear")
	logger.Warn("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("info message should have been filtered at warn level")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("warn message should have been output at warn level")
	}
}

func TestNewNop(t *testing.T) {
	logger := NewNop()
	// Should not panic when logging.
	logger.Info("this should go nowhere", "key", "value")
	logger.Error("this too")
}

func TestWithModule(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{Level: "info", Format: "text"}, &buf)
	moduleLogger := WithModule(logger, "parser")

	moduleLogger.Info("parsing file")

	output := buf.String()
	if !strings.Contains(output, "module=parser") {
		t.Errorf("expected output to contain 'module=parser', got: %s", output)
	}
}

func TestWithOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{Level: "info", Format: "text"}, &buf)
	opLogger := WithOperation(logger, "store")

	opLogger.Info("storing artifact")

	output := buf.String()
	if !strings.Contains(output, "operation=store") {
		t.Errorf("expected output to contain 'operation=store', got: %s", output)
	}
}

func TestWithProject(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{Level: "info", Format: "text"}, &buf)
	projectID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	projLogger := WithProject(logger, projectID)

	projLogger.Info("project operation")

	output := buf.String()
	if !strings.Contains(output, "project_id=550e8400-e29b-41d4-a716-446655440000") {
		t.Errorf("expected output to contain project_id, got: %s", output)
	}
}

func TestWithWorkspace(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Config{Level: "info", Format: "text"}, &buf)
	wsLogger := WithWorkspace(logger, "my-workspace")

	wsLogger.Info("workspace operation")

	output := buf.String()
	if !strings.Contains(output, "workspace=my-workspace") {
		t.Errorf("expected output to contain 'workspace=my-workspace', got: %s", output)
	}
}

func TestContextualFieldsChain(t *testing.T) {
	// Verify that multiple contextual fields can be chained.
	var buf bytes.Buffer
	logger := New(Config{Level: "info", Format: "text"}, &buf)
	chainedLogger := WithModule(WithWorkspace(logger, "ws"), "parser")

	chainedLogger.Info("chained context")

	output := buf.String()
	if !strings.Contains(output, "workspace=ws") {
		t.Errorf("expected workspace field, got: %s", output)
	}
	if !strings.Contains(output, "module=parser") {
		t.Errorf("expected module field, got: %s", output)
	}
}
