package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify critical defaults.
	if cfg.Watcher.DebounceMs != 300 {
		t.Errorf("default debounce_ms = %d, want 300", cfg.Watcher.DebounceMs)
	}
	if cfg.AI.Enabled {
		t.Error("AI should be disabled by default")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default log level = %q, want 'info'", cfg.Logging.Level)
	}
	if !cfg.Logging.RedactSensitive {
		t.Error("redact_sensitive should be true by default")
	}
	if !cfg.Database.WALMode {
		t.Error("WAL mode should be enabled by default")
	}
	if !cfg.AI.Verification.RequireEvidence {
		t.Error("require_evidence should be true by default")
	}
	if !cfg.Rules.Enabled {
		t.Error("rules should be enabled by default")
	}
	if cfg.Parser.MaxFileSizeMB != 50 {
		t.Errorf("default max_file_size_mb = %d, want 50", cfg.Parser.MaxFileSizeMB)
	}
	if len(cfg.Watcher.IgnorePatterns) == 0 {
		t.Error("default ignore patterns should not be empty")
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	content := `
[workspace]
name = "test-workspace"

[logging]
level = "debug"
format = "json"

[watcher]
debounce_ms = 500

[ai]
enabled = false
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Workspace.Name != "test-workspace" {
		t.Errorf("workspace.name = %q, want 'test-workspace'", cfg.Workspace.Name)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level = %q, want 'debug'", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging.format = %q, want 'json'", cfg.Logging.Format)
	}
	if cfg.Watcher.DebounceMs != 500 {
		t.Errorf("watcher.debounce_ms = %d, want 500", cfg.Watcher.DebounceMs)
	}
}

func TestLoad_MergesWithDefaults(t *testing.T) {
	// Only override one field; everything else should keep defaults.
	content := `
[workspace]
name = "partial"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Overridden field.
	if cfg.Workspace.Name != "partial" {
		t.Errorf("workspace.name = %q, want 'partial'", cfg.Workspace.Name)
	}

	// Default fields should be preserved.
	if cfg.Watcher.DebounceMs != 300 {
		t.Errorf("debounce_ms should retain default 300, got %d", cfg.Watcher.DebounceMs)
	}
	if cfg.Cache.MaxEntries != 1000 {
		t.Errorf("cache.max_entries should retain default 1000, got %d", cfg.Cache.MaxEntries)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	content := `this is not valid toml {{{{`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	content := `
[logging]
level = "verbose"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
	if !strings.Contains(err.Error(), "invalid log level") {
		t.Errorf("error should mention 'invalid log level', got: %v", err)
	}
}

func TestLoad_InvalidLogFormat(t *testing.T) {
	content := `
[logging]
format = "xml"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid log format")
	}
}

func TestLoad_NegativeDebounce(t *testing.T) {
	content := `
[watcher]
debounce_ms = -1
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for negative debounce")
	}
}

func TestLoad_InvalidTemperature(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "too high",
			content: `
[ai]
temperature = 3.0
`,
		},
		{
			name: "negative",
			content: `
[ai]
temperature = -0.5
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestConfig(t, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected validation error for invalid temperature")
			}
		})
	}
}

func TestLoad_AIEnabledWithoutModel(t *testing.T) {
	content := `
[ai]
enabled = true
base_url = "http://localhost:11434/v1"
model = ""
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for AI enabled without model")
	}
	if !strings.Contains(err.Error(), "ai.model must be set") {
		t.Errorf("error should mention model requirement, got: %v", err)
	}
}

func TestLoad_AIEnabledWithoutBaseURL(t *testing.T) {
	content := `
[ai]
enabled = true
base_url = ""
model = "llama3.1"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for AI enabled without base_url")
	}
}

func TestLoad_InvalidSpeculationRatio(t *testing.T) {
	content := `
[ai.verification]
max_speculation_ratio = 1.5
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for speculation ratio > 1.0")
	}
}

func TestLoadWithOverrides_NoProjectConfig(t *testing.T) {
	dir := t.TempDir()

	// Write workspace config.
	wsConfig := `
[workspace]
name = "test-ws"
`
	if err := os.WriteFile(filepath.Join(dir, "workspace.toml"), []byte(wsConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithOverrides(dir, "nonexistent-project")
	if err != nil {
		t.Fatalf("LoadWithOverrides() error = %v", err)
	}

	if cfg.Workspace.Name != "test-ws" {
		t.Errorf("workspace.name = %q, want 'test-ws'", cfg.Workspace.Name)
	}
}

func TestLoadWithOverrides_WithProjectConfig(t *testing.T) {
	dir := t.TempDir()

	// Write workspace config.
	wsConfig := `
[workspace]
name = "test-ws"

[logging]
level = "info"
`
	if err := os.WriteFile(filepath.Join(dir, "workspace.toml"), []byte(wsConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Write project config that overrides logging level.
	projectDir := filepath.Join(dir, "projects", "my-project")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfig := `
[logging]
level = "debug"
`
	if err := os.WriteFile(filepath.Join(projectDir, "config.toml"), []byte(projectConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithOverrides(dir, "my-project")
	if err != nil {
		t.Fatalf("LoadWithOverrides() error = %v", err)
	}

	// Project override should take effect.
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level = %q, want 'debug' (from project override)", cfg.Logging.Level)
	}

	// Workspace values should be preserved where not overridden.
	if cfg.Workspace.Name != "test-ws" {
		t.Errorf("workspace.name = %q, want 'test-ws'", cfg.Workspace.Name)
	}
}

func TestLoadWithOverrides_EmptyProjectSlug(t *testing.T) {
	dir := t.TempDir()

	wsConfig := `
[workspace]
name = "test-ws"
`
	if err := os.WriteFile(filepath.Join(dir, "workspace.toml"), []byte(wsConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithOverrides(dir, "")
	if err != nil {
		t.Fatalf("LoadWithOverrides() error = %v", err)
	}

	if cfg.Workspace.Name != "test-ws" {
		t.Errorf("workspace.name = %q, want 'test-ws'", cfg.Workspace.Name)
	}
}

// writeTestConfig writes config content to a temp file and returns its path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return path
}
