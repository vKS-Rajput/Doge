// Package config provides type-safe configuration loading, validation,
// and per-project overrides for the workspace.
//
// Configuration is loaded from workspace.toml at the workspace root.
// Per-project overrides are loaded from projects/<slug>/config.toml.
// All validation happens at load time — if Load returns without error,
// the configuration is guaranteed to be valid.
//
// The Config struct mirrors the TOML schema exactly. Fields use
// sensible defaults defined in [DefaultConfig]. Callers should
// never construct a Config manually; always use [Load] or [DefaultConfig].
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Config is the top-level configuration structure.
// It mirrors the workspace.toml schema.
type Config struct {
	Workspace WorkspaceConfig `toml:"workspace"`
	Watcher   WatcherConfig   `toml:"watcher"`
	Parser    ParserConfig    `toml:"parser"`
	Database  DatabaseConfig  `toml:"database"`
	Cache     CacheConfig     `toml:"cache"`
	AI        AIConfig        `toml:"ai"`
	Logging   LoggingConfig   `toml:"logging"`
	Snapshot  SnapshotConfig  `toml:"snapshot"`
	Rules     RulesConfig     `toml:"rules"`
}

// WorkspaceConfig holds workspace-level settings.
type WorkspaceConfig struct {
	// Name is the display name for the workspace.
	Name string `toml:"name"`
}

// WatcherConfig holds file watcher settings.
type WatcherConfig struct {
	// DebounceMs is the milliseconds to wait after a filesystem event
	// before processing, to coalesce rapid successive writes.
	DebounceMs int `toml:"debounce_ms"`

	// IgnorePatterns lists glob patterns for files and directories
	// the watcher should ignore.
	IgnorePatterns []string `toml:"ignore_patterns"`
}

// ParserConfig holds parser engine settings.
type ParserConfig struct {
	// MaxFileSizeMB is the maximum file size (in megabytes) that
	// parsers will process. Larger files are skipped with a warning.
	MaxFileSizeMB int `toml:"max_file_size_mb"`
}

// DatabaseConfig holds SQLite database settings.
type DatabaseConfig struct {
	// WALMode enables Write-Ahead Logging for concurrent read support.
	WALMode bool `toml:"wal_mode"`

	// BusyTimeoutMs is the SQLite busy timeout in milliseconds.
	// Queries will wait this long for a lock before returning SQLITE_BUSY.
	BusyTimeoutMs int `toml:"busy_timeout_ms"`
}

// CacheConfig holds caching layer settings.
type CacheConfig struct {
	// MaxEntries is the maximum number of entries in the LRU cache.
	MaxEntries int `toml:"max_entries"`

	// TTLMinutes is the default time-to-live for cache entries in minutes.
	TTLMinutes int `toml:"ttl_minutes"`
}

// AIConfig holds AI reasoning engine settings.
type AIConfig struct {
	// Enabled controls whether AI features are available.
	// When false, all AI-dependent commands return a clear message
	// that AI is not configured. The workspace remains fully
	// functional without AI.
	Enabled bool `toml:"enabled"`

	// Provider identifies the LLM backend type.
	// Valid values: "openai_compatible", "ollama".
	Provider string `toml:"provider"`

	// BaseURL is the API endpoint for the LLM provider.
	BaseURL string `toml:"base_url"`

	// Model is the model name to use (e.g., "llama3.1", "mistral").
	Model string `toml:"model"`

	// ContextWindow is the model's context window size in tokens.
	ContextWindow int `toml:"context_window"`

	// MaxResponseTokens caps the maximum tokens in an AI response.
	MaxResponseTokens int `toml:"max_response_tokens"`

	// Temperature controls response randomness. Lower values produce
	// more deterministic, grounded output. Range: 0.0–2.0.
	Temperature float64 `toml:"temperature"`

	// TimeoutSeconds is the maximum time to wait for an AI response.
	TimeoutSeconds int `toml:"timeout_seconds"`

	// Verification holds settings for the Verification Engine.
	Verification VerificationConfig `toml:"verification"`
}

// VerificationConfig holds settings for AI output verification.
type VerificationConfig struct {
	// RequireEvidence rejects AI responses that don't cite evidence.
	RequireEvidence bool `toml:"require_evidence"`

	// MaxSpeculationRatio is the maximum fraction of an AI response
	// that can be speculative (not backed by evidence). Range: 0.0–1.0.
	MaxSpeculationRatio float64 `toml:"max_speculation_ratio"`
}

// LoggingConfig holds structured logging settings.
type LoggingConfig struct {
	// Level is the minimum log level. Valid: "debug", "info", "warn", "error".
	Level string `toml:"level"`

	// Format is the output format. Valid: "text", "json".
	Format string `toml:"format"`

	// RedactSensitive enables redaction of sensitive data in log output.
	RedactSensitive bool `toml:"redact_sensitive"`
}

// SnapshotConfig holds timeline snapshot settings.
type SnapshotConfig struct {
	// AutoIntervalMinutes is the interval in minutes between automatic
	// snapshots. Set to 0 to disable auto-snapshots.
	AutoIntervalMinutes int `toml:"auto_interval_minutes"`
}

// RulesConfig holds Rule Engine settings.
type RulesConfig struct {
	// Enabled controls whether the deterministic Rule Engine is active.
	Enabled bool `toml:"rules"`
}

// DefaultConfig returns a Config with sensible defaults.
// These defaults match the values in configs/default.toml.
func DefaultConfig() Config {
	return Config{
		Watcher: WatcherConfig{
			DebounceMs: 300,
			IgnorePatterns: []string{
				"*.tmp", "*.swp", "*.swo", "*~",
				".git/**", ".doge/**", "node_modules/**",
			},
		},
		Parser: ParserConfig{
			MaxFileSizeMB: 50,
		},
		Database: DatabaseConfig{
			WALMode:       true,
			BusyTimeoutMs: 5000,
		},
		Cache: CacheConfig{
			MaxEntries: 1000,
			TTLMinutes: 60,
		},
		AI: AIConfig{
			Enabled:           false,
			Provider:          "openai_compatible",
			BaseURL:           "http://localhost:11434/v1",
			ContextWindow:     8192,
			MaxResponseTokens: 2048,
			Temperature:       0.1,
			TimeoutSeconds:    120,
			Verification: VerificationConfig{
				RequireEvidence:     true,
				MaxSpeculationRatio: 0.1,
			},
		},
		Logging: LoggingConfig{
			Level:           "info",
			Format:          "text",
			RedactSensitive: true,
		},
		Snapshot: SnapshotConfig{
			AutoIntervalMinutes: 60,
		},
		Rules: RulesConfig{
			Enabled: true,
		},
	}
}

// Load reads and validates a configuration file from the given path.
// The configuration is merged on top of [DefaultConfig], so any
// fields not specified in the file retain their default values.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// LoadWithOverrides loads the workspace configuration and then applies
// per-project overrides on top of it. Project overrides are optional;
// if the project config file doesn't exist, the workspace config is
// returned unchanged.
func LoadWithOverrides(workspacePath, projectSlug string) (Config, error) {
	wsConfigPath := filepath.Join(workspacePath, "workspace.toml")
	cfg, err := Load(wsConfigPath)
	if err != nil {
		return Config{}, fmt.Errorf("loading workspace config: %w", err)
	}

	if projectSlug == "" {
		return cfg, nil
	}

	projectConfigPath := filepath.Join(workspacePath, "projects", projectSlug, "config.toml")
	if _, err := os.Stat(projectConfigPath); os.IsNotExist(err) {
		// No project override — return workspace config.
		return cfg, nil
	}

	projectData, err := os.ReadFile(projectConfigPath)
	if err != nil {
		return Config{}, fmt.Errorf("reading project config %s: %w", projectConfigPath, err)
	}

	// Unmarshal project overrides on top of the workspace config.
	if err := toml.Unmarshal(projectData, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing project config %s: %w", projectConfigPath, err)
	}

	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("validating merged config: %w", err)
	}

	return cfg, nil
}

// validate checks a Config for invalid values. It returns the first
// validation error found. All validation happens at load time.
func validate(cfg Config) error {
	// Validate log level.
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if cfg.Logging.Level != "" && !validLevels[strings.ToLower(cfg.Logging.Level)] {
		return fmt.Errorf("invalid log level: %q (valid: debug, info, warn, error)", cfg.Logging.Level)
	}

	// Validate log format.
	validFormats := map[string]bool{"text": true, "json": true}
	if cfg.Logging.Format != "" && !validFormats[strings.ToLower(cfg.Logging.Format)] {
		return fmt.Errorf("invalid log format: %q (valid: text, json)", cfg.Logging.Format)
	}

	// Validate AI provider.
	validProviders := map[string]bool{
		"openai_compatible": true, "ollama": true,
	}
	if cfg.AI.Enabled && cfg.AI.Provider != "" && !validProviders[strings.ToLower(cfg.AI.Provider)] {
		return fmt.Errorf("invalid AI provider: %q (valid: openai_compatible, ollama)", cfg.AI.Provider)
	}

	// Validate numeric ranges.
	if cfg.Watcher.DebounceMs < 0 {
		return fmt.Errorf("watcher.debounce_ms must be non-negative, got %d", cfg.Watcher.DebounceMs)
	}
	if cfg.Parser.MaxFileSizeMB < 1 {
		return fmt.Errorf("parser.max_file_size_mb must be at least 1, got %d", cfg.Parser.MaxFileSizeMB)
	}
	if cfg.Database.BusyTimeoutMs < 0 {
		return fmt.Errorf("database.busy_timeout_ms must be non-negative, got %d", cfg.Database.BusyTimeoutMs)
	}
	if cfg.Cache.MaxEntries < 1 {
		return fmt.Errorf("cache.max_entries must be at least 1, got %d", cfg.Cache.MaxEntries)
	}
	if cfg.AI.Temperature < 0 || cfg.AI.Temperature > 2.0 {
		return fmt.Errorf("ai.temperature must be between 0.0 and 2.0, got %f", cfg.AI.Temperature)
	}
	if cfg.AI.Verification.MaxSpeculationRatio < 0 || cfg.AI.Verification.MaxSpeculationRatio > 1.0 {
		return fmt.Errorf("ai.verification.max_speculation_ratio must be between 0.0 and 1.0, got %f",
			cfg.AI.Verification.MaxSpeculationRatio)
	}
	if cfg.Snapshot.AutoIntervalMinutes < 0 {
		return fmt.Errorf("snapshot.auto_interval_minutes must be non-negative, got %d",
			cfg.Snapshot.AutoIntervalMinutes)
	}

	// Validate AI model is set when AI is enabled.
	if cfg.AI.Enabled && cfg.AI.Model == "" {
		return fmt.Errorf("ai.model must be set when ai.enabled is true")
	}
	if cfg.AI.Enabled && cfg.AI.BaseURL == "" {
		return fmt.Errorf("ai.base_url must be set when ai.enabled is true")
	}

	return nil
}
