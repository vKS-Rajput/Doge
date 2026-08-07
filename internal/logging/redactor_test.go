package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	sensitiveTests := []string{
		"password", "PASSWORD", "Password",
		"token", "TOKEN",
		"access_token", "refresh_token",
		"api_key", "apikey",
		"secret", "secret_key",
		"authorization", "AUTHORIZATION",
		"cookie", "Cookie",
		"set-cookie", "set_cookie",
		"session", "session_id",
		"credential", "credentials",
		"private_key",
		"jwt", "JWT",
		"bearer",
		"passwd",
	}

	for _, key := range sensitiveTests {
		t.Run("sensitive_"+key, func(t *testing.T) {
			if !IsSensitiveKey(key) {
				t.Errorf("IsSensitiveKey(%q) = false, want true", key)
			}
		})
	}

	nonSensitiveTests := []string{
		"module", "operation", "project_id",
		"url", "path", "method", "status_code",
		"entity_id", "artifact_id", "observation_id",
		"count", "duration", "error",
	}

	for _, key := range nonSensitiveTests {
		t.Run("not_sensitive_"+key, func(t *testing.T) {
			if IsSensitiveKey(key) {
				t.Errorf("IsSensitiveKey(%q) = true, want false", key)
			}
		})
	}
}

func TestRedactingHandler_RedactsPerRecordAttrs(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: true}
	logger := New(cfg, &buf)

	logger.Info("auth attempt",
		"username", "admin",
		"password", "super_secret_123",
		"token", "eyJhbGciOiJIUzI1NiJ9",
	)

	output := buf.String()

	// Password and token values should be redacted.
	if strings.Contains(output, "super_secret_123") {
		t.Errorf("password value should be redacted, got: %s", output)
	}
	if strings.Contains(output, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("token value should be redacted, got: %s", output)
	}

	// The keys themselves should still appear.
	if !strings.Contains(output, "password=") {
		t.Errorf("password key should still appear, got: %s", output)
	}
	if !strings.Contains(output, "token=") {
		t.Errorf("token key should still appear, got: %s", output)
	}

	// Redacted placeholder should appear.
	if !strings.Contains(output, RedactedValue) {
		t.Errorf("expected %s in output, got: %s", RedactedValue, output)
	}

	// Non-sensitive values should NOT be redacted.
	if !strings.Contains(output, "admin") {
		t.Errorf("non-sensitive value 'admin' should appear, got: %s", output)
	}
}

func TestRedactingHandler_RedactsPreAppliedAttrs(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: true}
	logger := New(cfg, &buf)

	// Pre-apply a sensitive attribute via With().
	secureLogger := logger.With("api_key", "sk-1234567890abcdef")
	secureLogger.Info("making API call")

	output := buf.String()

	if strings.Contains(output, "sk-1234567890abcdef") {
		t.Errorf("pre-applied api_key value should be redacted, got: %s", output)
	}
	if !strings.Contains(output, RedactedValue) {
		t.Errorf("expected %s in output, got: %s", RedactedValue, output)
	}
}

func TestRedactingHandler_NonSensitiveKeysPreserved(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: true}
	logger := New(cfg, &buf)

	logger.Info("parsed file",
		"module", "parser",
		"artifact_id", "abc-123",
		"observations", 42,
	)

	output := buf.String()

	// Non-sensitive values should appear unchanged.
	if !strings.Contains(output, "module=parser") {
		t.Errorf("expected 'module=parser', got: %s", output)
	}
	if !strings.Contains(output, "artifact_id=abc-123") {
		t.Errorf("expected 'artifact_id=abc-123', got: %s", output)
	}
	if !strings.Contains(output, "observations=42") {
		t.Errorf("expected 'observations=42', got: %s", output)
	}

	// No redaction should have occurred.
	if strings.Contains(output, RedactedValue) {
		t.Errorf("no redaction expected for non-sensitive keys, got: %s", output)
	}
}

func TestRedactingHandler_DisabledRedaction(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: false}
	logger := New(cfg, &buf)

	logger.Info("debug mode", "password", "visible_password")

	output := buf.String()

	// With redaction disabled, sensitive values should appear.
	if !strings.Contains(output, "visible_password") {
		t.Errorf("with redaction disabled, password should be visible, got: %s", output)
	}
}

func TestRedactingHandler_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "json", RedactSensitive: true}
	logger := New(cfg, &buf)

	logger.Info("login", "cookie", "session=abc123")

	output := buf.String()

	if strings.Contains(output, "session=abc123") {
		t.Errorf("cookie value should be redacted in JSON format, got: %s", output)
	}
	if !strings.Contains(output, RedactedValue) {
		t.Errorf("expected %s in JSON output, got: %s", RedactedValue, output)
	}
}

func TestRedactingHandler_MultipleSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text", RedactSensitive: true}
	logger := New(cfg, &buf)

	logger.Info("request",
		"authorization", "Bearer xyz",
		"cookie", "sid=abc",
		"url", "https://example.com/api",
		"secret", "mysecret",
	)

	output := buf.String()

	// All sensitive values should be redacted.
	if strings.Contains(output, "Bearer xyz") {
		t.Error("authorization should be redacted")
	}
	if strings.Contains(output, "sid=abc") {
		t.Error("cookie should be redacted")
	}
	if strings.Contains(output, "mysecret") {
		t.Error("secret should be redacted")
	}

	// Non-sensitive URL should be preserved.
	if !strings.Contains(output, "https://example.com/api") {
		t.Errorf("url should not be redacted, got: %s", output)
	}
}

func TestRedactingHandler_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "error", Format: "text", RedactSensitive: true}
	logger := New(cfg, &buf)

	logger.Info("this should be filtered", "password", "secret")

	output := buf.String()
	if output != "" {
		t.Errorf("info message should be filtered at error level, got: %s", output)
	}
}
