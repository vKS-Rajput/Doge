package logging

import (
	"context"
	"log/slog"
	"strings"
)

// RedactedValue is the replacement string for sensitive data in log output.
const RedactedValue = "[REDACTED]"

// sensitiveKeys is the set of log attribute keys whose values must be
// redacted. Keys are matched case-insensitively. This list covers the
// most common sensitive fields in security tooling output.
//
// Adding a key here is cheap and safe — false positives (redacting a
// non-sensitive value) are acceptable; false negatives (leaking a
// sensitive value) are not.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"passwd":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"bearer":        true,
	"api_key":       true,
	"apikey":        true,
	"secret":        true,
	"secret_key":    true,
	"authorization": true,
	"cookie":        true,
	"set_cookie":    true,
	"set-cookie":    true,
	"session":       true,
	"session_id":    true,
	"credential":    true,
	"credentials":   true,
	"private_key":   true,
	"jwt":           true,
}

// IsSensitiveKey returns true if the given key name should trigger
// value redaction. The check is case-insensitive.
func IsSensitiveKey(key string) bool {
	return sensitiveKeys[strings.ToLower(key)]
}

// RedactingHandler is a [slog.Handler] wrapper that replaces the values
// of sensitive attributes with [RedactedValue] before passing them to
// the base handler.
//
// Redaction occurs in two places:
//   - In [WithAttrs], for attributes pre-applied via logger.With()
//   - In [Handle], for per-record attributes added to individual log calls
//
// Sensitive keys are identified by [IsSensitiveKey]. Only string values
// are redacted — non-string values with sensitive keys are replaced
// with the string [RedactedValue].
type RedactingHandler struct {
	base slog.Handler
}

// NewRedactingHandler creates a handler that redacts sensitive attribute
// values before delegating to the base handler.
func NewRedactingHandler(base slog.Handler) *RedactingHandler {
	return &RedactingHandler{base: base}
}

// Enabled reports whether the handler handles records at the given level.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle redacts sensitive attributes in the record and delegates
// to the base handler.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Build a new record with redacted attributes.
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	r.Attrs(func(a slog.Attr) bool {
		newRecord.AddAttrs(redactAttr(a))
		return true
	})

	return h.base.Handle(ctx, newRecord)
}

// WithAttrs returns a new handler with the given attributes pre-applied,
// after redacting sensitive ones. Pre-applied attributes appear in every
// subsequent log line from loggers using this handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &RedactingHandler{base: h.base.WithAttrs(redacted)}
}

// WithGroup returns a new handler with the given group name.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{base: h.base.WithGroup(name)}
}

// redactAttr checks if an attribute's key is sensitive and replaces
// its value with [RedactedValue] if so. Group attributes are processed
// recursively.
func redactAttr(a slog.Attr) slog.Attr {
	// Handle group attributes recursively.
	if a.Value.Kind() == slog.KindGroup {
		groupAttrs := a.Value.Group()
		redacted := make([]any, len(groupAttrs))
		for i, ga := range groupAttrs {
			redacted[i] = redactAttr(ga)
		}
		return slog.Group(a.Key, redacted...)
	}

	// Redact if the key is sensitive.
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, RedactedValue)
	}

	return a
}
