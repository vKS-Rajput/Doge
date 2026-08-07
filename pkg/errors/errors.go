// Package errors defines shared error types used across all modules
// in the workspace.
//
// All errors in this package follow these conventions:
//   - Sentinel errors (ErrNotFound, ErrAlreadyExists, etc.) enable
//     callers to use errors.Is() for control flow
//   - Wrapped errors preserve the full error chain for debugging
//   - Error messages are descriptive enough for a developer to
//     understand the problem without reading source code
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure modes. Modules should wrap these
// with context using fmt.Errorf("...: %w", Err...) to preserve the
// error chain while adding module-specific context.
var (
	// ErrNotFound indicates a requested resource does not exist.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates a resource with the same identity
	// already exists (unique constraint violation).
	ErrAlreadyExists = errors.New("already exists")

	// ErrInvalidInput indicates the caller provided invalid arguments.
	ErrInvalidInput = errors.New("invalid input")

	// ErrDuplicate indicates a duplicate was detected (e.g., same
	// observation checksum).
	ErrDuplicate = errors.New("duplicate")

	// ErrNotSupported indicates the requested operation is not supported
	// (e.g., no parser available for a file format).
	ErrNotSupported = errors.New("not supported")

	// ErrDatabaseError indicates a database operation failed.
	ErrDatabaseError = errors.New("database error")

	// ErrConfigError indicates a configuration problem.
	ErrConfigError = errors.New("configuration error")

	// ErrModelUnavailable indicates no AI model is available or healthy.
	ErrModelUnavailable = errors.New("model unavailable")

	// ErrVerificationFailed indicates the Verification Engine rejected
	// an AI response because it contained unsupported claims.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrContextBudgetExceeded indicates the context assembly exceeded
	// the model's token budget.
	ErrContextBudgetExceeded = errors.New("context budget exceeded")

	// ErrPluginError indicates a plugin failed during execution.
	ErrPluginError = errors.New("plugin error")

	// ErrShuttingDown indicates the system is shutting down and
	// cannot accept new work.
	ErrShuttingDown = errors.New("shutting down")
)

// NotFoundError wraps ErrNotFound with resource type and identifier.
func NotFoundError(resourceType string, id any) error {
	return fmt.Errorf("%s %v: %w", resourceType, id, ErrNotFound)
}

// AlreadyExistsError wraps ErrAlreadyExists with resource type and identifier.
func AlreadyExistsError(resourceType string, id any) error {
	return fmt.Errorf("%s %v: %w", resourceType, id, ErrAlreadyExists)
}

// InvalidInputError wraps ErrInvalidInput with a descriptive message.
func InvalidInputError(message string) error {
	return fmt.Errorf("%s: %w", message, ErrInvalidInput)
}

// DatabaseError wraps ErrDatabaseError with operation context.
func DatabaseError(operation string, err error) error {
	return fmt.Errorf("%s: %w: %w", operation, ErrDatabaseError, err)
}
