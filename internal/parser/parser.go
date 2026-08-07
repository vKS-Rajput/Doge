// Package parser defines the Parser interface and Registry for converting
// artifacts into observations.
//
// A Parser does exactly one thing:
//
//	Artifact → []RawObservation
//
// No database. No graph. No AI. No timeline. Just parsing.
//
// Parsers are registered in the [Registry], which automatically selects
// the appropriate parser for a given artifact based on MIME type, filename,
// and content inspection.
//
// To implement a new parser:
//  1. Create a struct implementing the [Parser] interface
//  2. Register it via [Registry.Register]
//  3. Add golden tests in testdata/<tool>/
//  4. Ensure it passes the contract tests via [testing.AssertValidObservations]
package parser

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts an Artifact's content into a slice of RawObservations.
//
// This is the only contract a parser must satisfy. Parsers should be:
//   - Pure: no side effects, no database access, no network calls
//   - Deterministic: same input → same output, always
//   - Complete: extract everything useful from the artifact
//   - Honest: if data is ambiguous, skip it rather than guess
type Parser interface {
	// Name returns the unique identifier for this parser (e.g., "httpx", "nuclei", "burp_xml").
	Name() string

	// CanParse returns true if this parser can handle the given artifact.
	// The decision should be based on:
	//   - artifact.MIMEType
	//   - artifact.FileName (extension, naming conventions)
	//   - header (first bytes of content, for magic byte detection)
	//
	// CanParse must be fast — it may be called for every registered parser
	// on every imported file. Avoid reading the full content here.
	CanParse(artifact domain.Artifact, header []byte) bool

	// Parse reads the artifact content and produces observations.
	//
	// The content Reader provides the full file content. The parser should
	// consume it completely and return all extracted observations.
	//
	// If the content is malformed but partially parseable, the parser should
	// return whatever observations it could extract along with a nil error.
	// Only return an error for truly unrecoverable failures (e.g., I/O errors).
	Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error)

	// Version returns the parser version string. Used to track which
	// parser version produced each observation, enabling re-parsing
	// when parser logic improves.
	Version() string
}

// Registry holds all registered parsers and selects the appropriate one
// for a given artifact.
//
// Parser selection is first-match: the registry iterates parsers in
// registration order and returns the first one whose CanParse returns true.
// Register more specific parsers before generic ones.
//
// Registry is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	parsers []Parser
	logger  *slog.Logger
}

// NewRegistry creates a new parser registry.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		parsers: make([]Parser, 0),
		logger:  logger,
	}
}

// Register adds a parser to the registry. Parsers are tried in
// registration order, so register more specific parsers first.
//
// Panics if a parser with the same Name() is already registered.
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.parsers {
		if existing.Name() == p.Name() {
			panic("parser: duplicate registration: " + p.Name())
		}
	}

	r.parsers = append(r.parsers, p)
	r.logger.Info("parser registered",
		"parser", p.Name(),
		"version", p.Version(),
	)
}

// FindParser returns the first parser that can handle the given artifact.
// The header parameter should contain the first bytes of the file content
// (typically 512 bytes) for content-type detection.
//
// Returns nil if no parser can handle the artifact.
func (r *Registry) FindParser(artifact domain.Artifact, header []byte) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.parsers {
		if p.CanParse(artifact, header) {
			r.logger.Debug("parser selected",
				"parser", p.Name(),
				"artifact", artifact.FileName,
				"mime_type", artifact.MIMEType,
			)
			return p
		}
	}

	r.logger.Debug("no parser found",
		"artifact", artifact.FileName,
		"mime_type", artifact.MIMEType,
	)
	return nil
}

// Parsers returns the names of all registered parsers.
func (r *Registry) Parsers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.parsers))
	for i, p := range r.parsers {
		names[i] = p.Name()
	}
	return names
}

// Count returns the number of registered parsers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.parsers)
}
