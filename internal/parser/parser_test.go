package parser

import (
	"context"
	"io"
	"testing"

	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// mockParser is a test parser for registry tests.
type mockParser struct {
	name     string
	canParse bool
}

func (m *mockParser) Name() string    { return m.name }
func (m *mockParser) Version() string { return "1.0.0" }
func (m *mockParser) CanParse(artifact domain.Artifact, header []byte) bool {
	return m.canParse
}
func (m *mockParser) Parse(_ context.Context, _ domain.Artifact, _ io.Reader) ([]domain.RawObservation, error) {
	return nil, nil
}

func TestRegistryRegisterAndFind(t *testing.T) {
	r := NewRegistry(logging.NewNop())

	p := &mockParser{name: "test-parser", canParse: true}
	r.Register(p)

	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}

	found := r.FindParser(domain.Artifact{}, nil)
	if found == nil {
		t.Fatal("expected to find parser")
	}
	if found.Name() != "test-parser" {
		t.Errorf("found parser name = %q, want 'test-parser'", found.Name())
	}
}

func TestRegistryFirstMatch(t *testing.T) {
	r := NewRegistry(logging.NewNop())

	r.Register(&mockParser{name: "specific", canParse: true})
	r.Register(&mockParser{name: "generic", canParse: true})

	// Should return first match.
	found := r.FindParser(domain.Artifact{}, nil)
	if found.Name() != "specific" {
		t.Errorf("expected first-match 'specific', got %q", found.Name())
	}
}

func TestRegistryNoMatch(t *testing.T) {
	r := NewRegistry(logging.NewNop())

	r.Register(&mockParser{name: "no-match", canParse: false})

	found := r.FindParser(domain.Artifact{}, nil)
	if found != nil {
		t.Error("expected nil when no parser matches")
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	r := NewRegistry(logging.NewNop())
	r.Register(&mockParser{name: "dup", canParse: false})

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()

	r.Register(&mockParser{name: "dup", canParse: false})
}

func TestRegistryParsers(t *testing.T) {
	r := NewRegistry(logging.NewNop())
	r.Register(&mockParser{name: "a", canParse: false})
	r.Register(&mockParser{name: "b", canParse: false})

	names := r.Parsers()
	if len(names) != 2 {
		t.Errorf("Parsers() length = %d, want 2", len(names))
	}
	if names[0] != "a" || names[1] != "b" {
		t.Errorf("Parsers() = %v, want [a, b]", names)
	}
}
