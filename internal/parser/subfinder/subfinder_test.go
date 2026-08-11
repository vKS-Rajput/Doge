package subfinder

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "subfinder" {
		t.Errorf("expected 'subfinder', got '%s'", p.Name())
	}
}

// --- Contract Test 1: Golden/real output ---

func TestParseJSONL(t *testing.T) {
	p := New()

	f, err := os.Open("../../../testdata/subfinder/input.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact := domain.Artifact{FileName: "subfinder_output.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatal(err)
	}

	if len(obs) != 5 {
		t.Fatalf("expected 5 observations, got %d", len(obs))
	}

	// Verify first observation.
	first := obs[0]
	if first.Type != domain.ObservationSubdomainDiscovery {
		t.Errorf("expected subdomain_discovery, got %s", first.Type)
	}
	if first.SourceTool != "subfinder" {
		t.Errorf("expected subfinder, got %s", first.SourceTool)
	}
	if first.Data["subdomain"] != "admin.example.com" {
		t.Errorf("expected admin.example.com, got %s", first.Data["subdomain"])
	}
	if first.Data["source"] != "crtsh" {
		t.Errorf("expected crtsh, got %s", first.Data["source"])
	}
	if first.Data["domain"] != "example.com" {
		t.Errorf("expected example.com, got %s", first.Data["domain"])
	}
}

func TestParsePlainText(t *testing.T) {
	p := New()

	f, err := os.Open("../../../testdata/subfinder/plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact := domain.Artifact{FileName: "subfinder_plain.txt"}
	obs, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatal(err)
	}

	if len(obs) != 5 {
		t.Fatalf("expected 5 observations from plain text, got %d", len(obs))
	}

	// Plain text has no source, but domain should be extracted.
	first := obs[0]
	if first.Data["subdomain"] != "admin.example.com" {
		t.Errorf("expected admin.example.com, got %s", first.Data["subdomain"])
	}
	if first.Data["domain"] != "example.com" {
		t.Errorf("expected example.com, got %s", first.Data["domain"])
	}
}

// --- Contract Test 2: CanParse detection ---

func TestCanParseByFilename(t *testing.T) {
	p := New()

	tests := []struct {
		filename string
		expected bool
	}{
		{"subfinder_output.jsonl", true},
		{"subfinder.json", true},
		{"subfinder_example.com.txt", true},
		{"httpx_output.jsonl", false},
		{"random.txt", false},
		{"nuclei_results.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			artifact := domain.Artifact{FileName: tt.filename}
			got := p.CanParse(artifact, nil)
			if got != tt.expected {
				t.Errorf("CanParse(%s) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

func TestCanParseByContent(t *testing.T) {
	p := New()

	// JSON content with subfinder fields.
	jsonHeader := []byte(`{"host":"admin.example.com","source":"crtsh","input":"example.com"}`)
	artifact := domain.Artifact{FileName: "unknown.jsonl"}
	if !p.CanParse(artifact, jsonHeader) {
		t.Error("expected CanParse=true for subfinder JSON content")
	}

	// Non-subfinder JSON.
	httpxHeader := []byte(`{"url":"https://example.com","status_code":200}`)
	if p.CanParse(artifact, httpxHeader) {
		t.Error("expected CanParse=false for httpx-like content")
	}
}

// --- Contract Test 3: Malformed input ---

func TestParseMalformedInput(t *testing.T) {
	p := New()

	malformed := `{"host":"admin.example.com","source":"crtsh"}
not json at all {{{
{"broken json
{"host":"","source":"crtsh"}
{"host":"valid.example.com","source":"web"}
`

	artifact := domain.Artifact{FileName: "subfinder_bad.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(malformed))
	if err != nil {
		t.Fatal("parser should not error on malformed input")
	}

	// Should extract what it can: 2 valid entries.
	if len(obs) != 2 {
		t.Errorf("expected 2 observations from partially malformed input, got %d", len(obs))
	}
}

// --- Contract Test 4: Empty input ---

func TestParseEmptyInput(t *testing.T) {
	p := New()

	artifact := domain.Artifact{FileName: "subfinder_empty.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatal("parser should not error on empty input")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations from empty input, got %d", len(obs))
	}
}

// --- Contract Test 5: Deduplication ---

func TestDeduplicatesWithinFile(t *testing.T) {
	p := New()

	input := `{"host":"admin.example.com","source":"crtsh","input":"example.com"}
{"host":"admin.example.com","source":"virustotal","input":"example.com"}
{"host":"api.example.com","source":"crtsh","input":"example.com"}
`

	artifact := domain.Artifact{FileName: "subfinder_dupes.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	// admin.example.com appears twice but should only produce 1 observation.
	if len(obs) != 2 {
		t.Errorf("expected 2 unique observations, got %d", len(obs))
	}
}

// --- Helper tests ---

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"admin.example.com", "example.com"},
		{"admin.api.example.com", "example.com"},
		{"example.com", "example.com"},
		{"deep.sub.domain.example.com", "example.com"},
	}

	for _, tt := range tests {
		got := extractDomain(tt.input)
		if got != tt.expected {
			t.Errorf("extractDomain(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestLooksLikeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"admin.example.com", true},
		{"example.com", true},
		{"https://example.com", false},   // has ://
		{"not a hostname", false},         // has spaces
		{"a", false},                      // too short
		{"{json}", false},                 // braces
		{"admin@example.com", false},      // has @
	}

	for _, tt := range tests {
		got := looksLikeHostname(tt.input)
		if got != tt.expected {
			t.Errorf("looksLikeHostname(%s) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
