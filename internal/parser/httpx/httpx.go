// Package httpx implements a parser for httpx JSON output.
//
// httpx is ProjectDiscovery's HTTP probe tool. Its JSON output contains
// rich data about probed URLs: status codes, technologies, headers,
// certificates, and more.
//
// This parser produces ObservationHTTPProbe observations.
//
// Input format: one JSON object per line (JSONL/NDJSON).
package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts httpx JSONL output into HTTP probe observations.
type Parser struct{}

// New creates a new httpx parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "httpx" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like httpx JSON output.
// Detection heuristics:
//   - Filename contains "httpx"
//   - Content starts with a JSON object containing httpx-specific fields
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	// Check filename.
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))
	if strings.Contains(name, "httpx") && (ext == ".json" || ext == ".jsonl" || ext == ".txt") {
		return true
	}

	// Check content for httpx-specific JSON fields.
	if len(header) > 0 {
		s := string(header)
		// httpx JSON typically contains these fields.
		if strings.Contains(s, `"url"`) &&
			(strings.Contains(s, `"status_code"`) || strings.Contains(s, `"status-code"`)) {
			return true
		}
	}

	return false
}

// httpxLine represents a single line of httpx JSON output.
// Only the fields we care about are mapped here.
type httpxLine struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Title         string   `json:"title"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	WebServer     string   `json:"webserver"`
	Technologies  []string `json:"tech"`
	Words         int      `json:"words"`
	Lines         int      `json:"lines"`
	FinalURL      string   `json:"final_url"`
	Failed        bool     `json:"failed"`
	Timestamp     string   `json:"timestamp"`
}

// Parse reads httpx JSONL and produces HTTP probe observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	var observations []domain.RawObservation

	scanner := bufio.NewScanner(content)
	// Allow large lines (httpx can produce long JSON with headers, etc.)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}

		var entry httpxLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue // Skip malformed lines.
		}

		// Skip failed probes.
		if entry.Failed || entry.URL == "" {
			continue
		}

		obs := p.lineToObservation(entry, line)
		observations = append(observations, obs)
	}

	if err := scanner.Err(); err != nil {
		return observations, err // Return what we have + the error.
	}

	return observations, nil
}

// lineToObservation converts a parsed httpx line into a RawObservation.
func (p *Parser) lineToObservation(entry httpxLine, rawLine string) domain.RawObservation {
	data := map[string]any{
		"url":         entry.URL,
		"status_code": entry.StatusCode,
		"host":        entry.Host,
	}

	// Only include non-empty optional fields.
	if entry.Input != "" {
		data["input"] = entry.Input
	}
	if entry.ContentLength > 0 {
		data["content_length"] = entry.ContentLength
	}
	if entry.ContentType != "" {
		data["content_type"] = entry.ContentType
	}
	if entry.Title != "" {
		data["title"] = entry.Title
	}
	if entry.Port != "" {
		data["port"] = entry.Port
	}
	if entry.Scheme != "" {
		data["scheme"] = entry.Scheme
	}
	if entry.Method != "" {
		data["method"] = entry.Method
	}
	if entry.Path != "" {
		data["path"] = entry.Path
	}
	if entry.WebServer != "" {
		data["webserver"] = entry.WebServer
	}
	if len(entry.Technologies) > 0 {
		data["technologies"] = entry.Technologies
	}
	if entry.Words > 0 {
		data["words"] = entry.Words
	}
	if entry.Lines > 0 {
		data["lines"] = entry.Lines
	}
	if entry.FinalURL != "" && entry.FinalURL != entry.URL {
		data["final_url"] = entry.FinalURL
	}

	observedAt := time.Now().UTC()
	if entry.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
			observedAt = t
		}
	}

	return domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       data,
		RawValue:   rawLine,
		ObservedAt: observedAt,
	}
}
