// Package katana implements a parser for katana JSONL output.
//
// katana is ProjectDiscovery's web crawler. Its JSONL output contains
// crawled URLs with request/response data and discovered technologies.
//
// This parser produces crawl_result observations.
package katana

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

// Parser converts katana JSONL output into crawl result observations.
type Parser struct{}

// New creates a new katana parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "katana" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like katana output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	if strings.Contains(name, "katana") && (ext == ".json" || ext == ".jsonl" || ext == ".txt") {
		return true
	}

	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, `"request"`) && strings.Contains(s, `"response"`) &&
			strings.Contains(s, `"endpoint"`) {
			return true
		}
	}

	return false
}

type katanaLine struct {
	Timestamp string        `json:"timestamp"`
	Request   katanaRequest `json:"request"`
	Response  katanaResponse `json:"response"`
	Matched   string        `json:"matched"`
}

type katanaRequest struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
}

type katanaResponse struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Technologies []string          `json:"technologies"`
}

// Parse reads katana JSONL and produces crawl result observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	var observations []domain.RawObservation
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}

		var entry katanaLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		url := entry.Request.Endpoint
		if url == "" {
			url = entry.Matched
		}
		if url == "" {
			continue
		}

		if seen[url] {
			continue
		}
		seen[url] = true

		data := map[string]any{
			"url":    url,
			"method": entry.Request.Method,
		}

		if entry.Response.StatusCode > 0 {
			data["status_code"] = entry.Response.StatusCode
		}
		if ct, ok := entry.Response.Headers["content-type"]; ok {
			data["content_type"] = ct
		}
		if len(entry.Response.Technologies) > 0 {
			data["technologies"] = entry.Response.Technologies
		}

		observedAt := time.Now().UTC()
		if entry.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
				observedAt = t
			}
		}

		observations = append(observations, domain.RawObservation{
			Type:       domain.ObservationCrawlResult,
			SourceTool: "katana",
			Data:       data,
			RawValue:   line,
			ObservedAt: observedAt,
		})
	}

	if err := scanner.Err(); err != nil {
		return observations, err
	}

	return observations, nil
}
