// Package nuclei implements a parser for nuclei JSONL output.
//
// nuclei is ProjectDiscovery's vulnerability scanner. Its JSONL output
// contains template match results with severity, descriptions, and references.
//
// CRITICAL ARCHITECTURAL RULE:
//
//	A nuclei template match is an OBSERVATION, not a FINDING.
//	"Scanner pattern matched" ≠ "Vulnerability confirmed."
//
//	The observation enters the Knowledge Graph as evidence.
//	It may generate an Insight and a Task.
//	Only a researcher can promote it to a Finding (with evidence).
//
// This parser produces vulnerability_scan observations.
package nuclei

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

// Parser converts nuclei JSONL output into vulnerability scan observations.
//
// Nuclei results are OBSERVATIONS. They record that a scanner template
// matched. They do NOT confirm vulnerabilities. The authority hierarchy:
//
//	Nuclei match → Observation → Insight → Task → Researcher → Finding
type Parser struct{}

// New creates a new nuclei parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "nuclei" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like nuclei output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	if strings.Contains(name, "nuclei") && (ext == ".json" || ext == ".jsonl" || ext == ".txt") {
		return true
	}

	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, `"template-id"`) && strings.Contains(s, `"info"`) &&
			strings.Contains(s, `"matched-at"`) {
			return true
		}
	}

	return false
}

// nucleiLine represents a single nuclei JSONL result.
// The "info" object is nested in nuclei output.
type nucleiLine struct {
	TemplateID       string   `json:"template-id"`
	Info             nucleiInfo `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	MatcherName      string   `json:"matcher-name"`
	CURLCommand      string   `json:"curl-command"`
}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Reference   []string `json:"reference"`
	Author      []string `json:"author"`
}

// Parse reads nuclei JSONL and produces vulnerability scan observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	var observations []domain.RawObservation

	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}

		var entry nucleiLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.TemplateID == "" || entry.Host == "" {
			continue
		}

		obs := p.lineToObservation(entry, line)
		observations = append(observations, obs)
	}

	if err := scanner.Err(); err != nil {
		return observations, err
	}

	return observations, nil
}

func (p *Parser) lineToObservation(entry nucleiLine, rawLine string) domain.RawObservation {
	data := map[string]any{
		"template_id": entry.TemplateID,
		"name":        entry.Info.Name,
		"host":        entry.Host,
		// CRITICAL: severity is SCANNER-REPORTED, not confirmed.
		// The field name explicitly marks this as the scanner's assessment.
		"scanner_severity": entry.Info.Severity,
	}

	if entry.MatchedAt != "" {
		data["matched_at"] = entry.MatchedAt
	}
	if entry.IP != "" {
		data["ip"] = entry.IP
	}
	if entry.Info.Description != "" {
		data["description"] = entry.Info.Description
	}
	if len(entry.Info.Tags) > 0 {
		data["tags"] = entry.Info.Tags
	}
	if len(entry.Info.Reference) > 0 {
		data["references"] = entry.Info.Reference
	}
	if len(entry.ExtractedResults) > 0 {
		data["extracted_results"] = entry.ExtractedResults
	}
	if entry.MatcherName != "" {
		data["matcher_name"] = entry.MatcherName
	}
	if entry.Type != "" {
		data["scan_type"] = entry.Type
	}

	observedAt := time.Now().UTC()
	if entry.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
			observedAt = t
		}
	}

	return domain.RawObservation{
		Type:       domain.ObservationVulnerabilityScan,
		SourceTool: "nuclei",
		Data:       data,
		RawValue:   rawLine,
		ObservedAt: observedAt,
	}
}
