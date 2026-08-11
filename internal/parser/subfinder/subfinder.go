// Package subfinder implements a parser for subfinder output.
//
// subfinder is ProjectDiscovery's subdomain discovery tool. It supports
// two output formats:
//   - JSONL (-oJ): {"host":"sub.example.com","source":"crtsh","input":"example.com"}
//   - Plain text: one subdomain per line
//
// This parser produces subdomain_discovery observations.
//
// The parser is:
//   - Pure: no side effects, no database access, no network calls
//   - Deterministic: same input → same output
//   - Honest: malformed lines are skipped, not guessed
package subfinder

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

// Parser converts subfinder output into subdomain discovery observations.
type Parser struct{}

// New creates a new subfinder parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "subfinder" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like subfinder output.
// Detection heuristics:
//   - Filename contains "subfinder"
//   - Content is JSONL with "host" and "source" fields (subfinder JSON)
//   - Content is plain hostnames (one per line, all look like FQDNs)
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	// Filename detection.
	if strings.Contains(name, "subfinder") {
		return true
	}

	// Content detection for JSONL format.
	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, `"host"`) && strings.Contains(s, `"source"`) {
			return true
		}
	}

	// Plain text with common subdomain extensions.
	if ext == ".txt" && len(header) > 0 {
		s := string(header)
		lines := strings.Split(s, "\n")
		hostCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && looksLikeHostname(line) {
				hostCount++
			}
		}
		// If most non-empty lines look like hostnames, it's probably a subdomain list.
		if hostCount >= 3 {
			return true
		}
	}

	return false
}

// subfinderLine represents a single line of subfinder JSON output.
type subfinderLine struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	Input  string `json:"input"`
}

// Parse reads subfinder output and produces subdomain discovery observations.
// Supports both JSONL and plain text formats.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	var observations []domain.RawObservation
	seen := make(map[string]bool) // Deduplicate within a single file.

	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var obs *domain.RawObservation

		// Try JSON first.
		if line[0] == '{' {
			obs = p.parseJSON(line)
		} else {
			obs = p.parsePlain(line)
		}

		if obs == nil {
			continue
		}

		// Deduplicate within this file.
		host, _ := obs.Data["subdomain"].(string)
		if host == "" {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true

		observations = append(observations, *obs)
	}

	if err := scanner.Err(); err != nil {
		return observations, err
	}

	return observations, nil
}

func (p *Parser) parseJSON(line string) *domain.RawObservation {
	var entry subfinderLine
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil
	}

	if entry.Host == "" {
		return nil
	}

	data := map[string]any{
		"subdomain": strings.ToLower(entry.Host),
	}

	if entry.Source != "" {
		data["source"] = entry.Source
	}
	if entry.Input != "" {
		data["domain"] = strings.ToLower(entry.Input)
	} else {
		data["domain"] = extractDomain(entry.Host)
	}

	return &domain.RawObservation{
		Type:       domain.ObservationSubdomainDiscovery,
		SourceTool: "subfinder",
		Data:       data,
		RawValue:   line,
		ObservedAt: time.Now().UTC(),
	}
}

func (p *Parser) parsePlain(line string) *domain.RawObservation {
	host := strings.ToLower(strings.TrimSpace(line))
	if !looksLikeHostname(host) {
		return nil
	}

	return &domain.RawObservation{
		Type:       domain.ObservationSubdomainDiscovery,
		SourceTool: "subfinder",
		Data: map[string]any{
			"subdomain": host,
			"domain":    extractDomain(host),
		},
		RawValue:   line,
		ObservedAt: time.Now().UTC(),
	}
}

// looksLikeHostname returns true if the string looks like a valid FQDN.
func looksLikeHostname(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	// Must contain at least one dot.
	if !strings.Contains(s, ".") {
		return false
	}
	// Must not contain spaces or obvious non-hostname characters.
	for _, c := range s {
		if c == ' ' || c == '/' || c == ':' || c == '@' || c == '{' || c == '}' {
			return false
		}
	}
	return true
}

// extractDomain extracts the base domain from a subdomain.
// e.g., "admin.api.example.com" → "example.com"
func extractDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
