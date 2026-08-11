// Package dnsx implements a parser for dnsx JSON output.
//
// dnsx is ProjectDiscovery's DNS toolkit. Its JSON output contains
// DNS resolution data: A, AAAA, CNAME, MX, NS records and status codes.
//
// This parser produces dns_lookup observations.
//
// Input format: one JSON object per line (JSONL/NDJSON).
package dnsx

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

// Parser converts dnsx JSONL output into DNS lookup observations.
type Parser struct{}

// New creates a new dnsx parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "dnsx" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like dnsx JSON output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	if strings.Contains(name, "dnsx") && (ext == ".json" || ext == ".jsonl" || ext == ".txt") {
		return true
	}

	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, `"host"`) && strings.Contains(s, `"status_code"`) &&
			(strings.Contains(s, `"resolver"`) || strings.Contains(s, `"a"`) || strings.Contains(s, `"cname"`)) {
			return true
		}
	}

	return false
}

// dnsxLine represents a single line of dnsx JSON output.
type dnsxLine struct {
	Host       string   `json:"host"`
	Resolver   []string `json:"resolver"`
	A          []string `json:"a"`
	AAAA       []string `json:"aaaa"`
	CNAME      []string `json:"cname"`
	MX         []string `json:"mx"`
	NS         []string `json:"ns"`
	SOA        string   `json:"soa"`
	TXT        []string `json:"txt"`
	StatusCode string   `json:"status_code"`
	Timestamp  string   `json:"timestamp"`
}

// Parse reads dnsx JSONL and produces DNS lookup observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	var observations []domain.RawObservation

	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}

		var entry dnsxLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Host == "" {
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

func (p *Parser) lineToObservation(entry dnsxLine, rawLine string) domain.RawObservation {
	data := map[string]any{
		"host":        entry.Host,
		"status_code": entry.StatusCode,
	}

	if len(entry.A) > 0 {
		data["a"] = entry.A
	}
	if len(entry.AAAA) > 0 {
		data["aaaa"] = entry.AAAA
	}
	if len(entry.CNAME) > 0 {
		data["cname"] = entry.CNAME
	}
	if len(entry.MX) > 0 {
		data["mx"] = entry.MX
	}
	if len(entry.NS) > 0 {
		data["ns"] = entry.NS
	}
	if len(entry.TXT) > 0 {
		data["txt"] = entry.TXT
	}
	if len(entry.Resolver) > 0 {
		data["resolver"] = entry.Resolver
	}

	observedAt := time.Now().UTC()
	if entry.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
			observedAt = t
		}
	}

	return domain.RawObservation{
		Type:       domain.ObservationDNSLookup,
		SourceTool: "dnsx",
		Data:       data,
		RawValue:   rawLine,
		ObservedAt: observedAt,
	}
}
