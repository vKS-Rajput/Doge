// Package ffuf implements a parser for ffuf JSON output.
//
// ffuf is a fast web fuzzer. Its JSON output (-o result.json -of json) contains
// discovered endpoints with status codes, response sizes, and content types.
//
// This parser produces endpoint_discovery observations.
package ffuf

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts ffuf JSON output into endpoint discovery observations.
type Parser struct{}

// New creates a new ffuf parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "ffuf" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like ffuf JSON output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	if strings.Contains(name, "ffuf") && (ext == ".json" || ext == ".jsonl") {
		return true
	}

	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, `"commandline"`) && strings.Contains(s, `"results"`) &&
			strings.Contains(s, "ffuf") {
			return true
		}
	}

	return false
}

// ffufOutput represents the top-level ffuf JSON structure.
type ffufOutput struct {
	CommandLine string       `json:"commandline"`
	Results     []ffufResult `json:"results"`
}

type ffufResult struct {
	Input       map[string]string `json:"input"`
	Position    int               `json:"position"`
	Status      int               `json:"status"`
	Length      int               `json:"length"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content-type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Duration    int64             `json:"duration"`
}

// Parse reads ffuf JSON and produces endpoint discovery observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, nil
	}

	var output ffufOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, nil // Malformed — return empty.
	}

	var observations []domain.RawObservation
	now := time.Now().UTC()

	for _, result := range output.Results {
		if result.URL == "" {
			continue
		}

		obs := p.resultToObservation(result, now)
		observations = append(observations, obs)
	}

	return observations, nil
}

func (p *Parser) resultToObservation(result ffufResult, observedAt time.Time) domain.RawObservation {
	data := map[string]any{
		"url":         result.URL,
		"status_code": result.Status,
	}

	if result.Host != "" {
		data["host"] = result.Host
	}
	if result.Length > 0 {
		data["content_length"] = result.Length
	}
	if result.Words > 0 {
		data["words"] = result.Words
	}
	if result.Lines > 0 {
		data["lines"] = result.Lines
	}
	if result.ContentType != "" {
		data["content_type"] = result.ContentType
	}
	if result.Input != nil {
		data["input"] = result.Input
	}

	rawValue, _ := json.Marshal(result)

	return domain.RawObservation{
		Type:       domain.ObservationEndpointDiscovery,
		SourceTool: "ffuf",
		Data:       data,
		RawValue:   string(rawValue),
		ObservedAt: observedAt,
	}
}
