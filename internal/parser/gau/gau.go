// Package gau implements a parser for GAU (GetAllUrls) and waybackurls outputs.
package gau

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "gau" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	return strings.Contains(name, "gau") || strings.Contains(name, "wayback")
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seen := make(map[string]bool)

	tool := "gau"
	if strings.Contains(strings.ToLower(artifact.FileName), "wayback") {
		tool = "waybackurls"
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "http") {
			continue
		}

		u, err := url.Parse(line)
		if err != nil || seen[line] {
			continue
		}
		seen[line] = true

		obsType := domain.ObservationEndpointDiscovery
		if strings.HasSuffix(strings.ToLower(u.Path), ".js") {
			obsType = domain.ObservationJavaScriptAnalysis
		}

		// Extract query parameters
		params := make([]string, 0)
		for paramName := range u.Query() {
			params = append(params, paramName)
		}

		obs := domain.RawObservation{
			Type:       obsType,
			SourceTool: tool,
			Data: map[string]any{
				"url":        line,
				"host":       u.Hostname(),
				"path":       u.Path,
				"query":      u.RawQuery,
				"parameters": params,
				"historical": true,
			},
			RawValue:   line,
			ObservedAt: now,
		}
		observations = append(observations, obs)
	}

	return observations, scanner.Err()
}
