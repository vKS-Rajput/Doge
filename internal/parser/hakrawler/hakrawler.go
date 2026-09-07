// Package hakrawler implements a parser for hakrawler web crawling outputs.
package hakrawler

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

func (p *Parser) Name() string { return "hakrawler" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	return strings.Contains(name, "hakrawler")
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seen := make(map[string]bool)

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

		obsType := domain.ObservationCrawlResult
		if strings.HasSuffix(strings.ToLower(u.Path), ".js") {
			obsType = domain.ObservationJavaScriptAnalysis
		} else if u.RawQuery != "" || strings.Contains(u.Path, "/api/") {
			obsType = domain.ObservationEndpointDiscovery
		}

		obs := domain.RawObservation{
			Type:       obsType,
			SourceTool: "hakrawler",
			Data: map[string]any{
				"url":      line,
				"host":     u.Hostname(),
				"path":     u.Path,
				"query":    u.RawQuery,
				"protocol": u.Scheme,
			},
			RawValue:   line,
			ObservedAt: now,
		}
		observations = append(observations, obs)
	}

	return observations, scanner.Err()
}
