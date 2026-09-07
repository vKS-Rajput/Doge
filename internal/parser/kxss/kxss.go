// Package kxss implements a parser for kxss parameter reflection outputs.
package kxss

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

func (p *Parser) Name() string { return "kxss" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "kxss") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "param:") && strings.Contains(headerStr, "filtered:") {
		return true
	}
	return false
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Example: URL: http://target/search?q=test Param: q Unfiltered: [ " < > ]
		if strings.Contains(line, "URL:") || strings.Contains(line, "Param:") {
			fields := strings.Fields(line)
			targetURL := ""
			param := ""
			for i, f := range fields {
				if (f == "URL:" || f == "url:") && i+1 < len(fields) {
					targetURL = fields[i+1]
				}
				if (f == "Param:" || f == "param:") && i+1 < len(fields) {
					param = fields[i+1]
				}
			}

			if targetURL != "" || param != "" {
				u, _ := url.Parse(targetURL)
				host := ""
				if u != nil {
					host = u.Hostname()
				}

				obs := domain.RawObservation{
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "kxss",
					Data: map[string]any{
						"url":         targetURL,
						"host":        host,
						"parameter":   param,
						"reflection":  true,
					},
					RawValue:   line,
					ObservedAt: now,
				}
				observations = append(observations, obs)
			}
		}
	}

	return observations, scanner.Err()
}
