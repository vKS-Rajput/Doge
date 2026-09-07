// Package sqlmap implements a parser for sqlmap injection testing outputs.
package sqlmap

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

func (p *Parser) Name() string { return "sqlmap" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "sqlmap") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "sqlmap identified the following injection point") || strings.Contains(headerStr, "Parameter:") && strings.Contains(headerStr, "Type:") {
		return true
	}
	return false
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	var currentParam, currentType, currentTitle, currentPayload, currentURL string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// URL line: Target: http://example.com/api?id=1
		if strings.HasPrefix(line, "Target:") || strings.HasPrefix(line, "URL:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentURL = parts[1]
			}
		}

		// Parameter line: Parameter: id (GET)
		if strings.HasPrefix(line, "Parameter:") {
			currentParam = strings.TrimSpace(strings.TrimPrefix(line, "Parameter:"))
		}

		// Type line: Type: boolean-based blind
		if strings.HasPrefix(line, "Type:") {
			currentType = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
		}

		// Title line: Title: AND boolean-based blind - WHERE or HAVING clause
		if strings.HasPrefix(line, "Title:") {
			currentTitle = strings.TrimSpace(strings.TrimPrefix(line, "Title:"))
		}

		// Payload line: Payload: id=1 AND 1=1
		if strings.HasPrefix(line, "Payload:") {
			currentPayload = strings.TrimSpace(strings.TrimPrefix(line, "Payload:"))

			// Complete injection record detected
			u, _ := url.Parse(currentURL)
			host := ""
			if u != nil {
				host = u.Hostname()
			}

			obs := domain.RawObservation{
				Type:       domain.ObservationVulnerabilityScan,
				SourceTool: "sqlmap",
				Data: map[string]any{
					"vulnerability_type": "sql_injection_candidate",
					"parameter":          currentParam,
					"injection_type":     currentType,
					"title":              currentTitle,
					"payload":            currentPayload,
					"url":                currentURL,
					"host":               host,
				},
				RawValue:   line,
				ObservedAt: now,
			}
			observations = append(observations, obs)
		}
	}

	return observations, scanner.Err()
}
