// Package dalfox implements a parser for DalFox XSS scanner outputs.
package dalfox

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "dalfox" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "dalfox") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "[POC]") || strings.Contains(headerStr, "\"param\":") && strings.Contains(headerStr, "\"type\":\"VULN\"") {
		return true
	}
	return false
}

type dalfoxJSON struct {
	Type     string `json:"type"`
	Param    string `json:"param"`
	PoC      string `json:"poc"`
	Severity string `json:"severity"`
	Method   string `json:"method"`
	Data     string `json:"data"`
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

		// JSON line
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var df dalfoxJSON
			if err := json.Unmarshal([]byte(line), &df); err == nil && df.PoC != "" {
				u, _ := url.Parse(df.PoC)
				host := ""
				if u != nil {
					host = u.Hostname()
				}

				obs := domain.RawObservation{
					Type:       domain.ObservationVulnerabilityScan,
					SourceTool: "dalfox",
					Data: map[string]any{
						"type":      "xss_candidate",
						"parameter": df.Param,
						"poc":       df.PoC,
						"severity":  df.Severity,
						"method":    df.Method,
						"host":      host,
					},
					RawValue:   line,
					ObservedAt: now,
				}
				observations = append(observations, obs)
				continue
			}
		}

		// Text format: [POC][V] http://target/search?q=%3Cscript%3E...
		if strings.Contains(line, "[POC]") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "http") {
					u, _ := url.Parse(field)
					host := ""
					if u != nil {
						host = u.Hostname()
					}
					obs := domain.RawObservation{
						Type:       domain.ObservationVulnerabilityScan,
						SourceTool: "dalfox",
						Data: map[string]any{
							"type": "xss_candidate",
							"poc":  field,
							"host": host,
						},
						RawValue:   line,
						ObservedAt: now,
					}
					observations = append(observations, obs)
					break
				}
			}
		}
	}

	return observations, scanner.Err()
}
