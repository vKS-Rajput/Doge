// Package gobuster implements a parser for gobuster directory, dns, and vhost outputs.
package gobuster

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "gobuster" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "gobuster") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "Gobuster") || strings.Contains(headerStr, "(Status: ") {
		return true
	}
	return false
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "===") || strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "!--") {
			continue
		}

		// Gobuster dir output: /admin (Status: 301) [Size: 178] [--> http://target/admin/]
		if strings.Contains(line, "(Status: ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pathOrURL := parts[0]
				statusStr := ""
				for i, part := range parts {
					if part == "(Status:" && i+1 < len(parts) {
						statusStr = strings.TrimSuffix(parts[i+1], ")")
						break
					}
				}
				status, _ := strconv.Atoi(statusStr)

				if !seen[pathOrURL] {
					seen[pathOrURL] = true
					obs := domain.RawObservation{
						Type:       domain.ObservationEndpointDiscovery,
						SourceTool: "gobuster",
						Data: map[string]any{
							"path":        pathOrURL,
							"status_code": status,
						},
						RawValue:   line,
						ObservedAt: now,
					}
					if strings.HasPrefix(pathOrURL, "http") {
						obs.Data["url"] = pathOrURL
						if u, err := url.Parse(pathOrURL); err == nil {
							obs.Data["host"] = u.Hostname()
						}
					}
					observations = append(observations, obs)
				}
			}
			continue
		}

		// Gobuster dns output: Found: sub.example.com
		if strings.HasPrefix(line, "Found: ") {
			sub := strings.TrimSpace(strings.TrimPrefix(line, "Found: "))
			if sub != "" && !seen[sub] {
				seen[sub] = true
				obs := domain.RawObservation{
					Type:       domain.ObservationSubdomainDiscovery,
					SourceTool: "gobuster",
					Data: map[string]any{
						"subdomain": strings.ToLower(sub),
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
