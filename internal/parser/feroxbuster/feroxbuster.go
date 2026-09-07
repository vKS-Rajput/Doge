// Package feroxbuster implements a parser for Feroxbuster directory discovery outputs (JSON and text).
package feroxbuster

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "feroxbuster" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "ferox") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "\"type\":\"response\"") && strings.Contains(headerStr, "\"status\":") && strings.Contains(headerStr, "\"url\":") {
		return true
	}
	return false
}

type feroxResponse struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ContentLength int    `json:"content_length"`
	WordCount     int    `json:"word_count"`
	LineCount     int    `json:"line_count"`
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seenURLs := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON line
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var resp feroxResponse
			if err := json.Unmarshal([]byte(line), &resp); err == nil && resp.URL != "" {
				if seenURLs[resp.URL] {
					continue
				}
				seenURLs[resp.URL] = true

				u, _ := url.Parse(resp.URL)
				host := ""
				path := resp.Path
				if u != nil {
					host = u.Hostname()
					if path == "" {
						path = u.Path
					}
				}

				obs := domain.RawObservation{
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "feroxbuster",
					Data: map[string]any{
						"url":            resp.URL,
						"host":           host,
						"path":           path,
						"status_code":    resp.Status,
						"content_length": resp.ContentLength,
						"words":          resp.WordCount,
						"lines":          resp.LineCount,
					},
					RawValue:   line,
					ObservedAt: now,
				}
				observations = append(observations, obs)
				continue
			}
		}

		// Text format: 200      GET      123l      456w     7890c http://target/admin
		fields := strings.Fields(line)
		if len(fields) >= 5 && (fields[0] == "200" || fields[0] == "301" || fields[0] == "302" || fields[0] == "401" || fields[0] == "403") {
			status, _ := strconv.Atoi(fields[0])
			targetURL := fields[len(fields)-1]
			if strings.HasPrefix(targetURL, "http") && !seenURLs[targetURL] {
				seenURLs[targetURL] = true
				u, _ := url.Parse(targetURL)
				host := ""
				path := ""
				if u != nil {
					host = u.Hostname()
					path = u.Path
				}

				obs := domain.RawObservation{
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "feroxbuster",
					Data: map[string]any{
						"url":         targetURL,
						"host":        host,
						"path":        path,
						"status_code": status,
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
