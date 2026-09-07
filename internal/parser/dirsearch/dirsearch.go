// Package dirsearch implements a parser for dirsearch output (JSON and text format).
package dirsearch

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

func (p *Parser) Name() string { return "dirsearch" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "dirsearch") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "_  _  _") || strings.Contains(headerStr, "dirsearch") {
		return true
	}
	return false
}

type dirsearchJSON struct {
	Results []struct {
		URL           string `json:"url"`
		Path          string `json:"path"`
		Status        int    `json:"status"`
		ContentLength int    `json:"content_length"`
		Redirect      string `json:"redirect"`
	} `json:"results"`
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seenURLs := make(map[string]bool)
	var fullText strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fullText.WriteString(line)
		fullText.WriteString("\n")

		// Text format: [12:34:56] 200 -   123B  - /admin/login.php
		if strings.HasPrefix(line, "[") && strings.Contains(line, "] ") && strings.Contains(line, " - ") {
			idx := strings.Index(line, "] ")
			rest := line[idx+2:]
			fields := strings.Split(rest, " - ")
			if len(fields) >= 3 {
				statusStr := strings.TrimSpace(fields[0])
				status, _ := strconv.Atoi(statusStr)
				path := strings.TrimSpace(fields[len(fields)-1])

				if !seenURLs[path] && path != "" {
					seenURLs[path] = true
					obs := domain.RawObservation{
						Type:       domain.ObservationEndpointDiscovery,
						SourceTool: "dirsearch",
						Data: map[string]any{
							"path":        path,
							"status_code": status,
						},
						RawValue:   line,
						ObservedAt: now,
					}
					if strings.HasPrefix(path, "http") {
						obs.Data["url"] = path
						if u, err := url.Parse(path); err == nil {
							obs.Data["host"] = u.Hostname()
						}
					}
					observations = append(observations, obs)
				}
			}
		}
	}

	// Try JSON format
	if len(observations) == 0 {
		raw := strings.TrimSpace(fullText.String())
		if strings.HasPrefix(raw, "{") {
			var ds dirsearchJSON
			if err := json.Unmarshal([]byte(raw), &ds); err == nil {
				for _, res := range ds.Results {
					if seenURLs[res.URL] {
						continue
					}
					seenURLs[res.URL] = true
					u, _ := url.Parse(res.URL)
					host := ""
					if u != nil {
						host = u.Hostname()
					}

					obs := domain.RawObservation{
						Type:       domain.ObservationEndpointDiscovery,
						SourceTool: "dirsearch",
						Data: map[string]any{
							"url":            res.URL,
							"host":           host,
							"path":           res.Path,
							"status_code":    res.Status,
							"content_length": res.ContentLength,
							"redirect":       res.Redirect,
						},
						RawValue:   res.URL,
						ObservedAt: now,
					}
					observations = append(observations, obs)
				}
			}
		}
	}

	return observations, scanner.Err()
}
