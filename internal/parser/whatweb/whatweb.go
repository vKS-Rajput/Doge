// Package whatweb implements a parser for WhatWeb text output.
//
// WhatWeb produces output like:
//
//	https://example.com [200 OK] Country[US], HTML5, HTTPServer[nginx],
//	Script[module], Title[Example], Strict-Transport-Security[max-age=31536000]
//
// This parser extracts http_probe and technology_detection observations.
package whatweb

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts WhatWeb text output into observations.
type Parser struct{}

// New creates a new WhatWeb parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "whatweb" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like WhatWeb output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	// Don't claim XML/JSON.
	if ext == ".xml" || ext == ".json" || ext == ".jsonl" {
		return false
	}

	// Filename contains whatweb.
	if strings.Contains(name, "whatweb") && (ext == ".txt" || ext == ".log" || ext == "") {
		return true
	}

	// Content detection.
	if len(header) > 0 {
		s := string(header)
		// WhatWeb output format: URL [status] key[value], key[value], ...
		if whatwebLineRe.MatchString(s) {
			return true
		}
		if strings.Contains(s, "WhatWeb report") || strings.Contains(s, "WhatWeb/") {
			return true
		}
	}

	return false
}

// whatwebLineRe matches the main WhatWeb output line: URL [200 OK] ...
var whatwebLineRe = regexp.MustCompile(`^https?://\S+\s+\[\d{3}\s+`)

// pluginRe matches WhatWeb plugin output: PluginName[value] or just PluginName
var pluginRe = regexp.MustCompile(`([A-Za-z][\w-]*?)(?:\[([^\]]*)\])?(?:,|$)`)

// Parse reads WhatWeb text output and produces observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		obs := p.parseLine(line, now)
		observations = append(observations, obs...)
	}

	return observations, scanner.Err()
}

func (p *Parser) parseLine(line string, now time.Time) []domain.RawObservation {
	var obs []domain.RawObservation

	// Extract URL and status.
	urlEnd := strings.Index(line, " [")
	if urlEnd < 0 {
		return nil
	}
	rawURL := strings.TrimSpace(line[:urlEnd])
	if !strings.HasPrefix(rawURL, "http") {
		return nil
	}

	rest := line[urlEnd:]

	// Extract status code: [200 OK]
	var statusCode int
	statusEnd := strings.Index(rest, "] ")
	if statusEnd > 0 {
		statusStr := rest[2:statusEnd] // Skip " ["
		parts := strings.SplitN(statusStr, " ", 2)
		if code, err := strconv.Atoi(parts[0]); err == nil {
			statusCode = code
		}
		rest = rest[statusEnd+2:]
	}

	// Build HTTP probe observation.
	probeData := map[string]any{
		"url": rawURL,
	}
	if statusCode > 0 {
		probeData["status_code"] = statusCode
	}

	// Extract host from URL.
	if strings.Contains(rawURL, "://") {
		parts := strings.SplitN(rawURL, "://", 2)
		if len(parts) == 2 {
			hostPart := parts[1]
			if idx := strings.IndexAny(hostPart, ":/"); idx > 0 {
				hostPart = hostPart[:idx]
			}
			probeData["host"] = hostPart
		}
	}

	// Parse WhatWeb plugins from rest of line.
	var technologies []string
	plugins := parsePlugins(rest)

	for name, value := range plugins {
		lowerName := strings.ToLower(name)

		switch {
		case lowerName == "httpserver":
			probeData["webserver"] = value
			technologies = append(technologies, value)
		case lowerName == "title":
			probeData["title"] = value
		case lowerName == "country":
			probeData["country"] = value
		case lowerName == "ip":
			probeData["ip"] = value
		case lowerName == "strict-transport-security":
			if _, ok := probeData["security_headers"]; !ok {
				probeData["security_headers"] = map[string]string{}
			}
			if sh, ok := probeData["security_headers"].(map[string]string); ok {
				sh["strict-transport-security"] = value
			}
		case lowerName == "x-frame-options":
			if _, ok := probeData["security_headers"]; !ok {
				probeData["security_headers"] = map[string]string{}
			}
			if sh, ok := probeData["security_headers"].(map[string]string); ok {
				sh["x-frame-options"] = value
			}
		case lowerName == "x-powered-by":
			technologies = append(technologies, value)
		default:
			// Most WhatWeb plugins are technologies.
			if value != "" {
				technologies = append(technologies, name+"["+value+"]")
			} else {
				technologies = append(technologies, name)
			}
		}
	}

	if len(technologies) > 0 {
		probeData["technologies"] = technologies
	}

	obs = append(obs, domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "whatweb",
		Data:       probeData,
		RawValue:   line,
		ObservedAt: now,
	})

	// Individual technology detection observations.
	for _, tech := range technologies {
		obs = append(obs, domain.RawObservation{
			Type:       domain.ObservationTechnologyDetect,
			SourceTool: "whatweb",
			Data: map[string]any{
				"technology": tech,
				"url":        rawURL,
				"source":     "whatweb",
			},
			RawValue:   tech,
			ObservedAt: now,
		})
	}

	return obs
}

// parsePlugins extracts WhatWeb plugin key-value pairs from a line.
func parsePlugins(s string) map[string]string {
	plugins := make(map[string]string)

	// Split by ", " but handle brackets.
	parts := splitPlugins(s)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for Name[Value] pattern.
		bracketStart := strings.Index(part, "[")
		if bracketStart > 0 && strings.HasSuffix(part, "]") {
			name := part[:bracketStart]
			value := part[bracketStart+1 : len(part)-1]
			plugins[name] = value
		} else {
			// Bare plugin name (e.g., "HTML5").
			plugins[part] = ""
		}
	}

	return plugins
}

// splitPlugins splits WhatWeb output by commas, respecting brackets.
func splitPlugins(s string) []string {
	var parts []string
	depth := 0
	start := 0

	for i, c := range s {
		switch c {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}

	if start < len(s) {
		parts = append(parts, s[start:])
	}

	return parts
}
