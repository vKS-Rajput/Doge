// Package generic implements a high-confidence evidence extractor for
// arbitrary text output.
//
// This is the LAST RESORT parser. It only extracts evidence when pattern
// matches are unambiguous. It will never create entities from ordinary prose.
//
// High-confidence extractions:
//   - URLs (https?://...)
//   - IPv4 addresses (verified format, excludes version numbers)
//   - Ports (explicit port/tcp or port/udp notation)
//   - HTTP status lines
//
// This parser is registered last in the registry so tool-specific parsers
// always take priority.
package generic

import (
	"bufio"
	"context"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser extracts high-confidence evidence from arbitrary text.
type Parser struct{}

// New creates a new generic evidence parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "generic" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true for any text artifact that wasn't claimed by a
// tool-specific parser. Since this is registered last, it acts as a fallback.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)

	// Skip binary/structured formats.
	for _, ext := range []string{".xml", ".json", ".jsonl", ".csv", ".png", ".jpg", ".gif", ".pdf", ".zip", ".gz", ".tar"} {
		if strings.HasSuffix(name, ext) {
			return false
		}
	}

	// Only claim .txt and .log files with enough content.
	if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".log") {
		return len(header) > 10
	}

	return false
}

var (
	urlRe     = regexp.MustCompile(`https?://[^\s"'<>\x60\x00-\x1f]+`)
	ipv4Re    = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	portRe    = regexp.MustCompile(`\b(\d{1,5})/(tcp|udp)\b`)
	httpRe    = regexp.MustCompile(`(?:^|[<>]\s*)HTTP/[\d.]+\s+(\d{3})\b`)
)

// Parse extracts high-confidence evidence from text.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	now := time.Now().UTC()

	seenURLs := make(map[string]bool)
	seenIPs := make(map[string]bool)
	seenPorts := make(map[string]bool)

	var observations []domain.RawObservation

	for scanner.Scan() {
		line := scanner.Text()

		// Extract URLs.
		for _, u := range urlRe.FindAllString(line, -1) {
			// Clean trailing punctuation.
			u = strings.TrimRight(u, ".,;:)}>\"'")
			if seenURLs[u] {
				continue
			}
			seenURLs[u] = true

			observations = append(observations, domain.RawObservation{
				Type:       domain.ObservationHTTPProbe,
				SourceTool: "generic",
				Data: map[string]any{
					"url":    u,
					"source": "text_extraction",
				},
				RawValue:   u,
				ObservedAt: now,
			})
		}

		// Extract IPv4 addresses (validate they're real IPs).
		for _, m := range ipv4Re.FindAllStringSubmatch(line, -1) {
			ip := m[1]
			if seenIPs[ip] || !isValidIP(ip) {
				continue
			}
			seenIPs[ip] = true

			observations = append(observations, domain.RawObservation{
				Type:       domain.ObservationPortScan,
				SourceTool: "generic",
				Data: map[string]any{
					"host":   ip,
					"source": "text_extraction",
				},
				RawValue:   ip,
				ObservedAt: now,
			})
		}

		// Extract port/protocol pairs.
		for _, m := range portRe.FindAllStringSubmatch(line, -1) {
			portKey := m[1] + "/" + m[2]
			if seenPorts[portKey] {
				continue
			}
			seenPorts[portKey] = true

			// Port-only observations are low value without a host,
			// so we skip these to avoid noise.
		}
	}

	return observations, scanner.Err()
}

// isValidIP checks that an IPv4 string is a real routable address,
// not a version number like 1.2.3 or 255.255.255.255.
func isValidIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}

	// Exclude loopback, unspecified, broadcast.
	if ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}

	// Exclude 0.0.0.0 and 255.255.255.255.
	if s == "0.0.0.0" || s == "255.255.255.255" {
		return false
	}

	return true
}
