// Package nmap — text.go implements a parser for nmap's human-readable
// text output (stdout capture).
//
// When nmap is run without -oX, its output goes to stdout in text form:
//
//	Starting Nmap 7.98 ( https://nmap.org ) at ...
//	Nmap scan report for localhost (127.0.0.1)
//	PORT   STATE SERVICE VERSION
//	80/tcp open  http    nginx
//
// This parser extracts the same port_scan observations as the XML parser,
// allowing DOGE's auto-capture pipeline to process nmap output regardless
// of whether the user passed -oX.
package nmap

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

// TextParser converts nmap text (stdout) output into port scan observations.
type TextParser struct{}

// NewTextParser creates a new nmap text parser.
func NewTextParser() *TextParser { return &TextParser{} }

// Name returns the parser identifier.
func (p *TextParser) Name() string { return "nmap-text" }

// Version returns the parser version.
func (p *TextParser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like nmap text output.
func (p *TextParser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	// Filename-based: captured stdout files are named nmap_*.txt
	if strings.Contains(name, "nmap") && ext == ".txt" {
		return true
	}

	// Content-based: look for nmap text signatures.
	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, "Starting Nmap") ||
			strings.Contains(s, "Nmap scan report for") ||
			strings.Contains(s, "Nmap done:") {
			return true
		}
	}

	return false
}

// Regex patterns for nmap text output.
var (
	// "Nmap scan report for localhost (127.0.0.1)" or "Nmap scan report for 10.10.11.123"
	reHostLine = regexp.MustCompile(`(?i)Nmap scan report for\s+(\S+?)(?:\s+\(([^)]+)\))?$`)

	// "80/tcp  open  http    nginx 1.18.0"
	// Captures: port, protocol, state, service, version (optional)
	rePortLine = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(open|open\|filtered|filtered)\s+(\S+)\s*(.*)$`)
)

// Parse reads nmap text output and produces port scan observations.
func (p *TextParser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)

	var observations []domain.RawObservation
	var currentHost string
	var currentHostname string
	scanTime := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Extract host from "Nmap scan report for ..." line.
		if matches := reHostLine.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			ip := matches[2] // May be empty if no parenthesized IP.

			if ip != "" {
				currentHost = ip
				currentHostname = name
			} else {
				currentHost = name
				currentHostname = ""
			}
			continue
		}

		// Extract port/service from table rows.
		if matches := rePortLine.FindStringSubmatch(line); matches != nil {
			if currentHost == "" {
				continue // No host context yet.
			}

			portNum, _ := strconv.Atoi(matches[1])
			protocol := matches[2]
			state := matches[3]
			service := matches[4]
			versionRaw := strings.TrimSpace(matches[5])

			// Parse version info: "nginx 1.18.0" → product="nginx", version="1.18.0"
			product, version := parseVersionString(versionRaw)

			data := map[string]any{
				"host":     currentHost,
				"port":     portNum,
				"protocol": protocol,
				"state":    state,
			}

			if currentHostname != "" {
				data["hostname"] = currentHostname
			}
			if service != "" {
				data["service"] = service
			}
			if product != "" {
				data["product"] = product
			}
			if version != "" {
				data["version"] = version
			}

			rawValue := strings.Join([]string{
				currentHost,
				matches[1],
				protocol,
				state,
				service,
			}, "|")

			observations = append(observations, domain.RawObservation{
				Type:       domain.ObservationPortScan,
				SourceTool: "nmap",
				Data:       data,
				RawValue:   rawValue,
				ObservedAt: scanTime,
			})
		}
	}

	return observations, scanner.Err()
}

// parseVersionString splits "nginx 1.18.0" into ("nginx", "1.18.0").
// Handles: "nginx", "nginx 1.18.0", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1"
func parseVersionString(s string) (product, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	parts := strings.Fields(s)
	if len(parts) == 0 {
		return "", ""
	}

	product = parts[0]
	if len(parts) > 1 {
		version = parts[1]
	}

	return product, version
}
