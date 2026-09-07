// Package dnsrecon implements a parser for dnsrecon outputs (JSON, CSV, and text).
package dnsrecon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "dnsrecon" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "dnsrecon") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "\"type\":") && (strings.Contains(headerStr, "\"name\":") || strings.Contains(headerStr, "\"address\":")) {
		return true
	}
	return false
}

type dnsreconEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Target  string `json:"target"`
	Port    int    `json:"port"`
	Host    string `json:"host"`
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	var fullContent strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		fullContent.WriteString(line)
		fullContent.WriteString("\n")

		trimmed := strings.TrimSpace(line)
		// Standard dnsrecon text line: [*]      A target.example.com 192.168.1.1
		if strings.HasPrefix(trimmed, "[*]") || strings.HasPrefix(trimmed, "[+]") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 4 {
				rtype := fields[1]
				rname := strings.ToLower(fields[2])
				rval := fields[3]

				obs := domain.RawObservation{
					Type:       domain.ObservationDNSLookup,
					SourceTool: "dnsrecon",
					Data: map[string]any{
						"host":        rname,
						"record_type": rtype,
						"value":       rval,
					},
					RawValue:   trimmed,
					ObservedAt: now,
				}
				observations = append(observations, obs)
			}
		}
	}

	// Try JSON parse if text produced no records
	if len(observations) == 0 {
		raw := strings.TrimSpace(fullContent.String())
		if strings.HasPrefix(raw, "[") {
			var entries []dnsreconEntry
			if err := json.Unmarshal([]byte(raw), &entries); err == nil {
				for _, entry := range entries {
					host := entry.Name
					if host == "" {
						host = entry.Host
					}
					val := entry.Address
					if val == "" {
						val = entry.Target
					}

					obs := domain.RawObservation{
						Type:       domain.ObservationDNSLookup,
						SourceTool: "dnsrecon",
						Data: map[string]any{
							"host":        strings.ToLower(host),
							"record_type": entry.Type,
							"value":       val,
						},
						RawValue:   host,
						ObservedAt: now,
					}
					if entry.Port > 0 {
						obs.Data["port"] = entry.Port
					}
					observations = append(observations, obs)
				}
			}
		}
	}

	return observations, nil
}
