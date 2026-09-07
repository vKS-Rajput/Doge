// Package amass implements a parser for OWASP Amass enum outputs (JSON and text format).
package amass

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

func (p *Parser) Name() string { return "amass" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "amass") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "\"name\":") && strings.Contains(headerStr, "\"domain\":") && strings.Contains(headerStr, "\"addresses\":") {
		return true
	}
	return false
}

type amassJSONRecord struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Addresses []struct {
		IP   string `json:"ip"`
		CIDR string `json:"cidr"`
		ASN  int    `json:"asn"`
		Desc string `json:"desc"`
	} `json:"addresses"`
	Tag     string   `json:"tag"`
	Sources []string `json:"sources"`
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seenNames := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON line first
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var rec amassJSONRecord
			if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.Name != "" {
				name := strings.ToLower(strings.TrimSpace(rec.Name))
				if !seenNames[name] {
					seenNames[name] = true

					var ips []string
					for _, addr := range rec.Addresses {
						if addr.IP != "" {
							ips = append(ips, addr.IP)
						}
					}

					obs := domain.RawObservation{
						Type:       domain.ObservationSubdomainDiscovery,
						SourceTool: "amass",
						Data: map[string]any{
							"subdomain": name,
							"domain":    rec.Domain,
							"tag":       rec.Tag,
							"sources":   rec.Sources,
						},
						RawValue:   line,
						ObservedAt: now,
					}
					if len(ips) > 0 {
						obs.Data["ips"] = ips
					}
					observations = append(observations, obs)
				}
				continue
			}
		}

		// Otherwise parse plain text line (e.g. "subdomain.example.com" or "subdomain.example.com [FQDN] 1.2.3.4")
		fields := strings.Fields(line)
		if len(fields) > 0 {
			name := strings.ToLower(strings.TrimSpace(fields[0]))
			if strings.Contains(name, ".") && !seenNames[name] {
				seenNames[name] = true
				obs := domain.RawObservation{
					Type:       domain.ObservationSubdomainDiscovery,
					SourceTool: "amass",
					Data: map[string]any{
						"subdomain": name,
						"source":    "amass_text",
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
