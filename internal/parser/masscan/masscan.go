// Package masscan implements a parser for Masscan port scan outputs (JSON and text format).
package masscan

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "masscan" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "masscan") {
		return true
	}
	headerStr := string(header)
	if strings.Contains(headerStr, "Discovered open port") && strings.Contains(headerStr, "/tcp on") {
		return true
	}
	if strings.Contains(headerStr, "\"ip\":") && strings.Contains(headerStr, "\"ports\":") {
		return true
	}
	return false
}

type masscanJSONEntry struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
	Ports     []struct {
		Port     int    `json:"port"`
		Proto    string `json:"proto"`
		Status   string `json:"status"`
		TTL      int    `json:"ttl"`
		Service  struct {
			Name string `json:"name"`
		} `json:"service"`
	} `json:"ports"`
}

var textLineRegex = regexp.MustCompile(`Discovered open port (\d+)/(tcp|udp) on (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	var allContent strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		allContent.WriteString(trimmed)
		allContent.WriteString("\n")

		// Try text format line: Discovered open port 80/tcp on 192.168.1.1
		if matches := textLineRegex.FindStringSubmatch(trimmed); len(matches) == 4 {
			portNum, _ := strconv.Atoi(matches[1])
			proto := matches[2]
			ip := matches[3]

			obs := domain.RawObservation{
				Type:       domain.ObservationPortScan,
				SourceTool: "masscan",
				Data: map[string]any{
					"host":     ip,
					"port":     portNum,
					"protocol": proto,
					"state":    "open",
				},
				RawValue:   trimmed,
				ObservedAt: now,
			}
			observations = append(observations, obs)
		}
	}

	// Try JSON format if text format produced no observations
	if len(observations) == 0 {
		rawJSON := allContent.String()
		trimmedJSON := strings.TrimSpace(rawJSON)
		if strings.HasPrefix(trimmedJSON, "[") || strings.HasPrefix(trimmedJSON, "{") {
			var entries []masscanJSONEntry
			if strings.HasPrefix(trimmedJSON, "[") {
				_ = json.Unmarshal([]byte(trimmedJSON), &entries)
			} else {
				var single masscanJSONEntry
				if err := json.Unmarshal([]byte(trimmedJSON), &single); err == nil {
					entries = append(entries, single)
				}
			}

			for _, entry := range entries {
				for _, port := range entry.Ports {
					obs := domain.RawObservation{
						Type:       domain.ObservationPortScan,
						SourceTool: "masscan",
						Data: map[string]any{
							"host":     entry.IP,
							"port":     port.Port,
							"protocol": port.Proto,
							"state":    port.Status,
						},
						RawValue:   entry.IP,
						ObservedAt: now,
					}
					if port.Service.Name != "" {
						obs.Data["service"] = port.Service.Name
					}
					observations = append(observations, obs)
				}
			}
		}
	}

	return observations, nil
}
