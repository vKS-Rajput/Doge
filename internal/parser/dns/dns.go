// Package dns implements a parser for dig, host, and nslookup text output.
//
// Produces dns_lookup observations from common DNS tool output.
package dns

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts DNS tool text output into observations.
type Parser struct{}

// New creates a new DNS parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "dns-text" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like DNS tool output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	if ext == ".xml" || ext == ".json" || ext == ".jsonl" {
		return false
	}

	// Filename heuristic.
	for _, tool := range []string{"dig", "host_", "nslookup"} {
		if strings.Contains(name, tool) && (ext == ".txt" || ext == ".log" || ext == "") {
			return true
		}
	}

	// Content detection.
	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, ";; ANSWER SECTION:") { // dig
			return true
		}
		if strings.Contains(s, "has address") || strings.Contains(s, "mail is handled by") { // host
			return true
		}
		if strings.Contains(s, "Non-authoritative answer:") { // nslookup
			return true
		}
	}

	return false
}

var (
	// dig ANSWER patterns.
	digRecordRe = regexp.MustCompile(`^(\S+)\.\s+\d+\s+IN\s+(A|AAAA|CNAME|MX|NS|TXT|SOA|SRV)\s+(.+)`)

	// host command patterns.
	hostAddressRe = regexp.MustCompile(`^(\S+)\s+has\s+(?:IPv6\s+)?address\s+(.+)`)
	hostMailRe    = regexp.MustCompile(`^(\S+)\s+mail\s+is\s+handled\s+by\s+\d+\s+(.+)`)
	hostAliasRe   = regexp.MustCompile(`^(\S+)\s+is\s+an\s+alias\s+for\s+(.+)`)

	// nslookup patterns.
	nslookupAddrRe = regexp.MustCompile(`^Address:\s+(\S+)`)
	nslookupNameRe = regexp.MustCompile(`^Name:\s+(\S+)`)
)

// Parse reads DNS tool output and produces observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	text := strings.Join(lines, "\n")
	now := time.Now().UTC()
	tool := detectDNSTool(artifact.FileName, text)

	switch tool {
	case "dig":
		return p.parseDig(lines, now)
	case "nslookup":
		return p.parseNslookup(lines, now)
	default:
		return p.parseHost(lines, now)
	}
}

func (p *Parser) parseDig(lines []string, now time.Time) ([]domain.RawObservation, error) {
	var obs []domain.RawObservation
	inAnswer := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, ";; ANSWER SECTION:") {
			inAnswer = true
			continue
		}
		if strings.HasPrefix(trimmed, ";;") {
			inAnswer = false
			continue
		}

		if !inAnswer {
			continue
		}

		m := digRecordRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}

		host := strings.TrimSuffix(m[1], ".")
		recordType := m[2]
		value := strings.TrimSuffix(strings.TrimSpace(m[3]), ".")

		data := map[string]any{
			"host": host,
		}

		switch recordType {
		case "A", "AAAA":
			data["a"] = []string{value}
		case "CNAME":
			data["cname"] = []string{value}
		case "MX":
			data["mx"] = []string{value}
		case "NS":
			data["ns"] = []string{value}
		case "TXT":
			data["txt"] = []string{value}
		}

		obs = append(obs, domain.RawObservation{
			Type:       domain.ObservationDNSLookup,
			SourceTool: "dig",
			Data:       data,
			RawValue:   trimmed,
			ObservedAt: now,
		})
	}

	return obs, nil
}

func (p *Parser) parseHost(lines []string, now time.Time) ([]domain.RawObservation, error) {
	var obs []domain.RawObservation

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if m := hostAddressRe.FindStringSubmatch(trimmed); m != nil {
			host := m[1]
			ip := m[2]
			obs = append(obs, domain.RawObservation{
				Type:       domain.ObservationDNSLookup,
				SourceTool: "host",
				Data: map[string]any{
					"host": host,
					"a":    []string{ip},
				},
				RawValue:   trimmed,
				ObservedAt: now,
			})
		} else if m := hostMailRe.FindStringSubmatch(trimmed); m != nil {
			host := m[1]
			mx := m[2]
			obs = append(obs, domain.RawObservation{
				Type:       domain.ObservationDNSLookup,
				SourceTool: "host",
				Data: map[string]any{
					"host": host,
					"mx":   []string{mx},
				},
				RawValue:   trimmed,
				ObservedAt: now,
			})
		} else if m := hostAliasRe.FindStringSubmatch(trimmed); m != nil {
			host := m[1]
			cname := strings.TrimSuffix(m[2], ".")
			obs = append(obs, domain.RawObservation{
				Type:       domain.ObservationDNSLookup,
				SourceTool: "host",
				Data: map[string]any{
					"host":  host,
					"cname": []string{cname},
				},
				RawValue:   trimmed,
				ObservedAt: now,
			})
		}
	}

	return obs, nil
}

func (p *Parser) parseNslookup(lines []string, now time.Time) ([]domain.RawObservation, error) {
	var obs []domain.RawObservation

	var currentName string
	inAnswer := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "Non-authoritative answer:") {
			inAnswer = true
			continue
		}

		if !inAnswer {
			continue
		}

		if m := nslookupNameRe.FindStringSubmatch(trimmed); m != nil {
			currentName = m[1]
		} else if m := nslookupAddrRe.FindStringSubmatch(trimmed); m != nil && currentName != "" {
			ip := m[1]
			obs = append(obs, domain.RawObservation{
				Type:       domain.ObservationDNSLookup,
				SourceTool: "nslookup",
				Data: map[string]any{
					"host": currentName,
					"a":    []string{ip},
				},
				RawValue:   trimmed,
				ObservedAt: now,
			})
		}
	}

	return obs, nil
}

func detectDNSTool(filename, content string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "dig"):
		return "dig"
	case strings.Contains(lower, "nslookup"):
		return "nslookup"
	case strings.Contains(content, ";; ANSWER SECTION:"):
		return "dig"
	case strings.Contains(content, "Non-authoritative answer:"):
		return "nslookup"
	default:
		return "host"
	}
}
