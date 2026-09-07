// Package assetfinder implements a parser for assetfinder subdomain discovery outputs.
package assetfinder

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "assetfinder" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "assetfinder") {
		return true
	}
	return false
}

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cleanDomain := strings.ToLower(line)
		cleanDomain = strings.TrimPrefix(cleanDomain, "*.")

		if seen[cleanDomain] {
			continue
		}

		if domainRegex.MatchString(cleanDomain) {
			seen[cleanDomain] = true
			observations = append(observations, domain.RawObservation{
				Type:       domain.ObservationSubdomainDiscovery,
				SourceTool: "assetfinder",
				Data: map[string]any{
					"subdomain": cleanDomain,
					"source":    "assetfinder",
				},
				RawValue:   line,
				ObservedAt: now,
			})
		}
	}

	return observations, scanner.Err()
}
