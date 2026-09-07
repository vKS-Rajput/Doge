// Package whois implements a parser for whois registration and domain/IP lookup outputs.
package whois

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "whois" }

func (p *Parser) Version() string { return "1.0.0" }

func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	if strings.Contains(name, "whois") {
		return true
	}
	headerStr := strings.ToLower(string(header))
	if strings.Contains(headerStr, "domain name:") || strings.Contains(headerStr, "registrar:") || strings.Contains(headerStr, "netrange:") || strings.Contains(headerStr, "cidr:") {
		return true
	}
	return false
}

func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	var domainName, registrar, org, netRange, cidr string
	var nameServers []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "domain name":
			if domainName == "" {
				domainName = strings.ToLower(val)
			}
		case "registrar":
			if registrar == "" {
				registrar = val
			}
		case "registrant organization", "orgname", "org-name":
			if org == "" {
				org = val
			}
		case "name server", "nserver":
			ns := strings.ToLower(strings.Fields(val)[0])
			nameServers = append(nameServers, ns)
		case "netrange", "inetnum":
			if netRange == "" {
				netRange = val
			}
		case "cidr", "route":
			if cidr == "" {
				cidr = val
			}
		}
	}

	if domainName != "" {
		obs := domain.RawObservation{
			Type:       domain.ObservationSubdomainDiscovery,
			SourceTool: "whois",
			Data: map[string]any{
				"subdomain":    domainName,
				"registrar":    registrar,
				"organization": org,
				"nameservers":  nameServers,
			},
			RawValue:   domainName,
			ObservedAt: now,
		}
		observations = append(observations, obs)
	}

	if cidr != "" || netRange != "" {
		data := map[string]any{
			"organization": org,
		}
		if cidr != "" {
			data["cidr"] = cidr
		}
		if netRange != "" {
			data["netrange"] = netRange
		}
		observations = append(observations, domain.RawObservation{
			Type:       domain.ObservationDNSLookup,
			SourceTool: "whois",
			Data:       data,
			RawValue:   cidr,
			ObservedAt: now,
		})
	}

	return observations, scanner.Err()
}
