package whois

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestWhoisParser(t *testing.T) {
	p := New()
	input := `
Domain Name: example.com
Registrar: Example Registrar LLC
Registrant Organization: Example Corp
Name Server: ns1.example.com
Name Server: ns2.example.com
CIDR: 192.0.2.0/24
`
	artifact := domain.Artifact{FileName: "whois.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations (domain + cidr), got %d", len(obs))
	}
	if obs[0].Data["subdomain"] != "example.com" {
		t.Errorf("unexpected domain: %v", obs[0].Data["subdomain"])
	}
}
