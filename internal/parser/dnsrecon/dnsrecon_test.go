package dnsrecon

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestDNSReconParser(t *testing.T) {
	p := New()
	input := `
[*]      A api.example.com 93.184.216.34
[*]      CNAME mail.example.com google.com
`
	artifact := domain.Artifact{FileName: "dnsrecon.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Data["host"] != "api.example.com" || obs[0].Data["record_type"] != "A" {
		t.Errorf("unexpected obs[0]: %+v", obs[0].Data)
	}
}
