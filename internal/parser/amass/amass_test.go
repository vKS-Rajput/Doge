package amass

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestAmassParser_JSONAndText(t *testing.T) {
	p := New()
	input := `
{"name":"app.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4","cidr":"1.2.3.0/24","asn":12345,"desc":"Cloud"}],"tag":"dns","sources":["CertSpotter"]}
sub.example.com
`
	artifact := domain.Artifact{FileName: "amass.json"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Data["subdomain"] != "app.example.com" {
		t.Errorf("unexpected subdomain: %v", obs[0].Data["subdomain"])
	}
}
