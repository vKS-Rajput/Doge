package sqlmap

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestSQLMapParser(t *testing.T) {
	p := New()
	input := `
Target: https://example.com/api/products?cat=1
Parameter: cat (GET)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: cat=1 AND 5821=5821
`
	artifact := domain.Artifact{FileName: "sqlmap.log"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Data["vulnerability_type"] != "sql_injection_candidate" {
		t.Errorf("unexpected vuln type: %v", obs[0].Data["vulnerability_type"])
	}
	if obs[0].Data["parameter"] != "cat (GET)" {
		t.Errorf("unexpected parameter: %v", obs[0].Data["parameter"])
	}
}
