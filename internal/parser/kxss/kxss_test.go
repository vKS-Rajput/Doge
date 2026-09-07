package kxss

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestKxssParser(t *testing.T) {
	p := New()
	input := `
URL: https://example.com/search?q=test Param: q Unfiltered: [ " < > ]
URL: https://example.com/item?id=123 Param: id Unfiltered: [ ' ]
`
	artifact := domain.Artifact{FileName: "kxss.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Data["parameter"] != "q" {
		t.Errorf("unexpected param: %v", obs[0].Data["parameter"])
	}
}
