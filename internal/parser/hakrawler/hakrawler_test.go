package hakrawler

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestHakrawlerParser(t *testing.T) {
	p := New()
	input := `
https://example.com/
https://example.com/assets/app.js
https://example.com/api/users?page=1
`
	artifact := domain.Artifact{FileName: "hakrawler.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}
}
