package gau

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestGAUParser(t *testing.T) {
	p := New()
	input := `
https://example.com/login
https://example.com/api/v1/orders?user_id=123&token=abc
https://example.com/static/bundle.js
`
	artifact := domain.Artifact{FileName: "gau_out.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}
}
