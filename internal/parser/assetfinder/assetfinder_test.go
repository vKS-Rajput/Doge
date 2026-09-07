package assetfinder

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestAssetfinderParser(t *testing.T) {
	p := New()
	input := `
api.example.com
admin.example.com
*.dev.example.com
# comment
invalid_domain
test.example.com
`
	artifact := domain.Artifact{FileName: "assetfinder.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 4 {
		t.Fatalf("expected 4 valid subdomains, got %d", len(obs))
	}
}
