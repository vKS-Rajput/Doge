package dirsearch

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestDirsearchParser(t *testing.T) {
	p := New()
	input := `
[12:34:56] 200 -   123B  - /api/v1/health
[12:34:57] 301 -   456B  - /admin
`
	artifact := domain.Artifact{FileName: "dirsearch.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
}
