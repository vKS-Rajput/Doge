package feroxbuster

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestFeroxbusterParser_JSONAndText(t *testing.T) {
	p := New()
	input := `
{"type":"response","url":"https://example.com/api/v2/users","path":"/api/v2/users","status":200,"content_length":1024,"word_count":45,"line_count":12}
200      GET       12l       45w     1024c https://example.com/admin
`
	artifact := domain.Artifact{FileName: "ferox.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
}
