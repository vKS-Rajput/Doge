package gobuster

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestGobusterParser_DirAndDNS(t *testing.T) {
	p := New()
	input := `
/admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
/login                (Status: 200) [Size: 450]
Found: mail.example.com
`
	artifact := domain.Artifact{FileName: "gobuster.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}
}
