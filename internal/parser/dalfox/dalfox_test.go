package dalfox

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestDalfoxParser_JSONAndText(t *testing.T) {
	p := New()
	input := `
{"type":"VULN","param":"q","poc":"https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E","severity":"High","method":"GET"}
[POC][V] https://example.com/profile?name=%3Cimg+src=x+onerror=alert(1)%3E
`
	artifact := domain.Artifact{FileName: "dalfox.json"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].Data["type"] != "xss_candidate" {
		t.Errorf("unexpected obs[0]: %+v", obs[0].Data)
	}
}
