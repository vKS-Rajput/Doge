package masscan

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestMasscanParser_Text(t *testing.T) {
	p := New()
	input := `
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1
Discovered open port 22/tcp on 10.0.0.2
`
	artifact := domain.Artifact{FileName: "masscan_out.txt"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}
	if obs[0].Data["host"] != "192.168.1.1" || obs[0].Data["port"] != 80 {
		t.Errorf("unexpected obs[0]: %+v", obs[0].Data)
	}
}

func TestMasscanParser_JSON(t *testing.T) {
	p := New()
	input := `[
  { "ip": "192.168.1.5", "timestamp": "1600000000", "ports": [ { "port": 8080, "proto": "tcp", "status": "open", "service": { "name": "http-proxy" } } ] }
]`
	artifact := domain.Artifact{FileName: "masscan.json"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Data["host"] != "192.168.1.5" || obs[0].Data["port"] != 8080 {
		t.Errorf("unexpected obs[0]: %+v", obs[0].Data)
	}
}
