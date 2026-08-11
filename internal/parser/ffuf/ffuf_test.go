package ffuf

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	if New().Name() != "ffuf" {
		t.Error("expected 'ffuf'")
	}
}

func TestParseJSON(t *testing.T) {
	p := New()
	f, err := os.Open("../../../testdata/ffuf/results.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact := domain.Artifact{FileName: "ffuf_results.json"}
	obs, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 4 {
		t.Fatalf("expected 4 observations, got %d", len(obs))
	}
	if obs[0].Type != domain.ObservationEndpointDiscovery {
		t.Errorf("expected endpoint_discovery, got %s", obs[0].Type)
	}
	if obs[0].Data["url"] != "https://admin.example.com/admin" {
		t.Errorf("unexpected url: %v", obs[0].Data["url"])
	}
	if obs[0].Data["status_code"] != 200 {
		t.Errorf("expected status 200, got %v", obs[0].Data["status_code"])
	}
}

func TestCanParse(t *testing.T) {
	p := New()
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"ffuf_results.json", "", true},
		{"ffuf.json", "", true},
		{"unknown.json", `{"commandline":"ffuf -u ...","results":[]}`, true},
		{"nmap.xml", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(domain.Artifact{FileName: tt.name}, []byte(tt.header))
			if got != tt.expected {
				t.Errorf("CanParse(%s) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	p := New()
	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "ffuf.json"}, strings.NewReader("{broken"))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

func TestParseEmpty(t *testing.T) {
	p := New()
	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "ffuf.json"}, strings.NewReader(""))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

func TestFilterEmptyURLs(t *testing.T) {
	p := New()
	input := `{"commandline":"ffuf","results":[{"url":"","status":200},{"url":"https://x.com/a","status":200}]}`
	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "ffuf.json"}, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Errorf("expected 1 (empty URL filtered), got %d", len(obs))
	}
}
