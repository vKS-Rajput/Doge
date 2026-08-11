package katana

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	if New().Name() != "katana" {
		t.Error("expected 'katana'")
	}
}

func TestParseJSONL(t *testing.T) {
	p := New()
	f, err := os.Open("../../../testdata/katana/output.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "katana.jsonl"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}
	if obs[0].Type != domain.ObservationCrawlResult {
		t.Errorf("expected crawl_result, got %s", obs[0].Type)
	}
	if obs[0].Data["url"] != "https://admin.example.com/admin/dashboard" {
		t.Errorf("unexpected url: %v", obs[0].Data["url"])
	}
}

func TestCanParse(t *testing.T) {
	p := New()
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"katana_output.jsonl", "", true},
		{"katana.json", "", true},
		{"unknown.jsonl", `{"request":{"method":"GET","endpoint":"https://x.com"},"response":{"status_code":200}}`, true},
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
	obs, err := New().Parse(context.Background(), domain.Artifact{FileName: "k.jsonl"}, strings.NewReader("{bad\n{broken"))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

func TestParseEmpty(t *testing.T) {
	obs, err := New().Parse(context.Background(), domain.Artifact{FileName: "k.jsonl"}, strings.NewReader(""))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

func TestDeduplicatesURLs(t *testing.T) {
	input := `{"request":{"method":"GET","endpoint":"https://x.com/a"},"response":{"status_code":200},"matched":"https://x.com/a"}
{"request":{"method":"GET","endpoint":"https://x.com/a"},"response":{"status_code":200},"matched":"https://x.com/a"}
{"request":{"method":"GET","endpoint":"https://x.com/b"},"response":{"status_code":200},"matched":"https://x.com/b"}`
	obs, err := New().Parse(context.Background(), domain.Artifact{FileName: "k.jsonl"}, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Errorf("expected 2 unique, got %d", len(obs))
	}
}
