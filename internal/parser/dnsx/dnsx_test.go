package dnsx

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "dnsx" {
		t.Errorf("expected 'dnsx', got '%s'", p.Name())
	}
}

// Contract Test 1: Golden output.
func TestParseJSONL(t *testing.T) {
	p := New()

	f, err := os.Open("../../../testdata/dnsx/input.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact := domain.Artifact{FileName: "dnsx_output.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatal(err)
	}

	if len(obs) != 4 {
		t.Fatalf("expected 4 observations, got %d", len(obs))
	}

	// First: admin.example.com with A record.
	first := obs[0]
	if first.Type != domain.ObservationDNSLookup {
		t.Errorf("expected dns_lookup, got %s", first.Type)
	}
	if first.Data["host"] != "admin.example.com" {
		t.Errorf("expected admin.example.com, got %v", first.Data["host"])
	}
	aRecords, ok := first.Data["a"].([]string)
	if !ok || len(aRecords) != 1 || aRecords[0] != "203.0.113.10" {
		t.Errorf("expected A record 203.0.113.10, got %v", first.Data["a"])
	}

	// Second: api.example.com with A + AAAA.
	second := obs[1]
	if _, ok := second.Data["aaaa"]; !ok {
		t.Error("expected AAAA record for api.example.com")
	}

	// Third: mail with CNAME + MX.
	third := obs[2]
	if _, ok := third.Data["cname"]; !ok {
		t.Error("expected CNAME for mail.example.com")
	}
	if _, ok := third.Data["mx"]; !ok {
		t.Error("expected MX for mail.example.com")
	}

	// Fourth: NXDOMAIN (still a valid observation).
	fourth := obs[3]
	if fourth.Data["status_code"] != "NXDOMAIN" {
		t.Errorf("expected NXDOMAIN status, got %v", fourth.Data["status_code"])
	}
}

// Contract Test 2: CanParse detection.
func TestCanParse(t *testing.T) {
	p := New()

	tests := []struct {
		filename string
		header   string
		expected bool
	}{
		{"dnsx_output.jsonl", "", true},
		{"dnsx.json", "", true},
		{"unknown.jsonl", `{"host":"x.com","status_code":"NOERROR","resolver":["8.8.8.8"]}`, true},
		{"httpx_output.jsonl", "", false},
		{"random.txt", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			artifact := domain.Artifact{FileName: tt.filename}
			got := p.CanParse(artifact, []byte(tt.header))
			if got != tt.expected {
				t.Errorf("CanParse(%s) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// Contract Test 3: Malformed input.
func TestParseMalformedInput(t *testing.T) {
	p := New()

	malformed := `{"host":"good.example.com","status_code":"NOERROR","a":["1.2.3.4"]}
broken json {{{
{"host":"","status_code":"NOERROR"}
{"host":"also-good.example.com","status_code":"NOERROR"}
`
	artifact := domain.Artifact{FileName: "dnsx_bad.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(malformed))
	if err != nil {
		t.Fatal("should not error on malformed input")
	}
	if len(obs) != 2 {
		t.Errorf("expected 2 observations, got %d", len(obs))
	}
}

// Contract Test 4: Empty input.
func TestParseEmptyInput(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "dnsx_empty.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatal("should not error on empty input")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations, got %d", len(obs))
	}
}

// Contract Test 5: Timestamp parsing.
func TestTimestampParsing(t *testing.T) {
	p := New()

	input := `{"host":"timed.example.com","status_code":"NOERROR","a":["1.2.3.4"],"timestamp":"2025-01-15T10:30:00Z"}`
	artifact := domain.Artifact{FileName: "dnsx.jsonl"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatal("expected 1 observation")
	}
	if obs[0].ObservedAt.Year() != 2025 {
		t.Errorf("expected 2025, got %d", obs[0].ObservedAt.Year())
	}
}
