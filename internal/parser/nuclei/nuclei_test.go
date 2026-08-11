package nuclei

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	if New().Name() != "nuclei" {
		t.Error("expected 'nuclei'")
	}
}

// Contract Test 1: Golden output.
func TestParseJSONL(t *testing.T) {
	p := New()
	f, err := os.Open("../../../testdata/nuclei/results.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "nuclei.jsonl"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 5 {
		t.Fatalf("expected 5 observations, got %d", len(obs))
	}

	// All must be vulnerability_scan type.
	for i, o := range obs {
		if o.Type != domain.ObservationVulnerabilityScan {
			t.Errorf("obs[%d]: expected vulnerability_scan, got %s", i, o.Type)
		}
		if o.SourceTool != "nuclei" {
			t.Errorf("obs[%d]: expected nuclei, got %s", i, o.SourceTool)
		}
	}

	// Verify critical finding uses scanner_severity, NOT severity.
	critical := obs[4]
	if critical.Data["scanner_severity"] != "critical" {
		t.Errorf("expected scanner_severity=critical, got %v", critical.Data["scanner_severity"])
	}
	// Must NOT have a "severity" field — only scanner_severity.
	if _, exists := critical.Data["severity"]; exists {
		t.Error("nuclei observations must use 'scanner_severity', not 'severity' — " +
			"vulnerability confirmation requires researcher investigation")
	}

	// Verify XSS has correct template info.
	xss := obs[2]
	if xss.Data["template_id"] != "xss-reflected" {
		t.Errorf("expected xss-reflected, got %v", xss.Data["template_id"])
	}
	if xss.Data["scanner_severity"] != "high" {
		t.Errorf("expected high, got %v", xss.Data["scanner_severity"])
	}
}

// Contract Test 2: CanParse detection.
func TestCanParse(t *testing.T) {
	p := New()
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"nuclei_results.jsonl", "", true},
		{"nuclei.json", "", true},
		{"unknown.jsonl", `{"template-id":"test","info":{"name":"Test"},"matched-at":"https://x.com"}`, true},
		{"httpx.jsonl", "", false},
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

// Contract Test 3: Malformed input.
func TestParseMalformed(t *testing.T) {
	obs, err := New().Parse(context.Background(), domain.Artifact{FileName: "n.jsonl"}, strings.NewReader("{broken\n{bad"))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

// Contract Test 4: Empty input.
func TestParseEmpty(t *testing.T) {
	obs, err := New().Parse(context.Background(), domain.Artifact{FileName: "n.jsonl"}, strings.NewReader(""))
	if err != nil {
		t.Fatal("should not error")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

// Contract Test 5: Authority model — observations are NOT findings.
func TestAuthorityModel(t *testing.T) {
	p := New()

	// A nuclei critical match.
	input := `{"template-id":"cve-2024-99999","info":{"name":"Critical RCE","severity":"critical","description":"Remote code execution"},"type":"http","host":"https://target.com","matched-at":"https://target.com/vuln","timestamp":"2025-01-15T10:00:00Z"}`

	obs, err := p.Parse(context.Background(), domain.Artifact{FileName: "nuclei.jsonl"}, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatal("expected 1 observation")
	}

	o := obs[0]

	// Must be vulnerability_scan observation, not a Finding.
	if o.Type != domain.ObservationVulnerabilityScan {
		t.Errorf("expected vulnerability_scan, got %s — nuclei results are observations, not findings", o.Type)
	}

	// Must use scanner_severity, not severity.
	if o.Data["scanner_severity"] != "critical" {
		t.Error("expected scanner_severity=critical")
	}
	if _, has := o.Data["severity"]; has {
		t.Error("must not have 'severity' — that implies confirmation. Use 'scanner_severity'")
	}

	// Must be from nuclei source.
	if o.SourceTool != "nuclei" {
		t.Errorf("expected nuclei, got %s", o.SourceTool)
	}
}
