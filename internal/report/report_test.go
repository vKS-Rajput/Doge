package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func makeTestInput() ReportInput {
	now := time.Now().UTC()
	return ReportInput{
		ProjectName: "example.com",
		ProjectID:   uuid.New(),
		TargetScope: []string{"example.com", "*.example.com"},
		StartDate:   now.Add(-72 * time.Hour),
		EndDate:     now,
		Findings: []domain.Finding{
			{
				Title:       "Unauthorized File Upload",
				Severity:    domain.SeverityHigh,
				Category:    domain.FindingCatFileUpload,
				Description: "The /admin/upload endpoint allows unauthenticated file upload.",
				ReproductionSteps: []domain.ReproductionStep{
					{Order: 1, Description: "Access /admin/upload", ExpectedResult: "403", ObservedResult: "200"},
					{Order: 2, Description: "Attempt file upload", ExpectedResult: "denied", ObservedResult: "accepted"},
				},
				Impact: domain.ImpactAssessment{
					Confidentiality: "low",
					Integrity:       "high",
					Availability:    "low",
					Description:     "Arbitrary file upload allows attacker to place files.",
				},
				Remediation: "Implement authentication and authorization on upload endpoint.",
				EvidenceChain: domain.EvidenceChain{
					Summary: "Discovered via subfinder, validated via bounded HTTP.",
				},
				ConfirmedBy: "researcher@example.com",
				ConfirmedAt: &now,
			},
			{
				Title:       "Missing Security Headers",
				Severity:    domain.SeverityInfo,
				Category:    domain.FindingCatMisconfiguration,
				Description: "Several security headers are missing.",
				ReproductionSteps: []domain.ReproductionStep{
					{Order: 1, Description: "Check response headers"},
				},
				Remediation: "Add security headers.",
				EvidenceChain: domain.EvidenceChain{
					Summary: "Observed via httpx header analysis.",
				},
				ConfirmedBy: "researcher@example.com",
				ConfirmedAt: &now,
			},
		},
		DomainsDiscovered:   12,
		EndpointsDiscovered: 847,
		ServicesDiscovered:  23,
		TechnologiesFound:   15,
		ToolsUsed:           []string{"subfinder", "httpx", "nmap", "ffuf", "katana"},
		ObservationsCollected:  1250,
		CorrelationsDiscovered: 42,
		HypothesesTested:       8,
		ValidationsExecuted:    15,
		Timeline: []TimelineEntry{
			{Timestamp: now.Add(-72 * time.Hour), Event: "Assessment started", Description: "Initial scope review"},
			{Timestamp: now.Add(-48 * time.Hour), Event: "Discovery completed", Description: "12 domains, 847 endpoints"},
			{Timestamp: now, Event: "Assessment completed", Description: "2 findings confirmed"},
		},
		GeneratedBy: "researcher@example.com",
	}
}

func TestGenerateReport(t *testing.T) {
	input := makeTestInput()
	report, err := Generate(input)
	if err != nil {
		t.Fatalf("generate should succeed: %v", err)
	}

	if report.Title != "Security Assessment: example.com" {
		t.Errorf("unexpected title: %s", report.Title)
	}
	if report.Executive.FindingCounts.High != 1 {
		t.Errorf("expected 1 high finding, got %d", report.Executive.FindingCounts.High)
	}
	if report.Executive.FindingCounts.Info != 1 {
		t.Errorf("expected 1 info finding, got %d", report.Executive.FindingCounts.Info)
	}
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(report.Findings))
	}
}

func TestGenerateRequiresProjectName(t *testing.T) {
	input := makeTestInput()
	input.ProjectName = ""
	_, err := Generate(input)
	if err == nil {
		t.Error("should require project name")
	}
}

func TestGenerateRequiresFindings(t *testing.T) {
	input := makeTestInput()
	input.Findings = nil
	_, err := Generate(input)
	if err == nil {
		t.Error("should require at least one finding")
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	input := makeTestInput()
	// Add a critical finding.
	now := time.Now()
	input.Findings = append(input.Findings, domain.Finding{
		Title:       "Critical Issue",
		Severity:    domain.SeverityCritical,
		Category:    domain.FindingCatAuthorization,
		ConfirmedBy: "researcher",
		ConfirmedAt: &now,
		EvidenceChain: domain.EvidenceChain{
			Summary: "Critical evidence chain.",
		},
	})

	report, err := Generate(input)
	if err != nil {
		t.Fatalf("generate should succeed: %v", err)
	}

	// Critical should be first.
	if report.Findings[0].Severity != domain.SeverityCritical {
		t.Errorf("first finding should be critical, got %s", report.Findings[0].Severity)
	}
	// Info should be last.
	if report.Findings[len(report.Findings)-1].Severity != domain.SeverityInfo {
		t.Errorf("last finding should be info, got %s",
			report.Findings[len(report.Findings)-1].Severity)
	}
}

func TestRenderJSON(t *testing.T) {
	input := makeTestInput()
	report, _ := Generate(input)

	data, err := RenderJSON(report)
	if err != nil {
		t.Fatalf("JSON render should succeed: %v", err)
	}

	// Verify it's valid JSON.
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON should be valid: %v", err)
	}
	if parsed.Title != report.Title {
		t.Error("parsed title should match")
	}
}

func TestRenderMarkdown(t *testing.T) {
	input := makeTestInput()
	report, _ := Generate(input)

	md := RenderMarkdown(report)

	// Verify key sections exist.
	checks := []string{
		"# Security Assessment: example.com",
		"## Executive Summary",
		"## Findings",
		"Unauthorized File Upload",
		"🟠",
		"## Attack Surface Summary",
		"## Methodology",
		"## Timeline",
		"researcher@example.com",
		"subfinder",
	}

	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown should contain %q", check)
		}
	}
}

func TestRenderMarkdownReproductionSteps(t *testing.T) {
	input := makeTestInput()
	report, _ := Generate(input)
	md := RenderMarkdown(report)

	if !strings.Contains(md, "Reproduction Steps") {
		t.Error("markdown should contain reproduction steps section")
	}
	if !strings.Contains(md, "**Expected:**") {
		t.Error("markdown should contain expected results")
	}
	if !strings.Contains(md, "**Observed:**") {
		t.Error("markdown should contain observed results")
	}
}

func TestSeverityIcons(t *testing.T) {
	tests := []struct {
		severity domain.Severity
		icon     string
	}{
		{domain.SeverityCritical, "🔴"},
		{domain.SeverityHigh, "🟠"},
		{domain.SeverityMedium, "🟡"},
		{domain.SeverityLow, "🔵"},
		{domain.SeverityInfo, "⚪"},
	}

	for _, tt := range tests {
		icon := severityIcon(tt.severity)
		if icon != tt.icon {
			t.Errorf("severity %s: expected icon %s, got %s", tt.severity, tt.icon, icon)
		}
	}
}

func TestSeverityCounts(t *testing.T) {
	findings := []domain.Finding{
		{Severity: domain.SeverityCritical},
		{Severity: domain.SeverityHigh},
		{Severity: domain.SeverityHigh},
		{Severity: domain.SeverityMedium},
		{Severity: domain.SeverityLow},
		{Severity: domain.SeverityInfo},
		{Severity: domain.SeverityInfo},
		{Severity: domain.SeverityInfo},
	}

	counts := countSeverities(findings)
	if counts.Critical != 1 || counts.High != 2 || counts.Medium != 1 ||
		counts.Low != 1 || counts.Info != 3 {
		t.Errorf("unexpected counts: %+v", counts)
	}
}

func TestExecutiveSummaryText(t *testing.T) {
	input := makeTestInput()
	report, _ := Generate(input)

	if !strings.Contains(report.Executive.Summary, "2 finding") {
		t.Error("summary should mention finding count")
	}
	if !strings.Contains(report.Executive.Summary, "example.com") {
		t.Error("summary should mention target")
	}
}
