// Package report generates structured security reports from
// investigations, findings, and evidence.
//
// The report engine transforms a completed investigation into
// a professional, publishable security report in multiple formats.
//
// Report structure:
//
//	Executive Summary
//	Findings (each with full evidence chain)
//	Attack Surface Summary
//	Methodology
//	Timeline
//	Appendix
//
// Supported formats: JSON, Markdown.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Report is the complete generated security report.
type Report struct {
	// Metadata.
	ID          uuid.UUID `json:"id"`
	Title       string    `json:"title"`
	ProjectID   uuid.UUID `json:"project_id"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`

	// Executive summary.
	Executive ExecutiveSummary `json:"executive_summary"`

	// Findings, ordered by severity.
	Findings []FindingSection `json:"findings"`

	// Attack surface summary.
	AttackSurface AttackSurfaceSummary `json:"attack_surface"`

	// Methodology section.
	Methodology MethodologySection `json:"methodology"`

	// Timeline of key events.
	Timeline []TimelineEntry `json:"timeline"`
}

// ExecutiveSummary provides the high-level overview.
type ExecutiveSummary struct {
	Target        string        `json:"target"`
	Scope         []string      `json:"scope"`
	Duration      string        `json:"duration"`
	StartDate     time.Time     `json:"start_date"`
	EndDate       time.Time     `json:"end_date"`
	FindingCounts SeverityCounts `json:"finding_counts"`
	Summary       string        `json:"summary"`
}

// SeverityCounts tallies findings by severity.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// FindingSection is a single finding in the report.
type FindingSection struct {
	Title             string                  `json:"title"`
	Severity          domain.Severity         `json:"severity"`
	Category          domain.FindingCategory  `json:"category"`
	Description       string                  `json:"description"`
	ReproductionSteps []domain.ReproductionStep `json:"reproduction_steps"`
	Impact            domain.ImpactAssessment `json:"impact"`
	Remediation       string                  `json:"remediation"`
	EvidenceSummary   string                  `json:"evidence_summary"`
	ConfirmedBy       string                  `json:"confirmed_by"`
	ConfirmedAt       *time.Time              `json:"confirmed_at,omitempty"`
}

// AttackSurfaceSummary describes the discovered attack surface.
type AttackSurfaceSummary struct {
	DomainsDiscovered   int      `json:"domains_discovered"`
	EndpointsDiscovered int      `json:"endpoints_discovered"`
	ServicesDiscovered  int      `json:"services_discovered"`
	TechnologiesFound   int      `json:"technologies_found"`
	Domains             []string `json:"domains,omitempty"`
}

// MethodologySection describes the testing approach.
type MethodologySection struct {
	ToolsUsed              []string `json:"tools_used"`
	ObservationsCollected  int      `json:"observations_collected"`
	CorrelationsDiscovered int      `json:"correlations_discovered"`
	HypothesesTested       int      `json:"hypotheses_tested"`
	ValidationsExecuted    int      `json:"validations_executed"`
}

// TimelineEntry is a key event in the investigation.
type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Description string    `json:"description"`
}

// --- Report Input ---

// ReportInput is the data needed to generate a report.
type ReportInput struct {
	// Project information.
	ProjectName string
	ProjectID   uuid.UUID
	TargetScope []string

	// Investigation timeline.
	StartDate time.Time
	EndDate   time.Time

	// Confirmed findings.
	Findings []domain.Finding

	// Attack surface stats.
	DomainsDiscovered   int
	EndpointsDiscovered int
	ServicesDiscovered  int
	TechnologiesFound   int
	Domains             []string

	// Methodology stats.
	ToolsUsed              []string
	ObservationsCollected  int
	CorrelationsDiscovered int
	HypothesesTested       int
	ValidationsExecuted    int

	// Timeline events.
	Timeline []TimelineEntry

	// Who generated this report.
	GeneratedBy string
}

// --- Generator ---

// Generate creates a Report from input data.
func Generate(input ReportInput) (*Report, error) {
	if input.ProjectName == "" {
		return nil, fmt.Errorf("project name is required")
	}
	if len(input.Findings) == 0 {
		return nil, fmt.Errorf("at least one confirmed finding is required")
	}

	report := &Report{
		ID:          uuid.New(),
		Title:       fmt.Sprintf("Security Assessment: %s", input.ProjectName),
		ProjectID:   input.ProjectID,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: input.GeneratedBy,
	}

	// Executive summary.
	counts := countSeverities(input.Findings)
	report.Executive = ExecutiveSummary{
		Target:        input.ProjectName,
		Scope:         input.TargetScope,
		StartDate:     input.StartDate,
		EndDate:       input.EndDate,
		Duration:      input.EndDate.Sub(input.StartDate).Round(time.Hour).String(),
		FindingCounts: counts,
		Summary: fmt.Sprintf(
			"Security assessment of %s identified %d finding(s): %d Critical, %d High, %d Medium, %d Low, %d Informational.",
			input.ProjectName, len(input.Findings),
			counts.Critical, counts.High, counts.Medium, counts.Low, counts.Info),
	}

	// Findings (sorted by severity).
	report.Findings = buildFindingSections(input.Findings)

	// Attack surface.
	report.AttackSurface = AttackSurfaceSummary{
		DomainsDiscovered:   input.DomainsDiscovered,
		EndpointsDiscovered: input.EndpointsDiscovered,
		ServicesDiscovered:  input.ServicesDiscovered,
		TechnologiesFound:   input.TechnologiesFound,
		Domains:             input.Domains,
	}

	// Methodology.
	report.Methodology = MethodologySection{
		ToolsUsed:              input.ToolsUsed,
		ObservationsCollected:  input.ObservationsCollected,
		CorrelationsDiscovered: input.CorrelationsDiscovered,
		HypothesesTested:       input.HypothesesTested,
		ValidationsExecuted:    input.ValidationsExecuted,
	}

	// Timeline.
	report.Timeline = input.Timeline

	return report, nil
}

// countSeverities tallies findings by severity.
func countSeverities(findings []domain.Finding) SeverityCounts {
	var counts SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			counts.Critical++
		case domain.SeverityHigh:
			counts.High++
		case domain.SeverityMedium:
			counts.Medium++
		case domain.SeverityLow:
			counts.Low++
		case domain.SeverityInfo:
			counts.Info++
		}
	}
	return counts
}

// buildFindingSections creates report sections from findings.
func buildFindingSections(findings []domain.Finding) []FindingSection {
	// Sort by severity: critical > high > medium > low > info.
	severityOrder := map[domain.Severity]int{
		domain.SeverityCritical: 0,
		domain.SeverityHigh:     1,
		domain.SeverityMedium:   2,
		domain.SeverityLow:      3,
		domain.SeverityInfo:     4,
	}

	sorted := make([]domain.Finding, len(findings))
	copy(sorted, findings)

	// Simple insertion sort (findings are small).
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && severityOrder[sorted[j].Severity] < severityOrder[sorted[j-1].Severity]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	sections := make([]FindingSection, len(sorted))
	for i, f := range sorted {
		sections[i] = FindingSection{
			Title:             f.Title,
			Severity:          f.Severity,
			Category:          f.Category,
			Description:       f.Description,
			ReproductionSteps: f.ReproductionSteps,
			Impact:            f.Impact,
			Remediation:       f.Remediation,
			EvidenceSummary:   f.EvidenceChain.Summary,
			ConfirmedBy:       f.ConfirmedBy,
			ConfirmedAt:       f.ConfirmedAt,
		}
	}
	return sections
}

// --- Format Rendering ---

// RenderJSON outputs the report as formatted JSON.
func RenderJSON(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// RenderMarkdown outputs the report as Markdown.
func RenderMarkdown(report *Report) string {
	var b strings.Builder

	// Title.
	b.WriteString(fmt.Sprintf("# %s\n\n", report.Title))
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Generated by:** %s\n\n", report.GeneratedBy))
	b.WriteString("---\n\n")

	// Executive Summary.
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s  \n", report.Executive.Target))
	if len(report.Executive.Scope) > 0 {
		b.WriteString(fmt.Sprintf("**Scope:** %s  \n", strings.Join(report.Executive.Scope, ", ")))
	}
	b.WriteString(fmt.Sprintf("**Duration:** %s (%s to %s)  \n",
		report.Executive.Duration,
		report.Executive.StartDate.Format("2006-01-02"),
		report.Executive.EndDate.Format("2006-01-02")))
	b.WriteString("\n")

	// Severity table.
	c := report.Executive.FindingCounts
	b.WriteString("| Severity | Count |\n|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", c.Critical))
	b.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", c.High))
	b.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", c.Medium))
	b.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", c.Low))
	b.WriteString(fmt.Sprintf("| ⚪ Info | %d |\n", c.Info))
	b.WriteString("\n")

	b.WriteString(report.Executive.Summary + "\n\n")
	b.WriteString("---\n\n")

	// Findings.
	b.WriteString("## Findings\n\n")
	for i, f := range report.Findings {
		severityIcon := severityIcon(f.Severity)
		b.WriteString(fmt.Sprintf("### %d. %s %s [%s]\n\n",
			i+1, severityIcon, f.Title, strings.ToUpper(string(f.Severity))))
		b.WriteString(fmt.Sprintf("**Category:** %s  \n", f.Category))
		b.WriteString(fmt.Sprintf("**Confirmed by:** %s\n\n", f.ConfirmedBy))

		b.WriteString("#### Description\n\n")
		b.WriteString(f.Description + "\n\n")

		if len(f.ReproductionSteps) > 0 {
			b.WriteString("#### Reproduction Steps\n\n")
			for _, step := range f.ReproductionSteps {
				b.WriteString(fmt.Sprintf("%d. %s\n", step.Order, step.Description))
				if step.ExpectedResult != "" {
					b.WriteString(fmt.Sprintf("   - **Expected:** %s\n", step.ExpectedResult))
				}
				if step.ObservedResult != "" {
					b.WriteString(fmt.Sprintf("   - **Observed:** %s\n", step.ObservedResult))
				}
			}
			b.WriteString("\n")
		}

		if f.Impact.Description != "" {
			b.WriteString("#### Impact\n\n")
			b.WriteString(f.Impact.Description + "\n\n")
			if f.Impact.Confidentiality != "" || f.Impact.Integrity != "" || f.Impact.Availability != "" {
				b.WriteString(fmt.Sprintf("- Confidentiality: %s\n", f.Impact.Confidentiality))
				b.WriteString(fmt.Sprintf("- Integrity: %s\n", f.Impact.Integrity))
				b.WriteString(fmt.Sprintf("- Availability: %s\n\n", f.Impact.Availability))
			}
		}

		if f.Remediation != "" {
			b.WriteString("#### Remediation\n\n")
			b.WriteString(f.Remediation + "\n\n")
		}

		if f.EvidenceSummary != "" {
			b.WriteString("#### Evidence\n\n")
			b.WriteString(f.EvidenceSummary + "\n\n")
		}

		b.WriteString("---\n\n")
	}

	// Attack Surface.
	b.WriteString("## Attack Surface Summary\n\n")
	b.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Domains | %d |\n", report.AttackSurface.DomainsDiscovered))
	b.WriteString(fmt.Sprintf("| Endpoints | %d |\n", report.AttackSurface.EndpointsDiscovered))
	b.WriteString(fmt.Sprintf("| Services | %d |\n", report.AttackSurface.ServicesDiscovered))
	b.WriteString(fmt.Sprintf("| Technologies | %d |\n", report.AttackSurface.TechnologiesFound))
	b.WriteString("\n---\n\n")

	// Methodology.
	b.WriteString("## Methodology\n\n")
	if len(report.Methodology.ToolsUsed) > 0 {
		b.WriteString("**Tools:** " + strings.Join(report.Methodology.ToolsUsed, ", ") + "\n\n")
	}
	b.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Observations | %d |\n", report.Methodology.ObservationsCollected))
	b.WriteString(fmt.Sprintf("| Correlations | %d |\n", report.Methodology.CorrelationsDiscovered))
	b.WriteString(fmt.Sprintf("| Hypotheses tested | %d |\n", report.Methodology.HypothesesTested))
	b.WriteString(fmt.Sprintf("| Validations | %d |\n", report.Methodology.ValidationsExecuted))
	b.WriteString("\n---\n\n")

	// Timeline.
	if len(report.Timeline) > 0 {
		b.WriteString("## Timeline\n\n")
		b.WriteString("| Time | Event | Details |\n|------|-------|--------|\n")
		for _, e := range report.Timeline {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				e.Timestamp.Format("2006-01-02 15:04"), e.Event, e.Description))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func severityIcon(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return "🔴"
	case domain.SeverityHigh:
		return "🟠"
	case domain.SeverityMedium:
		return "🟡"
	case domain.SeverityLow:
		return "🔵"
	case domain.SeverityInfo:
		return "⚪"
	default:
		return "⚪"
	}
}
