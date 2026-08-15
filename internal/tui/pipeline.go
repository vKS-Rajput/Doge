package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/vKS-Rajput/doge/internal/orchestrator"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Epistemic Status Rendering ---

// EpistemicTag represents a stage in the investigation lifecycle.
// The TUI makes the epistemic state visible so users never confuse
// "interesting" with "confirmed."
type EpistemicTag string

const (
	TagObserved           EpistemicTag = "OBSERVED"
	TagCorrelated         EpistemicTag = "CORRELATED"
	TagNovel              EpistemicTag = "NOVEL"
	TagOpportunity        EpistemicTag = "OPPORTUNITY"
	TagHypothesis         EpistemicTag = "HYPOTHESIS"
	TagAwaitingApproval   EpistemicTag = "AWAITING APPROVAL"
	TagValidated          EpistemicTag = "VALIDATED"
	TagCandidate          EpistemicTag = "CANDIDATE"
	TagAwaitingConfirm    EpistemicTag = "AWAITING CONFIRMATION"
	TagConfirmedFinding   EpistemicTag = "CONFIRMED FINDING"
)

// RenderTag renders an epistemic tag with appropriate styling.
func RenderTag(tag EpistemicTag) string {
	switch tag {
	case TagObserved:
		return DimText.Render("[OBSERVED]")
	case TagCorrelated:
		return InfoText.Render("[CORRELATED]")
	case TagNovel:
		return MediumText.Render("[NOVEL]")
	case TagOpportunity:
		return AccentText.Render("[OPPORTUNITY]")
	case TagHypothesis:
		return AccentText.Render("[HYPOTHESIS]")
	case TagAwaitingApproval:
		return WarningText.Render("[⏳ AWAITING APPROVAL]")
	case TagValidated:
		return InfoText.Render("[VALIDATED]")
	case TagCandidate:
		return HighText.Render("[CANDIDATE]")
	case TagAwaitingConfirm:
		return WarningText.Render("[⏳ AWAITING CONFIRMATION]")
	case TagConfirmedFinding:
		return CriticalText.Render("[✅ CONFIRMED FINDING]")
	default:
		return DimText.Render(fmt.Sprintf("[%s]", tag))
	}
}

// --- Pipeline Dashboard ---

// PipelineView renders the full investigation pipeline status.
type PipelineView struct {
	State *orchestrator.InvestigationState
	Stats orchestrator.PipelineStats

	// Queues.
	PendingApprovals     int
	PendingConfirmations int
	ActiveValidations    int

	// Findings.
	ConfirmedFindings []FindingSummary
}

// FindingSummary is a minimal finding for TUI display.
type FindingSummary struct {
	Title       string
	Severity    domain.Severity
	Category    domain.FindingCategory
	ConfirmedBy string
}

// RenderPipelineDashboard renders the full pipeline view.
func RenderPipelineDashboard(v PipelineView, w, h int) string {
	var sections []string

	// Header.
	sections = append(sections, HeaderStyle.Render("🐕 DOGE Investigation Pipeline"))
	sections = append(sections, "")

	// Pipeline stage counters.
	if v.State != nil {
		sections = append(sections, renderPipelineCounters(v.State))
		sections = append(sections, "")
	}

	// Human gates (the most important display).
	sections = append(sections, renderHumanGates(v.PendingApprovals, v.PendingConfirmations))
	sections = append(sections, "")

	// Findings.
	if len(v.ConfirmedFindings) > 0 {
		sections = append(sections, renderFindingsList(v.ConfirmedFindings, h/3))
	}

	return strings.Join(sections, "\n")
}

func renderPipelineCounters(state *orchestrator.InvestigationState) string {
	var lines []string

	lines = append(lines, BrightText.Render("Pipeline Status"))
	lines = append(lines, "")

	// Each stage with its count.
	stages := []struct {
		icon  string
		label string
		count int
		tag   EpistemicTag
	}{
		{"📡", "Observations", state.ObservationsProcessed, TagObserved},
		{"🔗", "Correlations", state.CorrelationsFound, TagCorrelated},
		{"🧬", "Novelty Signals", state.NoveltySignals, TagNovel},
		{"🎯", "Opportunities", state.OpportunitiesCreated, TagOpportunity},
		{"🧠", "Hypotheses", state.HypothesesGenerated, TagHypothesis},
		{"🧪", "Validations", state.ValidationsExecuted, TagValidated},
		{"📋", "Candidates", state.CandidatesCreated, TagCandidate},
		{"✅", "Findings", state.FindingsConfirmed, TagConfirmedFinding},
	}

	for _, s := range stages {
		countStr := AccentText.Render(fmt.Sprintf("%d", s.count))
		line := fmt.Sprintf("  %s %-18s %s", s.icon, s.label, countStr)
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func renderHumanGates(approvals, confirmations int) string {
	var lines []string

	lines = append(lines, BrightText.Render("Human Gates"))
	lines = append(lines, "")

	// Approval queue.
	if approvals > 0 {
		badge := WarningText.Render(fmt.Sprintf(" 🔴 %d ", approvals))
		lines = append(lines, fmt.Sprintf("  Approval Queue     %s", badge))
	} else {
		lines = append(lines, fmt.Sprintf("  Approval Queue     %s", DimText.Render("empty")))
	}

	// Confirmation queue.
	if confirmations > 0 {
		badge := HighText.Render(fmt.Sprintf(" 🔴 %d ", confirmations))
		lines = append(lines, fmt.Sprintf("  Confirmation Queue %s", badge))
	} else {
		lines = append(lines, fmt.Sprintf("  Confirmation Queue %s", DimText.Render("empty")))
	}

	return strings.Join(lines, "\n")
}

func renderFindingsList(findings []FindingSummary, maxLines int) string {
	var lines []string

	lines = append(lines, BrightText.Render("Confirmed Findings"))
	lines = append(lines, "")

	shown := len(findings)
	if shown > maxLines {
		shown = maxLines
	}

	for i := 0; i < shown; i++ {
		f := findings[i]
		icon := severityTUIIcon(f.Severity)
		sev := strings.ToUpper(string(f.Severity))
		lines = append(lines, fmt.Sprintf("  %s [%s] %s", icon, sev, f.Title))
	}

	if len(findings) > shown {
		lines = append(lines, DimText.Render(fmt.Sprintf("  ... and %d more", len(findings)-shown)))
	}

	return strings.Join(lines, "\n")
}

func severityTUIIcon(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return CriticalText.Render("🔴")
	case domain.SeverityHigh:
		return HighText.Render("🟠")
	case domain.SeverityMedium:
		return MediumText.Render("🟡")
	case domain.SeverityLow:
		return LowText.Render("🔵")
	default:
		return DimText.Render("⚪")
	}
}

// --- Approval Queue View ---

// ApprovalItem represents a hypothesis awaiting human approval.
type ApprovalItem struct {
	HypothesisID string
	Title        string
	Target       string
	RequestCount int
	RiskLevel    string
	EvidenceKeys []string
}

// RenderApprovalQueue renders the approval queue view.
func RenderApprovalQueue(items []ApprovalItem, w, h int) string {
	var lines []string

	lines = append(lines, HeaderStyle.Render("🔐 Approval Queue"))
	lines = append(lines, "")

	if len(items) == 0 {
		lines = append(lines, DimText.Render("  No validation plans awaiting approval."))
		return strings.Join(lines, "\n")
	}

	maxItems := h - 4
	if maxItems < 1 {
		maxItems = 1
	}

	for i, item := range items {
		if i >= maxItems {
			lines = append(lines, DimText.Render(
				fmt.Sprintf("  ... and %d more", len(items)-i)))
			break
		}

		// Item header.
		idx := AccentText.Render(fmt.Sprintf("[%d]", i+1))
		title := BrightText.Render(item.Title)
		lines = append(lines, fmt.Sprintf("  %s %s", idx, title))

		// Details.
		lines = append(lines, DimText.Render(
			fmt.Sprintf("      Target: %s  Requests: %d  Risk: %s",
				item.Target, item.RequestCount, item.RiskLevel)))

		// Evidence.
		if len(item.EvidenceKeys) > 0 {
			lines = append(lines, DimText.Render(
				fmt.Sprintf("      Evidence: %s", strings.Join(item.EvidenceKeys, ", "))))
		}

		// Actions.
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("      %s  %s  %s",
			SuccessText.Render("[A] Approve"),
			ErrorText.Render("[D] Deny"),
			InfoText.Render("[V] View Details")))
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// --- Candidate Review View ---

// CandidateItem represents a finding candidate awaiting confirmation.
type CandidateItem struct {
	CandidateID       string
	Title             string
	SuggestedSeverity domain.Severity
	SuggestedCategory domain.FindingCategory
	Rationale         string
	EvidenceCount     int
}

// RenderCandidateQueue renders the candidate confirmation queue.
func RenderCandidateQueue(items []CandidateItem, w, h int) string {
	var lines []string

	lines = append(lines, HeaderStyle.Render("📋 Finding Candidates"))
	lines = append(lines, "")

	if len(items) == 0 {
		lines = append(lines, DimText.Render("  No candidates awaiting confirmation."))
		return strings.Join(lines, "\n")
	}

	maxItems := h - 4
	if maxItems < 1 {
		maxItems = 1
	}

	for i, item := range items {
		if i >= maxItems {
			lines = append(lines, DimText.Render(
				fmt.Sprintf("  ... and %d more", len(items)-i)))
			break
		}

		icon := severityTUIIcon(item.SuggestedSeverity)
		idx := AccentText.Render(fmt.Sprintf("[%d]", i+1))
		title := BrightText.Render(item.Title)
		sev := strings.ToUpper(string(item.SuggestedSeverity))

		lines = append(lines, fmt.Sprintf("  %s %s %s [%s]", idx, icon, title, sev))
		lines = append(lines, DimText.Render(
			fmt.Sprintf("      Category: %s  Evidence: %d items",
				item.SuggestedCategory, item.EvidenceCount)))

		if item.Rationale != "" {
			rationale := item.Rationale
			if len(rationale) > 60 {
				rationale = rationale[:57] + "..."
			}
			lines = append(lines, DimText.Render(
				fmt.Sprintf("      Rationale: %s", rationale)))
		}

		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("      %s  %s  %s  %s",
			SuccessText.Render("[C] Confirm"),
			ErrorText.Render("[R] Reject"),
			WarningText.Render("[M] Need More Evidence"),
			InfoText.Render("[V] View Details")))
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// --- Full Dashboard Render ---

// DashboardData holds all data for the full TUI dashboard.
type DashboardData struct {
	// Investigation.
	InvestigationTitle  string
	InvestigationStatus string

	// Attack surface.
	Domains      int
	Endpoints    int
	Services     int
	Technologies int

	// Pipeline.
	Pipeline PipelineView

	// Queues.
	Approvals  []ApprovalItem
	Candidates []CandidateItem
}

// RenderFullDashboard renders the complete v0.9.9 dashboard.
func RenderFullDashboard(data DashboardData, w, h int) string {
	// Title bar.
	status := SuccessText.Render(data.InvestigationStatus)
	title := TitleBarStyle.Width(w).Render(
		fmt.Sprintf("🐕 DOGE v0.9.9  │  %s  │  %s",
			data.InvestigationTitle, status))

	// Calculate column widths.
	leftW := w / 2
	rightW := w - leftW - 2
	paneH := (h - 6) / 2

	// Left column: pipeline + findings.
	pipeline := RenderPipelineDashboard(data.Pipeline, leftW, paneH)
	leftPane := PaneStyle.Width(leftW).Height(paneH*2).
		Render(pipeline)

	// Right column: approval queue + candidates.
	var rightContent string
	if len(data.Approvals) > 0 {
		rightContent = RenderApprovalQueue(data.Approvals, rightW, paneH)
	} else if len(data.Candidates) > 0 {
		rightContent = RenderCandidateQueue(data.Candidates, rightW, paneH)
	} else {
		rightContent = renderAttackSurface(data, rightW, paneH)
	}
	rightPane := PaneStyle.Width(rightW).Height(paneH*2).
		Render(rightContent)

	// Join.
	body := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)

	// Status bar.
	approvalBadge := ""
	if len(data.Approvals) > 0 {
		approvalBadge = WarningText.Render(fmt.Sprintf(" 🔴 %d approvals pending ", len(data.Approvals)))
	}
	candidateBadge := ""
	if len(data.Candidates) > 0 {
		candidateBadge = HighText.Render(fmt.Sprintf(" 🟠 %d candidates pending ", len(data.Candidates)))
	}

	statusBar := StatusBarStyle.Width(w).Render(
		fmt.Sprintf(" Tab: navigate │ A/D: approve/deny │ C/R: confirm/reject │ ?: help  %s%s",
			approvalBadge, candidateBadge))

	return lipgloss.JoinVertical(lipgloss.Left, title, body, statusBar)
}

func renderAttackSurface(data DashboardData, w, h int) string {
	var lines []string

	lines = append(lines, HeaderStyle.Render("🗺️ Attack Surface"))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  Domains        %s", AccentText.Render(fmt.Sprintf("%d", data.Domains))))
	lines = append(lines, fmt.Sprintf("  Endpoints      %s", AccentText.Render(fmt.Sprintf("%d", data.Endpoints))))
	lines = append(lines, fmt.Sprintf("  Services       %s", AccentText.Render(fmt.Sprintf("%d", data.Services))))
	lines = append(lines, fmt.Sprintf("  Technologies   %s", AccentText.Render(fmt.Sprintf("%d", data.Technologies))))
	lines = append(lines, "")

	// Novelty summary.
	if data.Pipeline.State != nil {
		lines = append(lines, HeaderStyle.Render("🧬 Novelty"))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  Signals        %s",
			AccentText.Render(fmt.Sprintf("%d", data.Pipeline.State.NoveltySignals))))
		lines = append(lines, fmt.Sprintf("  Opportunities  %s",
			AccentText.Render(fmt.Sprintf("%d", data.Pipeline.State.OpportunitiesCreated))))
	}

	return strings.Join(lines, "\n")
}
