package tui

import (
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/internal/orchestrator"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Epistemic Tag Tests ---

func TestRenderTagAllStages(t *testing.T) {
	tags := []EpistemicTag{
		TagObserved,
		TagCorrelated,
		TagNovel,
		TagOpportunity,
		TagHypothesis,
		TagAwaitingApproval,
		TagValidated,
		TagCandidate,
		TagAwaitingConfirm,
		TagConfirmedFinding,
	}

	for _, tag := range tags {
		result := RenderTag(tag)
		if result == "" {
			t.Errorf("tag %s rendered empty", tag)
		}
		// Should contain the tag text.
		if !strings.Contains(result, string(tag)) {
			t.Errorf("tag %s render should contain text, got %q", tag, result)
		}
	}
}

func TestRenderTagDistinctStyles(t *testing.T) {
	// Approval and confirmation tags should be visually distinct.
	approval := RenderTag(TagAwaitingApproval)
	confirm := RenderTag(TagAwaitingConfirm)
	finding := RenderTag(TagConfirmedFinding)

	if approval == confirm {
		t.Error("approval and confirmation tags should be visually different")
	}
	if approval == finding {
		t.Error("approval and finding tags should be visually different")
	}
}

// --- Pipeline Dashboard Tests ---

func TestRenderPipelineDashboardWithState(t *testing.T) {
	state := &orchestrator.InvestigationState{
		ObservationsProcessed: 150,
		CorrelationsFound:     12,
		NoveltySignals:        5,
		OpportunitiesCreated:  3,
		HypothesesGenerated:   4,
		ValidationsExecuted:   2,
		CandidatesCreated:     1,
		FindingsConfirmed:     1,
	}

	view := PipelineView{
		State:                state,
		PendingApprovals:     2,
		PendingConfirmations: 1,
	}

	result := RenderPipelineDashboard(view, 60, 30)

	checks := []string{
		"Pipeline Status",
		"Observations",
		"Correlations",
		"Novelty",
		"Opportunities",
		"Hypotheses",
		"Validations",
		"Candidates",
		"Findings",
		"Human Gates",
		"Approval Queue",
		"Confirmation Queue",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("dashboard should contain %q", check)
		}
	}
}

func TestRenderPipelineDashboardEmptyQueues(t *testing.T) {
	view := PipelineView{
		PendingApprovals:     0,
		PendingConfirmations: 0,
	}

	result := RenderPipelineDashboard(view, 60, 20)
	if !strings.Contains(result, "empty") {
		t.Error("empty queues should show 'empty'")
	}
}

// --- Approval Queue Tests ---

func TestRenderApprovalQueueWithItems(t *testing.T) {
	items := []ApprovalItem{
		{
			HypothesisID: "abc-123",
			Title:        "Validate authorization boundary",
			Target:       "admin.example.com",
			RequestCount: 4,
			RiskLevel:    "low",
			EvidenceKeys: []string{"subfinder", "httpx", "correlation"},
		},
	}

	result := RenderApprovalQueue(items, 60, 20)

	checks := []string{
		"Approval Queue",
		"Validate authorization boundary",
		"admin.example.com",
		"[A] Approve",
		"[D] Deny",
		"[V] View Details",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("approval queue should contain %q", check)
		}
	}
}

func TestRenderApprovalQueueEmpty(t *testing.T) {
	result := RenderApprovalQueue(nil, 60, 20)
	if !strings.Contains(result, "No validation plans") {
		t.Error("empty approval queue should indicate no plans")
	}
}

// --- Candidate Queue Tests ---

func TestRenderCandidateQueueWithItems(t *testing.T) {
	items := []CandidateItem{
		{
			CandidateID:       "def-456",
			Title:             "Unauthorized File Upload",
			SuggestedSeverity: domain.SeverityHigh,
			SuggestedCategory: domain.FindingCatFileUpload,
			Rationale:         "Hypothesis supported by validation results",
			EvidenceCount:     5,
		},
	}

	result := RenderCandidateQueue(items, 60, 20)

	checks := []string{
		"Finding Candidates",
		"Unauthorized File Upload",
		"HIGH",
		"[C] Confirm",
		"[R] Reject",
		"[M] Need More Evidence",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("candidate queue should contain %q", check)
		}
	}
}

func TestRenderCandidateQueueEmpty(t *testing.T) {
	result := RenderCandidateQueue(nil, 60, 20)
	if !strings.Contains(result, "No candidates") {
		t.Error("empty candidate queue should indicate no candidates")
	}
}

// --- Full Dashboard Tests ---

func TestRenderFullDashboard(t *testing.T) {
	data := DashboardData{
		InvestigationTitle:  "example.com",
		InvestigationStatus: "RUNNING",
		Domains:             12,
		Endpoints:           847,
		Services:            23,
		Technologies:        15,
		Pipeline: PipelineView{
			State: &orchestrator.InvestigationState{
				ObservationsProcessed: 100,
				CorrelationsFound:     10,
			},
		},
	}

	result := RenderFullDashboard(data, 80, 40)

	if !strings.Contains(result, "DOGE v0.9.9") {
		t.Error("dashboard should show version")
	}
	if !strings.Contains(result, "example.com") {
		t.Error("dashboard should show investigation title")
	}
}

// --- Findings List ---

func TestRenderFindingsListBySeverity(t *testing.T) {
	findings := []FindingSummary{
		{Title: "Critical Bug", Severity: domain.SeverityCritical},
		{Title: "Info Item", Severity: domain.SeverityInfo},
	}

	view := PipelineView{
		ConfirmedFindings: findings,
	}

	result := RenderPipelineDashboard(view, 60, 30)
	if !strings.Contains(result, "Confirmed Findings") {
		t.Error("should show confirmed findings section")
	}
	if !strings.Contains(result, "Critical Bug") {
		t.Error("should show finding title")
	}
	if !strings.Contains(result, "CRITICAL") {
		t.Error("should show severity label")
	}
}
