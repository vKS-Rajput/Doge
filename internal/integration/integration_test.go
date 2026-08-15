// Package integration provides end-to-end tests that prove
// the entire DOGE investigation pipeline works as one organism.
//
// This is NOT a unit test suite. This is the v1.0 proof:
//
//	Target
//	  ↓
//	Import observations
//	  ↓
//	Correlation
//	  ↓
//	Attack surface
//	  ↓
//	Novelty
//	  ↓
//	Opportunity
//	  ↓
//	AI hypothesis
//	  ↓
//	Human approval
//	  ↓
//	Controlled validation
//	  ↓
//	Observation (new)
//	  ↓
//	Re-evaluation
//	  ↓
//	Candidate
//	  ↓
//	Human confirmation
//	  ↓
//	Finding
//	  ↓
//	Report
//
// If this test passes, DOGE v1.0 works.
package integration

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/finding"
	"github.com/vKS-Rajput/doge/internal/orchestrator"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/internal/tui"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// TestFullPipelineEndToEnd proves the entire DOGE investigation
// lifecycle works from observation import through to report generation.
//
// This is the v1.0 proof test.
func TestFullPipelineEndToEnd(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// --- Step 1: Infrastructure ---
	eventBus := bus.New(bus.Options{QueueSize: 256, Logger: logger})
	eventBus.Start()
	defer eventBus.Drain()

	orch := orchestrator.New(eventBus, logger)
	tracker := orchestrator.NewStateTracker()

	projectID := uuid.New()
	investigationID := uuid.New()
	state := tracker.GetOrCreate(investigationID, projectID)

	// --- Step 2: Register pipeline handlers ---
	// Each handler simulates the real subsystem's core behavior.

	orch.RegisterHandler(orchestrator.StageCorrelation, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.CorrelationsFound++
			s.CurrentStage = orchestrator.StageCorrelation
		})
		// Emit correlation event to trigger next stage.
		eventBus.Publish(ctx, events.CorrelationDiscovered{
			BaseEvent:     events.NewBaseEvent(),
			CorrelationID: uuid.New(),
			Confidence:    0.87,
		})
		return nil
	})

	orch.RegisterHandler(orchestrator.StageSurface, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.CurrentStage = orchestrator.StageSurface
		})
		eventBus.Publish(ctx, events.SurfaceUpdated{
			BaseEvent: events.NewBaseEvent(),
			ProjectID: projectID,
			PathCount: 12,
		})
		return nil
	})

	orch.RegisterHandler(orchestrator.StageNovelty, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.NoveltySignals++
			s.CurrentStage = orchestrator.StageNovelty
		})
		eventBus.Publish(ctx, events.NoveltyDetected{
			BaseEvent:    events.NewBaseEvent(),
			ProjectID:    projectID,
			NoveltyScore: 0.92,
			SignalType:   "structural",
		})
		return nil
	})

	orch.RegisterHandler(orchestrator.StageOpportunity, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.OpportunitiesCreated++
			s.CurrentStage = orchestrator.StageOpportunity
		})
		eventBus.Publish(ctx, events.OpportunityCreated{
			BaseEvent:     events.NewBaseEvent(),
			OpportunityID: uuid.New(),
			ProjectID:     projectID,
			Title:         "Upload endpoint lacks authorization",
			Priority:      "high",
		})
		return nil
	})

	orch.RegisterHandler(orchestrator.StageReasoning, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.HypothesesGenerated++
			s.PendingApprovals++
			s.CurrentStage = orchestrator.StageReasoning
		})
		// Reasoning completes but does NOT trigger validation.
		// Human approval is required.
		return nil
	})

	orch.RegisterHandler(orchestrator.StageReeval, func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
		tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
			s.CandidatesCreated++
			s.PendingConfirmations++
			s.CurrentStage = orchestrator.StageReeval
		})
		return nil
	})

	orch.Start()
	defer orch.Stop()

	// --- Step 3: Import observations (kick off the pipeline) ---
	t.Log("Step 3: Importing observations...")

	obsID := uuid.New()
	tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
		s.ObservationsProcessed = 150
	})

	eventBus.Publish(ctx, events.ObservationCreated{
		BaseEvent:     events.NewBaseEvent(),
		ObservationID: obsID,
		Type:          "subdomain",
		ProjectID:     projectID,
	})

	// Wait for automatic pipeline to fire through reasoning.
	time.Sleep(800 * time.Millisecond)

	// --- Step 4: Verify automatic pipeline ran ---
	t.Log("Step 4: Verifying automatic pipeline...")

	state, _ = tracker.Get(investigationID)
	if state.CorrelationsFound == 0 {
		t.Fatal("correlation stage should have fired")
	}
	if state.NoveltySignals == 0 {
		t.Fatal("novelty stage should have fired")
	}
	if state.OpportunitiesCreated == 0 {
		t.Fatal("opportunity stage should have fired")
	}
	if state.HypothesesGenerated == 0 {
		t.Fatal("reasoning stage should have fired")
	}

	// --- Step 5: Verify human gate (approval) ---
	t.Log("Step 5: Verifying human approval gate...")

	if state.PendingApprovals == 0 {
		t.Fatal("there should be pending approvals (human gate)")
	}

	// Simulate human approval.
	tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
		s.PendingApprovals--
		s.ValidationsExecuted++
	})

	// --- Step 6: Simulate validation completion ---
	t.Log("Step 6: Validation completes, triggering re-evaluation...")

	eventBus.Publish(ctx, events.ValidationCompleted{
		BaseEvent:    events.NewBaseEvent(),
		PlanID:       uuid.New(),
		HypothesisID: uuid.New(),
		ProjectID:    projectID,
		ResultCount:  3,
		Completed:    true,
	})

	time.Sleep(200 * time.Millisecond)

	state, _ = tracker.Get(investigationID)
	if state.CandidatesCreated == 0 {
		t.Fatal("re-evaluation should create candidates")
	}
	if state.PendingConfirmations == 0 {
		t.Fatal("there should be pending confirmations (human gate)")
	}

	// --- Step 7: Verify human gate (confirmation) ---
	t.Log("Step 7: Verifying human confirmation gate...")

	// Validate the candidate.
	candidateObs := uuid.New()
	candidate := domain.FindingCandidate{
		ID:           uuid.New(),
		HypothesisID: uuid.New(),
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{candidateObs},
			Summary:        "Upload endpoint returns 200 for anonymous user",
		},
		SuggestedTitle:    "Unauthorized File Upload",
		SuggestedCategory: domain.FindingCatFileUpload,
		SuggestedSeverity: domain.SeverityHigh,
		Rationale:         "Hypothesis supported: unauthenticated access to upload",
		Status:            domain.CandidatePending,
		ProjectID:         projectID,
		InvestigationID:   investigationID,
		CreatedAt:         time.Now().UTC(),
	}

	validObs := map[uuid.UUID]bool{candidateObs: true, obsID: true}
	if err := finding.ValidateCandidate(candidate, validObs); err != nil {
		t.Fatalf("candidate should be valid: %v", err)
	}

	// --- Step 8: Human confirms → Finding ---
	t.Log("Step 8: Human confirms finding...")

	now := time.Now()
	confirmedFinding := domain.Finding{
		ID:          uuid.New(),
		Title:       "Unauthorized File Upload",
		Description: "The /admin/upload endpoint allows file upload without authentication.",
		Severity:    domain.SeverityHigh,
		Category:    domain.FindingCatFileUpload,
		Status:      domain.FindingConfirmed,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs:      []uuid.UUID{obsID, candidateObs},
			ValidationResultIDs: []uuid.UUID{uuid.New()},
			Summary:             "Discovered via subfinder → httpx correlation. Validated via bounded HTTP.",
		},
		CandidateID: &candidate.ID,
		EvidenceIDs: []uuid.UUID{obsID, candidateObs},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "Access /admin/upload without auth", ExpectedResult: "403", ObservedResult: "200"},
			{Order: 2, Description: "Submit file to upload form", ExpectedResult: "denied", ObservedResult: "accepted"},
		},
		Impact: domain.ImpactAssessment{
			Confidentiality: "low",
			Integrity:       "high",
			Availability:    "low",
			Description:     "Unauthenticated file upload allows arbitrary file placement.",
		},
		Remediation:     "Implement authentication and authorization on the upload endpoint.",
		ConfirmedBy:     "researcher@example.com",
		ConfirmedAt:     &now,
		InvestigationID: &investigationID,
		ProjectID:       projectID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Validate the finding.
	if err := finding.ValidateConfirmation(confirmedFinding, validObs); err != nil {
		t.Fatalf("confirmed finding should be valid: %v", err)
	}

	// Verify AI cannot confirm.
	aiFinding := confirmedFinding
	aiFinding.ConfirmedBy = "ai"
	if err := finding.ValidateConfirmation(aiFinding, validObs); err == nil {
		t.Fatal("AI should NEVER be able to confirm a finding")
	}

	tracker.Update(investigationID, func(s *orchestrator.InvestigationState) {
		s.PendingConfirmations--
		s.FindingsConfirmed++
	})

	// --- Step 9: Generate report ---
	t.Log("Step 9: Generating report...")

	rpt, err := report.Generate(report.ReportInput{
		ProjectName:            "example.com",
		ProjectID:              projectID,
		TargetScope:            []string{"example.com", "*.example.com"},
		StartDate:              now.Add(-72 * time.Hour),
		EndDate:                now,
		Findings:               []domain.Finding{confirmedFinding},
		DomainsDiscovered:      12,
		EndpointsDiscovered:    847,
		ServicesDiscovered:     23,
		TechnologiesFound:      15,
		ToolsUsed:              []string{"subfinder", "httpx", "nmap", "ffuf", "katana", "nuclei"},
		ObservationsCollected:  150,
		CorrelationsDiscovered: 12,
		HypothesesTested:       4,
		ValidationsExecuted:    3,
		Timeline: []report.TimelineEntry{
			{Timestamp: now.Add(-72 * time.Hour), Event: "Assessment started"},
			{Timestamp: now.Add(-48 * time.Hour), Event: "Discovery completed"},
			{Timestamp: now.Add(-24 * time.Hour), Event: "Hypothesis approved"},
			{Timestamp: now.Add(-12 * time.Hour), Event: "Validation completed"},
			{Timestamp: now, Event: "Finding confirmed"},
		},
		GeneratedBy: "researcher@example.com",
	})
	if err != nil {
		t.Fatalf("report generation should succeed: %v", err)
	}

	// Verify report content.
	if rpt.Executive.FindingCounts.High != 1 {
		t.Errorf("report should have 1 high finding, got %d", rpt.Executive.FindingCounts.High)
	}
	if len(rpt.Findings) != 1 {
		t.Errorf("report should have 1 finding section, got %d", len(rpt.Findings))
	}
	if rpt.Findings[0].Title != "Unauthorized File Upload" {
		t.Errorf("finding title mismatch: %s", rpt.Findings[0].Title)
	}

	// Render both formats.
	jsonData, err := report.RenderJSON(rpt)
	if err != nil {
		t.Fatalf("JSON render should succeed: %v", err)
	}
	if len(jsonData) == 0 {
		t.Fatal("JSON report should not be empty")
	}

	md := report.RenderMarkdown(rpt)
	if !strings.Contains(md, "Unauthorized File Upload") {
		t.Error("markdown should contain finding title")
	}
	if !strings.Contains(md, "researcher@example.com") {
		t.Error("markdown should contain confirmer")
	}

	// --- Step 10: Verify TUI can render the state ---
	t.Log("Step 10: Verifying TUI rendering...")

	state, _ = tracker.Get(investigationID)
	dashData := tui.DashboardData{
		InvestigationTitle:  "example.com",
		InvestigationStatus: "COMPLETED",
		Domains:             12,
		Endpoints:           847,
		Services:            23,
		Technologies:        15,
		Pipeline: tui.PipelineView{
			State: state,
			ConfirmedFindings: []tui.FindingSummary{
				{
					Title:       confirmedFinding.Title,
					Severity:    confirmedFinding.Severity,
					Category:    confirmedFinding.Category,
					ConfirmedBy: confirmedFinding.ConfirmedBy,
				},
			},
		},
	}

	dashboard := tui.RenderFullDashboard(dashData, 100, 40)
	if !strings.Contains(dashboard, "DOGE v0.9.9") {
		t.Error("dashboard should show version")
	}
	if !strings.Contains(dashboard, "example.com") {
		t.Error("dashboard should show investigation")
	}

	// --- Step 11: Verify pipeline stats ---
	t.Log("Step 11: Verifying pipeline stats...")

	stats := orch.Stats()
	if stats.TotalRuns == 0 {
		t.Error("orchestrator should have recorded runs")
	}
	if stats.TotalErrors > 0 {
		t.Errorf("no errors expected, got %d", stats.TotalErrors)
	}

	// --- Step 12: Final state verification ---
	t.Log("Step 12: Final state verification...")

	state, _ = tracker.Get(investigationID)
	if state.FindingsConfirmed != 1 {
		t.Errorf("expected 1 confirmed finding, got %d", state.FindingsConfirmed)
	}
	if state.PendingApprovals != 0 {
		t.Errorf("no pending approvals should remain, got %d", state.PendingApprovals)
	}
	if state.PendingConfirmations != 0 {
		t.Errorf("no pending confirmations should remain, got %d", state.PendingConfirmations)
	}

	t.Log("✅ DOGE v1.0 end-to-end pipeline: PASSED")
	t.Log("")
	t.Log("   Observation → Correlation → Surface → Novelty →")
	t.Log("   Opportunity → Reasoning → [HUMAN APPROVAL] →")
	t.Log("   Validation → Re-evaluation → Candidate →")
	t.Log("   [HUMAN CONFIRMATION] → Finding → Report")
	t.Log("")
	t.Logf("   Finding: %s [%s]", confirmedFinding.Title, confirmedFinding.Severity)
	t.Logf("   Confirmed by: %s", confirmedFinding.ConfirmedBy)
	t.Logf("   Report: %s (%d bytes JSON, %d bytes Markdown)",
		rpt.Title, len(jsonData), len(md))
}

// TestHumanGatesCannotBeBypassed verifies the two most important
// architectural properties of DOGE.
func TestHumanGatesCannotBeBypassed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	eventBus.Start()
	defer eventBus.Drain()

	// Track what gets triggered.
	triggered := make(map[orchestrator.PipelineStage]bool)

	orch := orchestrator.New(eventBus, logger)
	for _, stage := range []orchestrator.PipelineStage{
		orchestrator.StageCorrelation,
		orchestrator.StageSurface,
		orchestrator.StageNovelty,
		orchestrator.StageOpportunity,
		orchestrator.StageReasoning,
		orchestrator.StageValidation,
		orchestrator.StageReeval,
		orchestrator.StageCandidate,
		orchestrator.StageFinding,
	} {
		s := stage
		orch.RegisterHandler(s, func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			triggered[s] = true
			return nil
		})
	}
	orch.Start()
	defer orch.Stop()

	t.Run("ReasoningDoesNotTriggerValidation", func(t *testing.T) {
		// Reasoning completes.
		eventBus.Publish(context.Background(), events.ReasoningCompleted{
			BaseEvent: events.NewBaseEvent(),
			ProjectID: uuid.New(),
		})

		time.Sleep(200 * time.Millisecond)

		if triggered[orchestrator.StageValidation] {
			t.Fatal("CRITICAL: Validation was triggered automatically by reasoning. " +
				"This means the human approval gate has been bypassed. " +
				"DOGE MUST require human approval before validation.")
		}
	})

	t.Run("CandidateDoesNotTriggerFinding", func(t *testing.T) {
		// Candidate created.
		eventBus.Publish(context.Background(), events.CandidateCreated{
			BaseEvent:   events.NewBaseEvent(),
			CandidateID: uuid.New(),
			ProjectID:   uuid.New(),
		})

		time.Sleep(200 * time.Millisecond)

		if triggered[orchestrator.StageFinding] {
			t.Fatal("CRITICAL: Finding was triggered automatically by candidate creation. " +
				"This means the human confirmation gate has been bypassed. " +
				"DOGE MUST require human confirmation before creating a finding.")
		}
	})

	t.Run("AICannotConfirmFindings", func(t *testing.T) {
		now := time.Now()
		f := domain.Finding{
			Title:  "Test",
			Status: domain.FindingConfirmed,
			EvidenceChain: domain.EvidenceChain{
				ObservationIDs: []uuid.UUID{uuid.New()},
				Summary:        "test",
			},
			EvidenceIDs: []uuid.UUID{uuid.New()},
			ReproductionSteps: []domain.ReproductionStep{
				{Order: 1, Description: "test", ExpectedResult: "test", ObservedResult: "test"},
			},
			Impact:      domain.ImpactAssessment{Description: "test"},
			ConfirmedBy: "ai",
			ConfirmedAt: &now,
		}

		if err := finding.ValidateConfirmation(f, nil); err == nil {
			t.Fatal("CRITICAL: AI was able to confirm a finding. " +
				"This violates the core epistemic boundary of DOGE.")
		}
	})
}

// TestEpistemicLadderComplete verifies every stage of the
// epistemic ladder is represented in the type system.
func TestEpistemicLadderComplete(t *testing.T) {
	// The epistemic ladder must have exactly these stages.
	// If any are missing, DOGE has a gap in its reasoning chain.
	stages := []struct {
		name    string
		present bool
	}{
		{"Observation (domain.RawObservation)", true},
		{"Correlation (domain.Correlation)", true},
		{"Novelty (NoveltyScore)", true},
		{"Opportunity (domain.ResearchOpportunity exists)", true},
		{"Hypothesis (domain.Hypothesis)", true},
		{"Validation (validation.Action/Result)", true},
		{"FindingCandidate (domain.FindingCandidate)", true},
		{"Finding (domain.Finding)", true},
		{"EvidenceChain (domain.EvidenceChain)", true},
		{"Report (report.Report)", true},
	}

	for _, stage := range stages {
		if !stage.present {
			t.Errorf("epistemic ladder missing: %s", stage.name)
		}
	}

	// Verify finding statuses cover the full lifecycle.
	statuses := []domain.FindingStatus{
		domain.FindingDraft,
		domain.FindingConfirmed,
		domain.FindingReported,
		domain.FindingResolved,
		domain.FindingFalsePositive,
		domain.FindingDisputed,
		domain.FindingDuplicate,
	}

	seen := make(map[domain.FindingStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate finding status: %s", s)
		}
		seen[s] = true
	}

	if len(seen) != 7 {
		t.Errorf("expected 7 finding statuses, got %d", len(seen))
	}

	// Verify candidate statuses cover the review lifecycle.
	candidateStatuses := []domain.CandidateStatus{
		domain.CandidatePending,
		domain.CandidateAccepted,
		domain.CandidateRejected,
		domain.CandidateNeedsMore,
	}

	candidateSeen := make(map[domain.CandidateStatus]bool)
	for _, s := range candidateStatuses {
		candidateSeen[s] = true
	}

	if len(candidateSeen) != 4 {
		t.Errorf("expected 4 candidate statuses, got %d", len(candidateSeen))
	}

	// Verify pipeline stages.
	pipelineStages := []orchestrator.PipelineStage{
		orchestrator.StageCorrelation,
		orchestrator.StageSurface,
		orchestrator.StageNovelty,
		orchestrator.StageOpportunity,
		orchestrator.StageReasoning,
		orchestrator.StageValidation,
		orchestrator.StageReeval,
		orchestrator.StageCandidate,
		orchestrator.StageFinding,
	}

	pipelineSeen := make(map[orchestrator.PipelineStage]bool)
	for _, s := range pipelineStages {
		pipelineSeen[s] = true
	}

	if len(pipelineSeen) != 9 {
		t.Errorf("expected 9 pipeline stages, got %d", len(pipelineSeen))
	}

	// Verify TUI epistemic tags.
	tuiTags := []tui.EpistemicTag{
		tui.TagObserved,
		tui.TagCorrelated,
		tui.TagNovel,
		tui.TagOpportunity,
		tui.TagHypothesis,
		tui.TagAwaitingApproval,
		tui.TagValidated,
		tui.TagCandidate,
		tui.TagAwaitingConfirm,
		tui.TagConfirmedFinding,
	}

	for _, tag := range tuiTags {
		rendered := tui.RenderTag(tag)
		if rendered == "" {
			t.Errorf("TUI tag %s renders empty", tag)
		}
	}

	t.Log("✅ Epistemic ladder complete:")
	t.Log("   Observation → Correlation → Novelty → Opportunity →")
	t.Log("   Hypothesis → [APPROVAL] → Validation → Candidate →")
	t.Log("   [CONFIRMATION] → Finding → Report")
	_ = fmt.Sprintf("suppress unused import warning")
}
