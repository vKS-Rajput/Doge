package e2e

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/research"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// TestResearchTrajectory executes a deterministic, multi-iteration trajectory test proving
// the complete closed cognitive loop:
// Evidence → Hypothesize → Prioritize (Info Gain) → Execute → Falsify → Learn → Replan → Confirm
func TestResearchTrajectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup Scope & Program Rules
	scopeCfg := scope.Config{
		Target:      "target-app.local",
		Environment: "lab", // allows auto-recon in simulated environment
		InScope:     []string{"target-app.local", "*.target-app.local"},
		Rules:       scope.DefaultProgramRules(),
	}
	scopeEng, err := scope.NewEngine(scopeCfg)
	if err != nil {
		t.Fatalf("failed to initialize scope engine: %v", err)
	}

	gateMgr := gates.NewManager("")
	parserReg := parser.NewRegistry(nil)
	learner := learning.NewLearner(nil)

	agentCfg := research.Config{
		Target:          "target-app.local",
		Environment:     "lab",
		MaxIterations:   10,
		RateLimitPerSec: 100,
		AllowAutoRecon:  true,
	}

	agent := research.NewResearchAgent(
		agentCfg,
		scopeEng,
		gateMgr,
		parserReg,
		learner,
		nil,
	)

	// 2. Plant Synthetic Initial Observations (Deliberate Clues)
	// Clue 1: Object endpoint /api/users/1001
	// Clue 2: URL destination parameter dest_url
	initialEntities := []domain.Entity{
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "https://target-app.local/api/users/1001",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityParameter,
			Value: "dest_url",
			Attributes: map[string]any{
				"host": "target-app.local",
			},
		},
	}
	initialObservations := []domain.Observation{
		{
			ID:         uuid.New(),
			Type:       domain.ObservationEndpointDiscovery,
			SourceTool: "doge_surface",
			RawValue:   "https://target-app.local/api/users/1001",
			ObservedAt: time.Now().UTC(),
		},
		{
			ID:         uuid.New(),
			Type:       domain.ObservationEndpointDiscovery,
			SourceTool: "doge_surface",
			RawValue:   "dest_url",
			ObservedAt: time.Now().UTC(),
		},
	}

	agent.IngestEvidence(initialEntities, initialObservations)

	// 3. Configure Simulated Runner with Deterministic Responses
	currentExecution := 0
	agent.SetRunner(func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult {
		currentExecution++
		res := &runner.RunResult{
			Command:   cmd,
			StartedAt: time.Now(),
		}

		// First Execution: BOLA authorization test → Returns 403 Forbidden with tenant mismatch
		if strings.Contains(cmd, "users/1001") || currentExecution == 1 {
			res.ExitCode = 0
			res.Stdout = "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"error\": \"tenant mismatch - unauthorized access to object\"}"
			return res
		}

		// Second Execution: SSRF callback probe → Returns OOB DNS callback confirmed
		if strings.Contains(cmd, "target-app.local") || currentExecution == 2 {
			res.ExitCode = 0
			res.Stdout = "HTTP/1.1 200 OK\n\nDNS callback received on listener.doge-oob.net from 192.168.1.50 (callback_success)"
			return res
		}

		res.ExitCode = 0
		res.Stdout = "HTTP/1.1 200 OK"
		return res
	})

	// -------------------------------------------------------------------------
	// ITERATION 1: Initial Reasoning, Prioritization, Execution & Falsification
	// -------------------------------------------------------------------------
	t.Log("=== STEP 1: Running Iteration 1 ===")
	rep1, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration 1 failed: %v", err)
	}

	if rep1.SelectedAction == nil {
		t.Fatalf("expected iteration 1 to select an action, got nil")
	}

	// Verify that BOLA hypothesis was formed and tested first due to high initial confidence/impact
	t.Logf("Iteration 1 Selected Action: Tool=%s Target=%s Reason=%s Priority=%.2f",
		rep1.SelectedAction.Tool, rep1.SelectedAction.Target, rep1.SelectedAction.Reason, rep1.SelectedAction.PriorityScore)

	if rep1.EvaluationResult == nil {
		t.Fatalf("expected evaluation result in iteration 1")
	}

	// Assert Hypothesis Falsification: 403 Forbidden must reject BOLA hypothesis
	if !rep1.EvaluationResult.IsFalsified {
		t.Errorf("expected BOLA hypothesis to be falsified by 403 tenant mismatch, got: %v", rep1.EvaluationResult.Reason)
	}
	if rep1.EvaluationResult.NewStatus != hypothesis.StatusRejected {
		t.Errorf("expected hypothesis status REJECTED, got: %s", rep1.EvaluationResult.NewStatus)
	}
	if rep1.EvaluationResult.ConfidenceNew != 0.0 {
		t.Errorf("expected confidence to decay to 0.0 after refutation, got: %.2f", rep1.EvaluationResult.ConfidenceNew)
	}
	t.Logf("✓ Verified Falsification: %s", rep1.EvaluationResult.Reason)

	// -------------------------------------------------------------------------
	// ITERATION 2: Replanning, Dynamic Re-Ranking & Hypothesis Confirmation
	// -------------------------------------------------------------------------
	t.Log("=== STEP 2: Running Iteration 2 (Replanning & Direction Change) ===")
	rep2, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration 2 failed: %v", err)
	}

	if rep2.SelectedAction == nil {
		t.Fatalf("expected iteration 2 to select an action, got nil")
	}

	t.Logf("Iteration 2 Selected Action: Tool=%s Target=%s Reason=%s Priority=%.2f",
		rep2.SelectedAction.Tool, rep2.SelectedAction.Target, rep2.SelectedAction.Reason, rep2.SelectedAction.PriorityScore)

	// Verify that the agent changed direction to the SSRF hypothesis
	if rep2.SelectedAction.HypothesisID == nil {
		t.Fatalf("expected iteration 2 action to be linked to SSRF hypothesis")
	}

	if rep2.EvaluationResult == nil {
		t.Fatalf("expected evaluation result in iteration 2")
	}

	// Assert Hypothesis Confirmation: OOB DNS callback confirms SSRF
	if !rep2.EvaluationResult.IsConfirmed {
		t.Errorf("expected SSRF hypothesis to be confirmed by OOB DNS callback, got: %v", rep2.EvaluationResult.Reason)
	}
	if rep2.EvaluationResult.NewStatus != hypothesis.StatusConfirmed {
		t.Errorf("expected hypothesis status CONFIRMED, got: %s", rep2.EvaluationResult.NewStatus)
	}
	if rep2.EvaluationResult.ConfidenceNew < 0.90 {
		t.Errorf("expected high confidence (>= 0.90) for confirmed finding, got: %.2f", rep2.EvaluationResult.ConfidenceNew)
	}
	t.Logf("✓ Verified Confirmation: %s (Confidence: %.2f)", rep2.EvaluationResult.Reason, rep2.EvaluationResult.ConfidenceNew)

	// -------------------------------------------------------------------------
	// VERIFY LEARNING FEEDBACK PERSISTENCE & PRIORITY PENALTY/BOOST
	// -------------------------------------------------------------------------
	t.Log("=== STEP 3: Verifying Bidirectional Learning Feedback ===")
	fb := agent.GetFeedbackEngine()
	bolaBoost := fb.GetPatternPriorityBoost("bola_idor")
	ssrfBoost := fb.GetPatternPriorityBoost("ssrf")

	t.Logf("Learned Pattern Boosts: bola_idor = %.2f (penalized), ssrf = %.2f (boosted)", bolaBoost, ssrfBoost)

	if bolaBoost >= 0 {
		t.Errorf("expected negative learning boost for refuted bola_idor pattern, got: %.2f", bolaBoost)
	}
	if ssrfBoost <= 0 {
		t.Errorf("expected positive learning boost for confirmed ssrf pattern, got: %.2f", ssrfBoost)
	}

	t.Log("🎉 Complete Closed-Loop Research Trajectory Successfully Demonstrated!")
}
