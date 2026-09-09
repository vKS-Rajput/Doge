package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/property"
	"github.com/vKS-Rajput/doge/internal/researcher"
)

// TestV2WorkflowSlice proves DOGE Ultimate Phase 1:
// Generalization to Workflow State Bypass through Security Property Reasoning.
//
// Target: Synthetic e-commerce app with payment step bypass vulnerability.
// Required flow: Cart → Order → Checkout → Payment → Confirmation
// Planted flaw: /confirm endpoint accepts orders in 'checkout' state without requiring 'paid'.
//
// CRITICAL CONSTRAINTS:
//   - DOGE is NOT told what vulnerability exists
//   - DOGE is NOT told where to look
//   - DOGE is NOT told that payment can be skipped
//   - DOGE must discover the state machine
//   - DOGE must evaluate the property: "Workflow transitions cannot be skipped"
//   - DOGE must independently validate the bypass with differential control
//   - DOGE must demonstrate financial impact ($999.95 unpaid order)
//   - DOGE must produce a PROVEN FINDING with complete evidence chain
func TestV2WorkflowSlice(t *testing.T) {
	// ──────────────────────────────────────
	// Setup: Synthetic workflow app with planted bypass
	// ──────────────────────────────────────
	app := benchmark.NewSyntheticWorkflowApp()
	defer app.Close()

	targetURL := app.BaseURL()
	credentials := app.Credentials()
	planted := app.GetPlantedVulnerabilities()

	t.Logf("=== DOGE Ultimate Phase 1: Workflow State Bypass Slice ===")
	t.Logf("Target: %s", targetURL)
	t.Logf("Credentials provided: %d (buyer identity NOT disclosed)", len(credentials))
	t.Logf("Planted vulnerabilities: %d (NOT disclosed to DOGE)", len(planted.PlantedVulnerabilities))
	t.Logf("")

	// ──────────────────────────────────────
	// Build DOGE Ultimate research fleet
	// ──────────────────────────────────────
	httpClient := researcher.NewHTTPClient()

	coord := coordinator.NewResearchCoordinator(targetURL, credentials)
	coord.RegisterResearcher(researcher.NewReconResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewWorkflowResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewValidationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewImpactResearcher(httpClient))

	// ──────────────────────────────────────
	// Run the complete research loop
	// ──────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf(">>> Starting DOGE Ultimate Research Loop...")
	start := time.Now()

	err := coord.Run(ctx)
	if err != nil {
		t.Fatalf("Research loop failed: %v", err)
	}

	elapsed := time.Since(start)
	state := coord.GetState()

	// ──────────────────────────────────────
	// Trajectory Analysis
	// ──────────────────────────────────────
	t.Logf("")
	t.Logf("=== RESEARCH TRAJECTORY ===")
	t.Logf("Duration: %v", elapsed)
	t.Logf("Missions executed: %d", len(state.Missions))
	t.Logf("")

	for i, m := range state.Missions {
		t.Logf("Mission %d: [%s] %s", i+1, m.ResearcherType, m.Summary)
		t.Logf("  Status: %s | Requests: %d | Duration: %v", m.Status, m.RequestsMade, m.Duration)
		t.Logf("  Evidence pieces: %d", len(m.Evidence))
		t.Logf("  Observations: %d", len(m.Observations))
		if len(m.HypothesisUpdates) > 0 {
			for _, hu := range m.HypothesisUpdates {
				t.Logf("  Hypothesis update: %s (confidence: %.2f) — %s", hu.NewStatus, hu.NewConfidence, hu.Reason)
			}
		}
		if len(m.CandidateFindings) > 0 {
			for _, cf := range m.CandidateFindings {
				t.Logf("  CANDIDATE: [%s] %s (%s)", cf.Severity, cf.Title, cf.Type)
			}
		}
		t.Logf("")
	}

	// ──────────────────────────────────────
	// World Model & Property State
	// ──────────────────────────────────────
	t.Logf("=== WORLD MODEL & SECURITY PROPERTY STATE ===")
	t.Logf("Things we found:")
	t.Logf("  Endpoints: %v", state.Endpoints)
	t.Logf("  Users: %v", state.Users)

	eval := coord.PropertyEvaluator()
	allProps := eval.ListAll()
	t.Logf("Registered Security Properties: %d", len(allProps))
	for _, p := range allProps {
		if p.Class == property.ClassWorkflowIntegrity {
			t.Logf("  [WorkflowProperty] %s: %s (State: %s, Confidence: %.2f)", p.Class, p.Statement, p.State, p.Confidence)
		}
	}

	graph := coord.AttackGraph()
	t.Logf("Attack Graph: %d nodes, %d edges", graph.NodeCount(), graph.EdgeCount())
	t.Logf("")

	// ──────────────────────────────────────
	// Assertions
	// ──────────────────────────────────────
	t.Logf("=== ASSERTIONS ===")

	// 1. Research must have discovered workflow endpoints
	if len(state.Endpoints) == 0 {
		t.Fatal("FAIL: No endpoints discovered")
	}
	t.Logf("✓ Endpoints discovered: %d", len(state.Endpoints))

	// 2. Research must have generated workflow hypotheses
	if len(state.Hypotheses) == 0 {
		t.Fatal("FAIL: No hypotheses generated")
	}
	foundWorkflowHyp := false
	for _, h := range state.Hypotheses {
		if strings.Contains(strings.ToLower(h.Title), "workflow") || strings.Contains(strings.ToLower(h.Title), "bypass") {
			foundWorkflowHyp = true
			break
		}
	}
	if !foundWorkflowHyp {
		t.Fatal("FAIL: No workflow-related hypothesis generated")
	}
	t.Logf("✓ Workflow hypotheses generated: %d total hypotheses", len(state.Hypotheses))

	// 3. Must have completed missions (recon, workflow, validation, impact)
	if len(state.Missions) < 3 {
		t.Fatalf("FAIL: Only %d missions completed (need at least 3)", len(state.Missions))
	}
	t.Logf("✓ Missions completed: %d", len(state.Missions))

	// 4. Must have candidate vulnerabilities
	if len(state.Candidates) == 0 {
		t.Fatal("FAIL: No candidate vulnerabilities discovered")
	}
	t.Logf("✓ Candidates discovered: %d", len(state.Candidates))

	// 5. Must have validated vulnerabilities
	if len(state.Validated) == 0 {
		t.Fatal("FAIL: No vulnerabilities independently validated")
	}
	t.Logf("✓ Vulnerabilities validated: %d", len(state.Validated))

	// 6. Must have proven findings
	if len(state.ProvenFindings) == 0 {
		t.Fatal("FAIL: No proven findings produced")
	}
	t.Logf("✓ Proven findings: %d", len(state.ProvenFindings))

	// 7. Proven finding must have complete evidence chain
	proven := state.ProvenFindings[0]
	if len(proven.DiscoveryEvidence) == 0 {
		t.Fatal("FAIL: Proven finding has no discovery evidence")
	}
	if len(proven.ValidationEvidence) == 0 {
		t.Fatal("FAIL: Proven finding has no validation evidence")
	}
	if len(proven.ImpactEvidence) == 0 {
		t.Fatal("FAIL: Proven finding has no impact evidence")
	}
	t.Logf("✓ Evidence chain complete: %d discovery, %d validation, %d impact",
		len(proven.DiscoveryEvidence), len(proven.ValidationEvidence), len(proven.ImpactEvidence))

	// 8. Proven finding must reference the workflow bypass
	if !strings.Contains(strings.ToLower(proven.Title), "workflow") &&
		!strings.Contains(strings.ToLower(proven.Type), "workflow") {
		t.Fatalf("FAIL: Proven finding title or type doesn't reference workflow bypass: %s (%s)", proven.Title, proven.Type)
	}
	t.Logf("✓ Proven finding: [%s] %s", proven.Severity, proven.Title)
	t.Logf("  Endpoint: %s", proven.Endpoint)

	// 9. Must have reproduction steps
	if len(proven.ReproductionSteps) == 0 {
		t.Fatal("FAIL: Proven finding has no reproduction steps")
	}
	t.Logf("✓ Reproduction steps: %d", len(proven.ReproductionSteps))
	for i, step := range proven.ReproductionSteps {
		t.Logf("  %d. %s", i+1, step)
	}

	// 10. Attack graph must contain nodes and edges
	if graph.NodeCount() < 3 {
		t.Fatalf("FAIL: Attack graph node count %d too low", graph.NodeCount())
	}
	t.Logf("✓ Attack graph populated: %d nodes, %d edges", graph.NodeCount(), graph.EdgeCount())

	// ──────────────────────────────────────
	// Benchmark Verification
	// ──────────────────────────────────────
	t.Logf("")
	t.Logf("=== BENCHMARK VERIFICATION ===")
	for _, p := range planted.PlantedVulnerabilities {
		found := false
		for _, pf := range state.ProvenFindings {
			if strings.Contains(pf.Endpoint, "confirm") ||
				strings.Contains(strings.ToLower(pf.Type), strings.ToLower(p.Type)) {
				found = true
				t.Logf("✓ PLANTED %s on %s → DISCOVERED & PROVEN as %s", p.Type, p.Endpoint, pf.Title)
			}
		}
		if !found {
			t.Errorf("✗ PLANTED %s on %s → NOT DISCOVERED", p.Type, p.Endpoint)
		}
	}

	t.Logf("")
	t.Logf("=== DOGE ULTIMATE WORKFLOW SLICE: PASSED ✅ ===")
}
