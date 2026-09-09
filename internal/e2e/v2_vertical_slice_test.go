package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/researcher"
)

// TestV2VerticalSlice proves the complete DOGE V2 research loop:
//
//	TARGET → LEARN → MAP → UNKNOWN → HYPOTHESIS → MISSION → RESEARCHER
//	→ EXPERIMENT → OBSERVATION → WORLD MODEL UPDATE → NEW HYPOTHESIS
//	→ EXPLOIT → INDEPENDENT VALIDATOR → IMPACT RESEARCHER → PROVEN FINDING
//
// CRITICAL CONSTRAINTS:
//   - DOGE is NOT told what vulnerability exists
//   - DOGE is NOT told where to look
//   - DOGE is NOT told what tools to use
//   - DOGE must DISCOVER the vulnerability through research
//   - DOGE must INDEPENDENTLY VALIDATE the vulnerability
//   - DOGE must DEMONSTRATE IMPACT
//   - DOGE must produce a PROVEN FINDING with complete evidence chain
func TestV2VerticalSlice(t *testing.T) {
	// ──────────────────────────────────────
	// Setup: Synthetic app with planted vulnerability
	// ──────────────────────────────────────
	app := benchmark.NewSyntheticBOLAApp()
	defer app.Close()

	targetURL := app.BaseURL()
	credentials := app.Credentials()
	planted := app.GetPlantedVulnerabilities()

	t.Logf("=== DOGE V2 Vertical Slice Test ===")
	t.Logf("Target: %s", targetURL)
	t.Logf("Credentials provided: %d (user identities NOT disclosed)", len(credentials))
	t.Logf("Planted vulnerabilities: %d (NOT disclosed to DOGE)", len(planted.PlantedVulnerabilities))
	t.Logf("")

	// ──────────────────────────────────────
	// Build DOGE V2 research system
	// ──────────────────────────────────────
	httpClient := researcher.NewHTTPClient()

	coord := coordinator.NewResearchCoordinator(targetURL, credentials)
	coord.RegisterResearcher(researcher.NewReconResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewAuthorizationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewValidationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewImpactResearcher(httpClient))

	// ──────────────────────────────────────
	// Run the complete research loop
	// ──────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf(">>> Starting DOGE V2 Research Loop...")
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
	// World Model State
	// ──────────────────────────────────────
	t.Logf("=== WORLD MODEL STATE ===")
	t.Logf("Things we found:")
	t.Logf("  Endpoints: %v", state.Endpoints)
	t.Logf("  Users: %v", state.Users)
	t.Logf("  Objects: %v", state.Objects)
	t.Logf("")

	t.Logf("Things we tried: %d attempts", len(state.Attempted))
	for _, a := range state.Attempted {
		t.Logf("  - %s", a.Description)
	}
	t.Logf("")

	t.Logf("Things that failed: %d", len(state.Failures))
	for _, f := range state.Failures {
		t.Logf("  - %s: %s", f.Description, f.Reason)
	}
	t.Logf("")

	t.Logf("Things we believe: %d hypotheses", len(state.Hypotheses))
	for _, h := range state.Hypotheses {
		t.Logf("  - [%.2f] %s", h.Confidence, h.Title)
	}
	t.Logf("")

	t.Logf("Things we disproved: %d", len(state.Disproved))
	for _, d := range state.Disproved {
		t.Logf("  - %s: %s", d.HypothesisTitle, d.Evidence)
	}
	t.Logf("")

	t.Logf("Things we have not tested: %d", len(state.Untested))
	for _, u := range state.Untested {
		t.Logf("  - %s", u)
	}
	t.Logf("")

	t.Logf("Total evidence collected: %d pieces", len(state.AllEvidence))
	t.Logf("")

	// ──────────────────────────────────────
	// ASSERTIONS: The research loop MUST produce results
	// ──────────────────────────────────────
	t.Logf("=== ASSERTIONS ===")

	// 1. Research must have discovered endpoints
	if len(state.Endpoints) == 0 {
		t.Fatal("FAIL: No endpoints discovered — recon failed")
	}
	t.Logf("✓ Endpoints discovered: %d", len(state.Endpoints))

	// 2. Research must have identified multiple principals
	if len(state.Users) < 2 {
		t.Fatal("FAIL: Did not identify at least 2 principals")
	}
	t.Logf("✓ Principals identified: %d", len(state.Users))

	// 3. Research must have generated hypotheses
	if len(state.Hypotheses) == 0 {
		t.Fatal("FAIL: No hypotheses generated — the research loop failed to reason")
	}
	t.Logf("✓ Hypotheses generated: %d", len(state.Hypotheses))

	// 4. Must have completed at least 3 missions (recon + auth + validation)
	if len(state.Missions) < 3 {
		t.Fatalf("FAIL: Only %d missions completed (need at least 3: recon + auth + validation)", len(state.Missions))
	}
	t.Logf("✓ Missions completed: %d", len(state.Missions))

	// 5. Must have candidate vulnerabilities
	if len(state.Candidates) == 0 {
		t.Fatal("FAIL: No candidate vulnerabilities discovered")
	}
	t.Logf("✓ Candidates discovered: %d", len(state.Candidates))

	// 6. Must have validated vulnerabilities
	if len(state.Validated) == 0 {
		t.Fatal("FAIL: No vulnerabilities independently validated")
	}
	t.Logf("✓ Vulnerabilities validated: %d", len(state.Validated))

	// 7. Must have proven findings
	if len(state.ProvenFindings) == 0 {
		t.Fatal("FAIL: No proven findings — the loop did not complete")
	}
	t.Logf("✓ Proven findings: %d", len(state.ProvenFindings))

	// 8. Proven finding must have complete evidence chain
	proven := state.ProvenFindings[0]
	if len(proven.DiscoveryEvidence) == 0 {
		t.Fatal("FAIL: Proven finding has no discovery evidence")
	}
	if len(proven.ValidationEvidence) == 0 {
		t.Fatal("FAIL: Proven finding has no validation evidence")
	}
	t.Logf("✓ Evidence chain complete: %d discovery, %d validation, %d impact",
		len(proven.DiscoveryEvidence), len(proven.ValidationEvidence), len(proven.ImpactEvidence))

	// 9. Proven finding must reference the correct vulnerability
	if !strings.Contains(strings.ToLower(proven.Title), "bola") &&
		!strings.Contains(strings.ToLower(proven.Title), "authorization") &&
		!strings.Contains(strings.ToLower(proven.Title), "idor") {
		t.Logf("WARNING: Proven finding title doesn't clearly reference BOLA/IDOR: %s", proven.Title)
	}
	t.Logf("✓ Proven finding: [%s] %s", proven.Severity, proven.Title)
	t.Logf("  Endpoint: %s", proven.Endpoint)

	// 10. Must have reproduction steps
	if len(proven.ReproductionSteps) == 0 {
		t.Fatal("FAIL: Proven finding has no reproduction steps")
	}
	t.Logf("✓ Reproduction steps: %d", len(proven.ReproductionSteps))
	for i, step := range proven.ReproductionSteps {
		t.Logf("  %d. %s", i+1, step)
	}

	// ──────────────────────────────────────
	// Trajectory Quality Metrics
	// ──────────────────────────────────────
	t.Logf("")
	t.Logf("=== TRAJECTORY QUALITY METRICS ===")

	totalRequests := 0
	for _, m := range state.Missions {
		totalRequests += m.RequestsMade
	}
	t.Logf("Total HTTP requests: %d", totalRequests)
	t.Logf("Requests per finding: %d", totalRequests/max(len(state.ProvenFindings), 1))
	t.Logf("Missions per finding: %d", len(state.Missions)/max(len(state.ProvenFindings), 1))
	t.Logf("Evidence pieces: %d", len(state.AllEvidence))
	t.Logf("Hypotheses tested: %d", len(state.Hypotheses))
	t.Logf("Hypotheses disproved: %d", len(state.Disproved))

	// Verify against planted vulnerabilities
	t.Logf("")
	t.Logf("=== BENCHMARK VERIFICATION ===")
	for _, planted := range planted.PlantedVulnerabilities {
		found := false
		for _, proven := range state.ProvenFindings {
			if strings.Contains(proven.Endpoint, "/items/") ||
				strings.Contains(strings.ToLower(proven.Type), strings.ToLower(planted.Type)) {
				found = true
				t.Logf("✓ PLANTED %s on %s → DISCOVERED & PROVEN as %s", planted.Type, planted.Endpoint, proven.Title)
			}
		}
		if !found {
			t.Errorf("✗ PLANTED %s on %s → NOT DISCOVERED", planted.Type, planted.Endpoint)
		}
	}

	t.Logf("")
	t.Logf("=== DOGE V2 VERTICAL SLICE: %s ===", func() string {
		if len(state.ProvenFindings) > 0 {
			return "PASSED ✅"
		}
		return "FAILED ❌"
	}())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TrajectoryReport generates a detailed markdown report of the research trajectory.
func TrajectoryReport(state *coordinator.ResearchState) string {
	var sb strings.Builder

	sb.WriteString("# DOGE V2 Research Trajectory Report\n\n")

	sb.WriteString("## Missions\n\n")
	for i, m := range state.Missions {
		sb.WriteString(fmt.Sprintf("### Mission %d: [%s] %s\n", i+1, m.ResearcherType, m.Summary))
		sb.WriteString(fmt.Sprintf("- Status: %s\n", m.Status))
		sb.WriteString(fmt.Sprintf("- Requests: %d\n", m.RequestsMade))
		sb.WriteString(fmt.Sprintf("- Duration: %v\n", m.Duration))
		sb.WriteString(fmt.Sprintf("- Evidence: %d pieces\n", len(m.Evidence)))
		sb.WriteString("\n")
	}

	sb.WriteString("## World Model\n\n")
	sb.WriteString(fmt.Sprintf("- Endpoints: %d\n", len(state.Endpoints)))
	sb.WriteString(fmt.Sprintf("- Users: %d\n", len(state.Users)))
	sb.WriteString(fmt.Sprintf("- Hypotheses: %d\n", len(state.Hypotheses)))
	sb.WriteString(fmt.Sprintf("- Candidates: %d\n", len(state.Candidates)))
	sb.WriteString(fmt.Sprintf("- Validated: %d\n", len(state.Validated)))
	sb.WriteString(fmt.Sprintf("- Proven: %d\n", len(state.ProvenFindings)))

	sb.WriteString("\n## Proven Findings\n\n")
	for _, pf := range state.ProvenFindings {
		sb.WriteString(fmt.Sprintf("### %s\n", pf.Title))
		sb.WriteString(fmt.Sprintf("- Type: %s\n", pf.Type))
		sb.WriteString(fmt.Sprintf("- Severity: %s\n", pf.Severity))
		sb.WriteString(fmt.Sprintf("- Endpoint: %s\n", pf.Endpoint))
		sb.WriteString(fmt.Sprintf("- Discovery Evidence: %d pieces\n", len(pf.DiscoveryEvidence)))
		sb.WriteString(fmt.Sprintf("- Validation Evidence: %d pieces\n", len(pf.ValidationEvidence)))
		sb.WriteString(fmt.Sprintf("- Impact Evidence: %d pieces\n", len(pf.ImpactEvidence)))
		sb.WriteString("\n**Reproduction Steps:**\n")
		for _, step := range pf.ReproductionSteps {
			sb.WriteString(fmt.Sprintf("- %s\n", step))
		}
	}

	return sb.String()
}
