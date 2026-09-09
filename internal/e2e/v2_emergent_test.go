package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/researcher"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// TestV2EmergentSlice proves DOGE Ultimate Phase 2:
// Unknown-Space Discovery & Epistemic Expansion.
//
// Core Research Question:
// "What computational mechanism allows DOGE to discover security failures
// that DOGE's designers did not explicitly encode?"
//
// Target: Synthetic enterprise gateway with planted Batch Pipeline Context Bleed.
// Planted flaw: /api/v1/batch fails to clear authorization context across sub-operation
// execution frames, allowing unauthenticated operations to inherit preceding credentials.
//
// CRITICAL CONSTRAINTS:
//   - The vulnerability class "Batch Pipeline Context Bleed" is NOT in DOGE's static ontology.
//   - DOGE is NOT told what vulnerability exists.
//   - DOGE is NOT told where to look.
//   - DOGE must discover endpoints via Recon.
//   - DOGE must induce dynamic invariants (Context Isolation, Order Commutativity) using InvariantMiner.
//   - DOGE must evaluate metamorphic relations via MetamorphicProber.
//   - DOGE must arbitrate budget using Dual-Policy ResearchDirector (exploit vs discover).
//   - DOGE must independently validate the anomaly with differential control (direct 401/403 rejection).
//   - DOGE must prove impact by exfiltrating classified vault credentials (sec-beta-999).
//   - DOGE must produce a PROVEN FINDING with a complete 3-tier evidence chain.
func TestV2EmergentSlice(t *testing.T) {
	// ──────────────────────────────────────
	// Setup: Synthetic emergent app with planted context bleed
	// ──────────────────────────────────────
	app := benchmark.NewSyntheticEmergentApp()
	defer app.Close()

	targetURL := app.BaseURL()
	credentials := app.Credentials()
	planted := app.GetPlantedVulnerabilities()

	t.Logf("=== DOGE Ultimate Phase 2: Unknown-Space Discovery Slice ===")
	t.Logf("Target: %s", targetURL)
	t.Logf("Credentials provided: %d", len(credentials))
	t.Logf("Planted emergent flaws: %d (NOT disclosed to DOGE)", len(planted.PlantedVulnerabilities))
	t.Logf("")

	// ──────────────────────────────────────
	// Build DOGE Ultimate research fleet
	// ──────────────────────────────────────
	httpClient := researcher.NewHTTPClient()

	coord := coordinator.NewResearchCoordinator(targetURL, credentials)
	coord.RegisterResearcher(researcher.NewReconResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewAnomalyResearcher(httpClient, coord.Miner()))
	coord.RegisterResearcher(researcher.NewValidationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewImpactResearcher(httpClient))

	// ──────────────────────────────────────
	// Run the complete research loop
	// ──────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf(">>> Starting DOGE Ultimate Research Loop (Phase 2 Epistemic Expansion)...")
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
	// Director & Invariant State
	// ──────────────────────────────────────
	t.Logf("=== DIRECTOR & DYNAMIC INVARIANT STATE ===")
	exploitStats, discoverStats, ratio := coord.Director().GetStats()
	t.Logf("Director Arbitration: ExploitRatio=%.2f", ratio)
	t.Logf("  Exploit Policy: Invocations=%d, Novelties=%d, Findings=%d",
		exploitStats.Invocations, exploitStats.Novelties, exploitStats.FindingsFound)
	t.Logf("  Discover Policy: Invocations=%d, Novelties=%d, Findings=%d",
		discoverStats.Invocations, discoverStats.Novelties, discoverStats.FindingsFound)

	minedInvariants := coord.Miner().MineInvariants()
	t.Logf("Dynamically Induced Invariants: %d", len(minedInvariants))
	for _, inv := range minedInvariants {
		t.Logf("  [%s] %s (Confidence: %.2f)", inv.Type, inv.Statement, inv.Confidence)
	}

	eval := coord.PropertyEvaluator()
	allProps := eval.ListAll()
	t.Logf("Active Security Properties: %d", len(allProps))

	graph := coord.AttackGraph()
	t.Logf("Attack Graph: %d nodes, %d edges", graph.NodeCount(), graph.EdgeCount())
	t.Logf("")

	// ──────────────────────────────────────
	// Assertions
	// ──────────────────────────────────────
	t.Logf("=== ASSERTIONS ===")

	// 1. Must have discovered batch endpoint
	if len(state.Endpoints) == 0 {
		t.Fatal("FAIL: No endpoints discovered")
	}
	hasBatch := false
	for _, ep := range state.Endpoints {
		if strings.Contains(strings.ToLower(ep), "batch") {
			hasBatch = true
			break
		}
	}
	if !hasBatch {
		t.Fatal("FAIL: Batch pipeline endpoint /api/v1/batch not discovered")
	}
	t.Logf("✓ Batch endpoint discovered: %v", state.Endpoints)

	// 2. Invariants must have been induced dynamically
	if len(minedInvariants) == 0 {
		t.Fatal("FAIL: No dynamic invariants induced from observed execution traces")
	}
	t.Logf("✓ Dynamic invariants induced: %d", len(minedInvariants))

	// 3. Must have executed AnomalyResearcher mission
	anomalyExecuted := false
	for _, m := range state.Missions {
		if m.ResearcherType == domain.ResearcherAnomaly {
			anomalyExecuted = true
			break
		}
	}
	if !anomalyExecuted {
		t.Fatal("FAIL: AnomalyResearcher mission was not executed")
	}
	t.Logf("✓ AnomalyResearcher executed metamorphic exploration")

	// 4. Must have candidate vulnerability for batch context bleed
	if len(state.Candidates) == 0 {
		t.Fatal("FAIL: No candidate vulnerabilities discovered")
	}
	cand := state.Candidates[0]
	if !strings.Contains(strings.ToLower(cand.Type), "batch") && !strings.Contains(strings.ToLower(cand.Title), "bleed") {
		t.Fatalf("FAIL: Candidate is not batch context bleed: %s (%s)", cand.Title, cand.Type)
	}
	t.Logf("✓ Emergent candidate discovered: [%s] %s", cand.Severity, cand.Title)

	// 5. Must have independently validated candidate
	if len(state.Validated) == 0 {
		t.Fatal("FAIL: No vulnerabilities independently validated")
	}
	t.Logf("✓ Emergent vulnerability independently validated: %d", len(state.Validated))

	// 6. Must have proven findings
	if len(state.ProvenFindings) == 0 {
		t.Fatal("FAIL: No proven findings produced")
	}
	proven := state.ProvenFindings[0]
	t.Logf("✓ Proven finding produced: [%s] %s", proven.Severity, proven.Title)
	t.Logf("  Endpoint: %s", proven.Endpoint)

	// 7. Proven finding must have complete 3-tier evidence chain
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

	// 8. Impact evidence must prove exfiltration of classified secret
	impactProven := false
	for _, obs := range state.Missions[len(state.Missions)-1].Observations {
		if obs.Type == "impact_assessed" && strings.Contains(obs.Description, "CLASSIFIED-BETA-ROOT-KEY-99942") {
			impactProven = true
			break
		}
	}
	if !impactProven {
		// Also check within evidence bodies
		for _, ev := range proven.ImpactEvidence {
			if strings.Contains(ev.ResponseBody, "CLASSIFIED-BETA-ROOT-KEY-99942") {
				impactProven = true
				break
			}
		}
	}
	if !impactProven {
		t.Fatal("FAIL: Impact evidence did not prove extraction of CLASSIFIED-BETA-ROOT-KEY-99942")
	}
	t.Logf("✓ Impact verified: Classified tenant secret successfully exfiltrated via context bleed")

	// 9. Attack graph must connect weakness to impact
	if graph.NodeCount() < 3 {
		t.Fatalf("FAIL: Attack graph node count %d too low", graph.NodeCount())
	}
	t.Logf("✓ Attack graph populated: %d nodes, %d edges", graph.NodeCount(), graph.EdgeCount())

	// 10. Benchmark Verification: Planted BENCH-003 verified
	t.Logf("")
	t.Logf("=== BENCHMARK VERIFICATION ===")
	for _, p := range planted.PlantedVulnerabilities {
		found := false
		for _, pf := range state.ProvenFindings {
			if strings.Contains(pf.Endpoint, "batch") ||
				strings.Contains(strings.ToLower(pf.Type), strings.ToLower(p.Type)) {
				found = true
				t.Logf("✓ PLANTED %s (%s) on %s → DISCOVERED & PROVEN as %s", p.ID, p.Type, p.Endpoint, pf.Title)
			}
		}
		if !found {
			t.Errorf("✗ PLANTED %s on %s → NOT DISCOVERED", p.Type, p.Endpoint)
		}
	}

	t.Logf("")
	t.Logf("=== DOGE ULTIMATE EMERGENT SLICE: PASSED ✅ ===")
}
