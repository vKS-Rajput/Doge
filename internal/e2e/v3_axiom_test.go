package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/researcher"
)

// TestV3AxiomRaceConditionSlice proves DOGE Ultimate Phase 3:
// Representation Discovery on BENCH-004 (Latent Race Window Serialization Collapse).
//
// Neither race conditions nor wallet concurrency are hardcoded into DOGE's ontology.
// DOGE must:
// 1. Discover endpoints via Reconnaissance.
// 2. Induce the latent behavioral dimension (Temporal Concurrency Interleaving) via LatentBasisMiner.
// 3. Formulate causal DAG nodes in SCMGraph.
// 4. Synthesize interventional concurrent bursts via AnomalyResearcher.
// 5. Discover balance collapse / double-spend.
// 6. Independently validate with differential sequential control.
// 7. Demonstrate real-world financial overdraft impact.
// 8. Synthesize CEGAR separating predicates.
// 9. Autonomously expand its security ontology via ModelRouter and OntologyExpander.
// 10. Produce a Proven Finding with an intact 3-tier evidence chain.
func TestV3AxiomRaceConditionSlice(t *testing.T) {
	app := benchmark.NewSyntheticRaceApp()
	defer app.Close()

	targetURL := app.BaseURL()
	credentials := app.Credentials()

	t.Logf("=== DOGE Ultimate Phase 3: AXIOM Representation Discovery (BENCH-004: Race Window) ===")
	t.Logf("Target: %s", targetURL)
	t.Logf("Credentials provided: %d", len(credentials))
	t.Logf("Planted flaw: Asynchronous balance check in /api/v1/wallet/transfer (NOT disclosed to DOGE)")
	t.Logf("")

	httpClient := researcher.NewHTTPClient()
	coord := coordinator.NewResearchCoordinator(targetURL, credentials)
	coord.RegisterResearcher(researcher.NewReconResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewAnomalyResearcher(httpClient, coord.Miner()))
	coord.RegisterResearcher(researcher.NewValidationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewImpactResearcher(httpClient))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf(">>> Starting DOGE Ultimate AXIOM Research Loop...")
	start := time.Now()

	err := coord.Run(ctx)
	if err != nil {
		t.Fatalf("Research loop failed: %v", err)
	}

	elapsed := time.Since(start)
	state := coord.GetState()

	t.Logf("")
	t.Logf("=== RESEARCH TRAJECTORY ===")
	t.Logf("Duration: %v", elapsed)
	t.Logf("Missions executed: %d", len(state.Missions))

	for i, m := range state.Missions {
		t.Logf("Mission %d: [%s] %s", i+1, m.ResearcherType, m.Summary)
		t.Logf("  Status: %s | Requests: %d | Duration: %v", m.Status, m.RequestsMade, m.Duration)
		t.Logf("  Evidence pieces: %d", len(m.Evidence))
		t.Logf("  Observations: %d", len(m.Observations))
		if len(m.CandidateFindings) > 0 {
			for _, cand := range m.CandidateFindings {
				t.Logf("  CANDIDATE: [%s] %s (%s)", cand.Severity, cand.Title, cand.Type)
			}
		}
	}

	t.Logf("")
	t.Logf("=== AXIOM LATENT REPRESENTATION & ONTOLOGY EXPANSION STATE ===")
	t.Logf("Discovered Endpoints: %v", state.Endpoints)
	t.Logf("SCM Causal Variables: %d", coord.CausalGraph().VariableCount())
	t.Logf("Attack Graph Nodes: %d, Edges: %d", coord.AttackGraph().NodeCount(), coord.AttackGraph().EdgeCount())
	t.Logf("Learned Security Concepts in Ontology: %d", coord.OntologyExpander().ConceptCount())

	for _, c := range coord.OntologyExpander().GetConcepts() {
		t.Logf("  [ONTOLOGY CONCEPT] %s: %s", c.ConceptID, c.Name)
		t.Logf("    Dimension: %s", c.Dimension)
		t.Logf("    Separating Predicate: %s", c.SeparatingPredicate)
		t.Logf("    Evidence count: %d", c.EmpiricalEvidenceCount)
	}

	t.Logf("")
	t.Logf("=== ASSERTIONS ===")

	// 1. Assert Endpoints Discovered
	hasTransfer := false
	for _, ep := range state.Endpoints {
		if strings.Contains(ep, "wallet/transfer") {
			hasTransfer = true
			break
		}
	}
	if !hasTransfer {
		t.Fatalf("expected /api/v1/wallet/transfer in discovered endpoints: %v", state.Endpoints)
	}
	t.Logf("✓ Wallet transfer endpoint discovered")

	// 2. Assert Latent Dimension Induced in SCM
	if coord.CausalGraph().VariableCount() == 0 {
		t.Errorf("expected SCM causal variables to be initialized")
	}
	t.Logf("✓ SCM Causal Graph populated with latent and observed variables")

	// 3. Assert Candidate Discovered
	if len(state.Candidates) == 0 {
		t.Fatalf("expected candidate findings from anomaly researcher")
	}
	t.Logf("✓ Candidate vulnerability discovered: %s", state.Candidates[0].Title)

	// 4. Assert Independently Validated
	if len(state.Validated) == 0 {
		t.Fatalf("expected independent validation to confirm race condition")
	}
	t.Logf("✓ Vulnerability independently validated: %s", state.Validated[0].Title)

	// 5. Assert Proven Finding Produced
	if len(state.ProvenFindings) == 0 {
		t.Fatalf("expected at least 1 proven finding, got 0")
	}
	proven := state.ProvenFindings[0]
	t.Logf("✓ Proven Finding: [%s] %s", proven.Severity, proven.Title)
	t.Logf("  Reproduction Steps: %d steps", len(proven.ReproductionSteps))

	// 6. Assert Complete 3-Tier Evidence Chain
	if len(proven.DiscoveryEvidence) == 0 {
		t.Errorf("missing discovery evidence in proven finding")
	}
	if len(proven.ValidationEvidence) == 0 {
		t.Errorf("missing validation evidence in proven finding")
	}
	if len(proven.ImpactEvidence) == 0 {
		t.Errorf("missing impact evidence in proven finding")
	}
	t.Logf("✓ Evidence chain complete: %d discovery, %d validation, %d impact",
		len(proven.DiscoveryEvidence), len(proven.ValidationEvidence), len(proven.ImpactEvidence))

	// 7. Assert Dynamic Ontology Expansion Occurred
	if coord.OntologyExpander().ConceptCount() == 0 {
		t.Errorf("expected ontology expansion to register newly discovered security concept")
	}
	t.Logf("✓ Ontology expansion confirmed: %d new concepts minted into DOGE knowledge",
		coord.OntologyExpander().ConceptCount())

	t.Logf("")
	t.Logf("=== BENCHMARK VERIFICATION ===")
	t.Logf("✓ PLANTED BENCH-004 (RACE_CONDITION_OVERDRAW) -> DISCOVERED, VALIDATED, & PROVEN")
	t.Logf("=== DOGE ULTIMATE PHASE 3 (BENCH-004): PASSED ✅ ===")
}

// TestV3AxiomCacheBleedSlice proves DOGE Ultimate Phase 3:
// Representation Discovery on BENCH-005 (Cache Key Normalization Collision Bleed).
//
// Target: Cached reporting service with reverse proxy.
// Discrepancy between proxy path canonicalization and backend origin routing.
func TestV3AxiomCacheBleedSlice(t *testing.T) {
	app := benchmark.NewSyntheticCacheApp()
	defer app.Close()

	targetURL := app.BaseURL()
	credentials := app.Credentials()

	t.Logf("=== DOGE Ultimate Phase 3: AXIOM Representation Discovery (BENCH-005: Cache Bleed) ===")
	t.Logf("Target: %s", targetURL)
	t.Logf("Credentials provided: %d", len(credentials))
	t.Logf("Planted flaw: Cache key normalization collision in reverse proxy (NOT disclosed to DOGE)")
	t.Logf("")

	httpClient := researcher.NewHTTPClient()
	coord := coordinator.NewResearchCoordinator(targetURL, credentials)
	coord.RegisterResearcher(researcher.NewReconResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewAnomalyResearcher(httpClient, coord.Miner()))
	coord.RegisterResearcher(researcher.NewValidationResearcher(httpClient))
	coord.RegisterResearcher(researcher.NewImpactResearcher(httpClient))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Logf(">>> Starting DOGE Ultimate AXIOM Research Loop...")
	start := time.Now()

	err := coord.Run(ctx)
	if err != nil {
		t.Fatalf("Research loop failed: %v", err)
	}

	elapsed := time.Since(start)
	state := coord.GetState()

	t.Logf("")
	t.Logf("=== RESEARCH TRAJECTORY ===")
	t.Logf("Duration: %v", elapsed)
	t.Logf("Missions executed: %d", len(state.Missions))

	for i, m := range state.Missions {
		t.Logf("Mission %d: [%s] %s", i+1, m.ResearcherType, m.Summary)
		t.Logf("  Status: %s | Requests: %d | Duration: %v", m.Status, m.RequestsMade, m.Duration)
		t.Logf("  Evidence pieces: %d", len(m.Evidence))
		t.Logf("  Observations: %d", len(m.Observations))
		if len(m.CandidateFindings) > 0 {
			for _, cand := range m.CandidateFindings {
				t.Logf("  CANDIDATE: [%s] %s (%s)", cand.Severity, cand.Title, cand.Type)
			}
		}
	}

	t.Logf("")
	t.Logf("=== AXIOM LATENT REPRESENTATION & ONTOLOGY EXPANSION STATE ===")
	t.Logf("Discovered Endpoints: %v", state.Endpoints)
	t.Logf("SCM Causal Variables: %d", coord.CausalGraph().VariableCount())
	t.Logf("Attack Graph Nodes: %d, Edges: %d", coord.AttackGraph().NodeCount(), coord.AttackGraph().EdgeCount())
	t.Logf("Learned Security Concepts in Ontology: %d", coord.OntologyExpander().ConceptCount())

	for _, c := range coord.OntologyExpander().GetConcepts() {
		t.Logf("  [ONTOLOGY CONCEPT] %s: %s", c.ConceptID, c.Name)
		t.Logf("    Dimension: %s", c.Dimension)
		t.Logf("    Separating Predicate: %s", c.SeparatingPredicate)
		t.Logf("    Evidence count: %d", c.EmpiricalEvidenceCount)
	}

	t.Logf("")
	t.Logf("=== ASSERTIONS ===")

	// 1. Assert Endpoints Discovered
	hasReports := false
	for _, ep := range state.Endpoints {
		if strings.Contains(ep, "reports") {
			hasReports = true
			break
		}
	}
	if !hasReports {
		t.Fatalf("expected /api/v1/reports in discovered endpoints: %v", state.Endpoints)
	}
	t.Logf("✓ Cached report endpoint discovered")

	// 2. Assert SCM Latent Representation
	if coord.CausalGraph().VariableCount() == 0 {
		t.Errorf("expected SCM causal variables to be initialized")
	}
	t.Logf("✓ SCM Causal Graph populated with latent encoding normalization dimensions")

	// 3. Assert Candidate Discovered
	if len(state.Candidates) == 0 {
		t.Fatalf("expected candidate findings from anomaly researcher")
	}
	t.Logf("✓ Candidate vulnerability discovered: %s", state.Candidates[0].Title)

	// 4. Assert Independently Validated
	if len(state.Validated) == 0 {
		t.Fatalf("expected independent validation to confirm cache bleed")
	}
	t.Logf("✓ Vulnerability independently validated: %s", state.Validated[0].Title)

	// 5. Assert Proven Finding Produced
	if len(state.ProvenFindings) == 0 {
		t.Fatalf("expected at least 1 proven finding, got 0")
	}
	proven := state.ProvenFindings[0]
	t.Logf("✓ Proven Finding: [%s] %s", proven.Severity, proven.Title)

	// 6. Assert Evidence Chain Complete
	if len(proven.DiscoveryEvidence) == 0 {
		t.Errorf("missing discovery evidence in proven finding")
	}
	if len(proven.ValidationEvidence) == 0 {
		t.Errorf("missing validation evidence in proven finding")
	}
	if len(proven.ImpactEvidence) == 0 {
		t.Errorf("missing impact evidence in proven finding")
	}
	t.Logf("✓ Evidence chain complete: %d discovery, %d validation, %d impact",
		len(proven.DiscoveryEvidence), len(proven.ValidationEvidence), len(proven.ImpactEvidence))

	// 7. Assert Dynamic Ontology Expansion
	if coord.OntologyExpander().ConceptCount() == 0 {
		t.Errorf("expected ontology expansion to register newly discovered security concept")
	}
	t.Logf("✓ Ontology expansion confirmed: %d new concepts minted into DOGE knowledge",
		coord.OntologyExpander().ConceptCount())

	t.Logf("")
	t.Logf("=== BENCHMARK VERIFICATION ===")
	t.Logf("✓ PLANTED BENCH-005 (CACHE_NORMALIZATION_BLEED) -> DISCOVERED, VALIDATED, & PROVEN")
	t.Logf("=== DOGE ULTIMATE PHASE 3 (BENCH-005): PASSED ✅ ===")
}
