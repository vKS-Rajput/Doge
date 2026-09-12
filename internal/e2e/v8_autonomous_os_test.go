package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/contradiction"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/director"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/internal/researcher"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
	"github.com/vKS-Rajput/doge/pkg/ai"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// TestV8AutonomousKernelLoop tests the full autonomous cognitive cycle:
// Target -> Observe -> MDL Scan -> Rho Expansion -> Strategy Synthesis -> Sandbox Probe ->
// CEGAR Validation -> Proof Bundle HMAC Attestation -> Enterprise Gate Evaluation.
func TestV8AutonomousKernelLoop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		time.Sleep(45 * time.Millisecond)
		w.Write([]byte(`{"status":"desync_success","poisoned":true,"admin_secret":"SUPER_ROOT_KEY_2026"}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secretKey := []byte("doge-v8-autonomous-kernel-hmac-key-2026")

	cfg := coordinator.EngineConfig{
		TargetURL:   ts.URL,
		Budget:      100,
		Timeout:     5 * time.Second,
		SecretKey:   secretKey,
		Policy:      gates.DefaultEnterprisePolicy(),
		ModelRouter: ai.NewModelRouter("deterministic_brain"),
	}
	cfg.ModelRouter.RegisterProvider(ai.NewDeterministicModel())

	engine := coordinator.NewAutonomousEngine(cfg)
	res, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("AutonomousEngine.Run failed: %v", err)
	}

	if res.TotalRequests == 0 {
		t.Errorf("Expected requests to be issued, got 0")
	}

	if len(res.ProvenFindings) == 0 {
		t.Errorf("Expected proven findings to be discovered on vulnerable target, got 0")
	}

	if len(res.ProofBundles) == 0 {
		t.Errorf("Expected proof bundles to be generated, got 0")
	}

	// Verify cryptographic attestation on generated proof bundles
	for _, bundle := range res.ProofBundles {
		valid, err := report.VerifyProofBundleIntegrity(bundle, secretKey)
		if err != nil || !valid {
			t.Errorf("Proof bundle HMAC verification failed: %v", err)
		}
	}

	if res.GatingVerdict == nil {
		t.Errorf("Expected gating verdict to be evaluated, got nil")
	}

	t.Logf("✓ Autonomous loop verified: %d requests, %d proven findings, %d proof bundles",
		res.TotalRequests, len(res.ProvenFindings), len(res.ProofBundles))
}

// TestV8ContradictionEngineAndCompetingHypotheses proves that observational
// anomalies (e.g. status divergence between identical requests) spawn competing
// hypotheses and guide falsification.
func TestV8ContradictionEngineAndCompetingHypotheses(t *testing.T) {
	cd := contradiction.NewEngine()

	ev1 := domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     "https://target.internal/api/v1/vault",
		RequestMethod:  "GET",
		ResponseStatus: 403,
		ResponseBody:   "{\"error\":\"forbidden\"}",
		ResponseTimeMs: 15,
		CapturedAt:     time.Now().UTC(),
	}

	ev2 := domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     "https://target.internal/api/v1/vault",
		RequestMethod:  "GET",
		ResponseStatus: 200,
		ResponseBody:   "{\"data\":\"secret_vault_keys\"}",
		ResponseTimeMs: 18,
		CapturedAt:     time.Now().UTC().Add(50 * time.Millisecond),
	}

	detected := cd.IngestAndDetect(ev2, []domain.ExperimentEvidence{ev1})
	if len(detected) == 0 {
		t.Fatalf("Expected contradiction detector to detect status code conflict (403 vs 200)")
	}

	contra := detected[0]
	hypotheses := cd.ConvertToHypotheses(contra)
	if len(hypotheses) < 2 {
		t.Fatalf("Expected at least 2 competing hypotheses from contradiction, got %d", len(hypotheses))
	}

	t.Logf("✓ Contradiction engine generated %d competing hypotheses from observational conflict", len(hypotheses))
}

// TestV8EIGUtilityArbitration proves that research director schedules experiments
// maximizing Expected Information Gain (EIG) while penalizing risk and request cost.
func TestV8EIGUtilityArbitration(t *testing.T) {
	highEIG := director.ResearchQuestion{
		ID:                    uuid.New(),
		Question:              "Verify latent race condition window on checkout API",
		TargetEndpoint:        "/api/v1/orders/checkout",
		RecommendedResearcher: domain.ResearcherRace,
		ExpectedInfoGain:      0.92,
		Novelty:               0.85,
		SecurityRelevance:     0.90,
		ImpactPotential:       0.88,
		Cost:                  0.15,
		Risk:                  0.10,
	}

	lowEIGHighRisk := director.ResearchQuestion{
		ID:                    uuid.New(),
		Question:              "Brute-force password field without rate limits",
		TargetEndpoint:        "/api/v1/login",
		RecommendedResearcher: domain.ResearcherRecon,
		ExpectedInfoGain:      0.10,
		Novelty:               0.05,
		SecurityRelevance:     0.20,
		ImpactPotential:       0.30,
		Cost:                  0.80,
		Risk:                  0.95,
	}

	u1 := director.ComputeUtility(&highEIG)
	u2 := director.ComputeUtility(&lowEIGHighRisk)

	if u1 <= u2 {
		t.Errorf("Expected high EIG action utility (%.3f) to exceed low EIG high risk action (%.3f)", u1, u2)
	}

	t.Logf("✓ EIG utility arbitration verified: High-EIG = %.3f vs Low-EIG/High-Risk = %.3f", u1, u2)
}

// TestV8SpecializedResearcherFleetExecution verifies all 14 specialized researchers
// are registered and function under deterministic constraints.
func TestV8SpecializedResearcherFleetExecution(t *testing.T) {
	client := researcher.NewHTTPClient()
	fleet := researcher.NewResearcherFleet(client)

	capabilities := fleet.ListCapabilities()
	if len(capabilities) < 10 {
		t.Fatalf("Expected at least 10 specialized researchers, found %d", len(capabilities))
	}

	expectedTypes := []domain.ResearcherType{
		domain.ResearcherRecon,
		domain.ResearcherAPI,
		domain.ResearcherAuthentication,
		domain.ResearcherAuthorization,
		domain.ResearcherDifferential,
		domain.ResearcherMetamorphic,
		domain.ResearcherRace,
		domain.ResearcherCache,
		domain.ResearcherInjection,
		domain.ResearcherChain,
		domain.ResearcherExploit,
		domain.ResearcherSource,
		domain.ResearcherValidation,
		domain.ResearcherImpact,
	}

	for _, exp := range expectedTypes {
		r := fleet.Get(exp)
		if r == nil {
			t.Errorf("Researcher capability %q is missing from fleet", exp)
		}
	}

	t.Logf("✓ All %d specialized researcher capabilities confirmed active in fleet", len(capabilities))
}

// TestV8WorldModelEpistemicGapDetection verifies that unmapped endpoints and boundaries
// are recognized as research gaps with prioritized uncertainty values.
func TestV8WorldModelEpistemicGapDetection(t *testing.T) {
	wm := worldmodel.NewWorldModel("https://api.cloud.corp")

	_ = wm.RegisterEndpoint(&worldmodel.EndpointModel{
		ID:           uuid.New(),
		Path:         "/api/v1/admin/debug",
		Method:       "POST",
		RequiresAuth: true,
	})

	_ = wm.RegisterPrincipal(&worldmodel.Principal{
		ID:    uuid.New(),
		Name:  "attacker-tenant-user",
		Type:  worldmodel.PrincipalUser,
		Roles: []string{"viewer"},
	})

	gapDetector := worldmodel.NewResearchGapDetector(wm)
	gaps := gapDetector.DetectGaps()

	if len(gaps) == 0 {
		t.Fatalf("Expected epistemic gap detector to find uncharacterized research gaps, found 0")
	}

	for _, g := range gaps {
		if g.Uncertainty <= 0.0 || g.ExpectedInfoGain <= 0.0 {
			t.Errorf("Gap %s has invalid metrics: Uncertainty=%.2f, EIG=%.2f", g.Type, g.Uncertainty, g.ExpectedInfoGain)
		}
	}

	t.Logf("✓ World model epistemic gap detector discovered %d active research gaps", len(gaps))
}
