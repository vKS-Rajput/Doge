package hypothesis

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestCompetingHypothesesURLIngestion(t *testing.T) {
	obs := domain.Observation{
		ID:         uuid.New(),
		Type:       domain.ObservationEndpointDiscovery,
		SourceTool: "katana",
		RawValue:   "webhook_url",
		ObservedAt: time.Now().UTC(),
	}

	cluster := GenerateCompetingHypotheses("api.target.com", obs)
	if cluster == nil {
		t.Fatalf("expected competing cluster for URL parameter observation, got nil")
	}

	if len(cluster.Hypotheses) != 5 {
		t.Fatalf("expected 5 competing hypotheses for URL ingestion, got %d", len(cluster.Hypotheses))
	}

	expectedCategories := []Category{CatSSRF, CatOpenRedirect, CatClientSideURL, CatAuthBoundary, CatInformationLeak}
	for i, cat := range expectedCategories {
		if cluster.Hypotheses[i].Category != cat {
			t.Errorf("hypothesis %d: expected category %s, got %s", i, cat, cluster.Hypotheses[i].Category)
		}
	}

	if len(cluster.DiscriminatingExperiments) == 0 {
		t.Errorf("expected discriminating experiments generated for competing cluster")
	}

	t.Logf("✓ Generated %d competing hypotheses for %s:", len(cluster.Hypotheses), obs.RawValue)
	for _, h := range cluster.Hypotheses {
		t.Logf("  - [%s] %s (Conf: %.2f)", h.Category, h.Title, h.Confidence)
	}

	t.Logf("✓ Generated %d discriminating experiments:", len(cluster.DiscriminatingExperiments))
	for _, exp := range cluster.DiscriminatingExperiments {
		t.Logf("  - %s: %s", exp.Title, exp.Command)
	}
}

func TestEpistemicTransitionsAndHistory(t *testing.T) {
	hyp := &ResearchHypothesis{
		ID:         uuid.New(),
		Title:      "BOLA on /api/users/123",
		Target:     "app.target.com",
		Tier:       TierHypothesis,
		Status:     StatusUnvalidated,
		Category:   CatBOLA,
		Confidence: 0.50,
	}

	// 1. Initial State
	if len(hyp.ConfidenceHistory) != 0 {
		t.Errorf("expected empty confidence history initially")
	}

	// 2. Transition to PLAUSIBLE
	hyp.Transition(StatusPlausible, TierHypothesis, 0.65, "Discovered multi-tenant path pattern with predictable integer ID")
	if hyp.Status != StatusPlausible || hyp.Confidence != 0.65 {
		t.Errorf("transition failed: status=%s, conf=%.2f", hyp.Status, hyp.Confidence)
	}
	if len(hyp.ConfidenceHistory) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hyp.ConfidenceHistory))
	}

	// 3. Transition to CANDIDATE_FINDING (SUPPORTED)
	hyp.Transition(StatusSupported, TierCandidateFinding, 0.85, "Cross-principal request returned HTTP 200 with object payload")
	if hyp.Status != StatusSupported || hyp.Tier != TierCandidateFinding {
		t.Errorf("transition failed: status=%s, tier=%s", hyp.Status, hyp.Tier)
	}

	// 4. Transition to VALIDATED_FINDING (CONFIRMED)
	hyp.Transition(StatusConfirmed, TierValidatedFinding, 1.0, "Verified full PII disclosure across distinct tenant boundary")
	if hyp.Status != StatusConfirmed || hyp.Tier != TierValidatedFinding || hyp.ConfirmedAt == nil {
		t.Errorf("confirmation transition failed")
	}
	if len(hyp.ConfidenceHistory) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(hyp.ConfidenceHistory))
	}

	t.Logf("✓ Epistemic transitions verified through %d history stages", len(hyp.ConfidenceHistory))
	for i, entry := range hyp.ConfidenceHistory {
		t.Logf("  Stage %d: [%s/%s] %.2f -> %.2f (Reason: %s)", i+1, entry.EpistemicStatus, entry.EpistemicTier, entry.OldConfidence, entry.NewConfidence, entry.Reason)
	}
}

func TestFalsificationAndRefutationEvaluation(t *testing.T) {
	hyp := &ResearchHypothesis{
		ID:         uuid.New(),
		Title:      "BOLA on /api/orders/99",
		Target:     "app.target.com",
		Tier:       TierHypothesis,
		Status:     StatusUnvalidated,
		Category:   CatBOLA,
		Confidence: 0.60,
	}

	// Case 1: Server rejects cross-tenant request with 403 Forbidden -> Falsifies BOLA
	res := EvaluateExecution(hyp, "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"error\": \"access denied to tenant object\"}", "", 0)

	if !res.IsFalsified {
		t.Errorf("expected hypothesis to be falsified on 403 Forbidden")
	}
	if hyp.Status != StatusRejected || hyp.Confidence != 0.0 {
		t.Errorf("expected status REJECTED and confidence 0.0, got status=%s, conf=%.2f", hyp.Status, hyp.Confidence)
	}
	if hyp.RejectedAt == nil {
		t.Errorf("expected RejectedAt timestamp to be set")
	}

	t.Logf("✓ Falsification verified: %s (Status: %s, Conf: %.2f)", res.Reason, hyp.Status, hyp.Confidence)
}
