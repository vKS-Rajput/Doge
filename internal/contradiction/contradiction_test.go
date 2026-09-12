package contradiction

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestContradictionEngine_DetectionAndResolution(t *testing.T) {
	engine := NewEngine()

	evA := domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     "http://target.local/api/v1/resource/123",
		RequestMethod:  "GET",
		ResponseStatus: 403,
		ResponseBody:   `{"error":"Forbidden access to resource 123"}`,
		ResponseTimeMs: 15,
		CapturedAt:     time.Now().UTC().Add(-10 * time.Minute),
	}

	evB := domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     "http://target.local/api/v1/resource/123",
		RequestMethod:  "GET",
		ResponseStatus: 200,
		ResponseBody:   `{"data":{"id":123,"secret":"admin_data"}}`,
		ResponseTimeMs: 20,
		CapturedAt:     time.Now().UTC(),
	}

	// Ingest and detect contradictions
	detected := engine.IngestAndDetect(evB, []domain.ExperimentEvidence{evA})
	if len(detected) == 0 {
		t.Fatalf("expected contradiction to be detected for 403 vs 200 conflict")
	}

	c := detected[0]
	t.Logf("✓ Detected Contradiction: %s (Discrepancy: %s)", c.Title, c.Discrepancy)

	if len(c.CandidateExplanations) < 3 {
		t.Errorf("expected at least 3 candidate explanations, got %d", len(c.CandidateExplanations))
	}

	for _, expl := range c.CandidateExplanations {
		t.Logf("  Candidate [%s]: %s (Confidence: %.2f)", expl.Category, expl.Hypothesis, expl.Confidence)
	}

	// Convert contradiction into research hypotheses for research frontier
	hypotheses := engine.ConvertToHypotheses(c)
	if len(hypotheses) == 0 {
		t.Fatalf("expected hypotheses to be generated from contradiction")
	}
	t.Logf("✓ Generated %d research frontier hypotheses from contradiction", len(hypotheses))

	// Resolve the contradiction
	err := engine.Resolve(c.ID, ExplainAuthInconsistency, "Verified that state S2 fails to check tenant binding on resource 123.")
	if err != nil {
		t.Fatalf("failed to resolve contradiction: %v", err)
	}

	if len(engine.GetOpen()) != 0 {
		t.Errorf("expected 0 open contradictions after resolution, got %d", len(engine.GetOpen()))
	}
	t.Logf("✓ Contradiction successfully resolved: %v", *c.ResolvedCategory)
}
