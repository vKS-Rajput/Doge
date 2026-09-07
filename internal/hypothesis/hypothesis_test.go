package hypothesis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestHypothesisEngine_EvidenceAnalysis(t *testing.T) {
	engine := NewEngine()

	entities := []domain.Entity{
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "/api/v1/users/12345",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "/admin/dashboard",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityParameter,
			Value: "webhook_url",
			Attributes: map[string]any{
				"host": "api.example.com",
			},
		},
	}

	observations := []domain.Observation{
		{
			ID:         uuid.New(),
			Type:       domain.ObservationAuthProbe,
			SourceTool: "httpx",
			RawValue:   "Authorization: Bearer eyJhbGciOi...",
			ObservedAt: time.Now().UTC(),
		},
		{
			ID:         uuid.New(),
			Type:       domain.ObservationEndpointDiscovery,
			SourceTool: "kxss",
			RawValue:   "URL: https://api.example.com/search?q=test Param: q",
			Data: map[string]any{
				"reflection": true,
			},
			ObservedAt: time.Now().UTC(),
		},
	}

	hyps := engine.AnalyzeEvidence(context.Background(), entities, nil, observations)
	if len(hyps) < 3 {
		t.Fatalf("expected at least 3 hypotheses generated, got %d", len(hyps))
	}

	// Verify categories generated
	categories := make(map[Category]bool)
	for _, h := range hyps {
		categories[h.Category] = true
		if h.Tier != TierHypothesis {
			t.Errorf("expected new hypothesis to start in TierHypothesis, got %s", h.Tier)
		}
		if h.Status != StatusUnvalidated && h.Status != StatusPlausible {
			t.Errorf("expected status UNVALIDATED/PLAUSIBLE, got %s", h.Status)
		}
	}

	if !categories[CatBOLA] {
		t.Errorf("expected BOLA hypothesis from /api/v1/users/12345")
	}
	if !categories[CatAuthBoundary] {
		t.Errorf("expected AuthBoundary hypothesis from /admin/dashboard")
	}
	if !categories[CatSSRF] {
		t.Errorf("expected SSRF hypothesis from webhook_url parameter")
	}
}

func TestHypothesis_ConfidenceLifecycle(t *testing.T) {
	h := &ResearchHypothesis{
		ID:         uuid.New(),
		Confidence: 0.60,
		Status:     StatusUnvalidated,
	}

	// Decay over evaluations with no new evidence
	h.RecalculateConfidence(false)
	if h.Confidence >= 0.60 {
		t.Errorf("expected confidence decay, got %f", h.Confidence)
	}

	// Strengthen on new evidence
	h.RecalculateConfidence(true)
	if h.Confidence <= 0.56 {
		t.Errorf("expected confidence increase with new evidence, got %f", h.Confidence)
	}

	// Contradiction penalty
	h.ContradictionCount = 2
	h.RecalculateConfidence(false)
	if h.Confidence > 0.40 {
		t.Errorf("expected significant drop on contradictions, got %f", h.Confidence)
	}
}
