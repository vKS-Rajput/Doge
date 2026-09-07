package explain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestExplainer_ExplainHypothesis(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope:     []string{"*.example.com", "example.com"},
	})
	if err != nil {
		t.Fatalf("failed to init scope: %v", err)
	}

	hypEngine := hypothesis.NewEngine()

	entities := []domain.Entity{
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "https://api.example.com/v1/users/999",
		},
	}

	hyps := hypEngine.AnalyzeEvidence(context.Background(), entities, nil, nil)
	if len(hyps) == 0 {
		t.Fatalf("expected BOLA hypothesis generated")
	}

	explainer := New(scopeEngine, hypEngine, nil)
	expl, err := explainer.ExplainHypothesis(hyps[0].ID)
	if err != nil {
		t.Fatalf("ExplainHypothesis failed: %v", err)
	}

	if expl.Target != "api.example.com" {
		t.Errorf("expected target api.example.com, got %s", expl.Target)
	}
	if !strings.Contains(expl.SummaryMarkdown, "Epistemic Explanation") {
		t.Errorf("expected markdown explanation to contain header")
	}
	if !strings.Contains(expl.SummaryMarkdown, "Supporting Grounded Evidence") {
		t.Errorf("expected markdown explanation to contain supporting evidence")
	}
}

func TestExplainer_ExplainEntity(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope:     []string{"*.example.com", "example.com"},
	})
	if err != nil {
		t.Fatalf("failed to init scope: %v", err)
	}

	explainer := New(scopeEngine, nil, nil)
	ent := domain.Entity{
		ID:          uuid.New(),
		Type:        domain.EntitySubdomain,
		Value:       "admin.example.com",
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
		Attributes:  make(map[string]any),
	}

	summary := explainer.ExplainEntity(ent, 5)
	if !strings.Contains(summary, "admin.example.com") || !strings.Contains(summary, "in_scope") {
		t.Errorf("unexpected entity summary: %s", summary)
	}
}
