package planner

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestPlanner_AdaptiveProgression(t *testing.T) {
	scopeEngine, err := scope.NewEngine(scope.Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope:     []string{"*.example.com", "example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	p := NewPlanner(scopeEngine, "example.com", "authorized")

	// 1. Initial Plan should generate passive recon actions
	actions := p.AdaptPlan(nil, nil)
	if len(actions) == 0 {
		t.Fatalf("expected initial passive recon actions, got 0")
	}

	foundSubfinder := false
	for _, a := range actions {
		if a.Tool == "subfinder" {
			foundSubfinder = true
			if a.Phase != PhasePassiveRecon {
				t.Errorf("expected phase %s, got %s", PhasePassiveRecon, a.Phase)
			}
		}
	}
	if !foundSubfinder {
		t.Errorf("expected subfinder in planned actions")
	}

	// 2. Discover subdomains & entities -> Adapt plan
	entities := []domain.Entity{
		{
			ID:    uuid.New(),
			Type:  domain.EntitySubdomain,
			Value: "api.example.com",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityURL,
			Value: "https://api.example.com/v1",
		},
	}

	hyps := []*hypothesis.ResearchHypothesis{
		{
			ID:         uuid.New(),
			Title:      "BOLA on User Endpoint",
			Category:   hypothesis.CatBOLA,
			Target:     "https://api.example.com/v1/users/1",
			Status:     hypothesis.StatusUnvalidated,
			Confidence: 0.65,
		},
	}

	nextActions := p.AdaptPlan(entities, hyps)
	if len(nextActions) == 0 {
		t.Fatalf("expected next actions from discovered entities, got 0")
	}

	foundHypothesisAction := false
	for _, a := range nextActions {
		if a.HypothesisID != nil && *a.HypothesisID == hyps[0].ID {
			foundHypothesisAction = true
			if a.Phase != PhaseHypothesisTesting {
				t.Errorf("expected hypothesis testing phase, got %s", a.Phase)
			}
		}
	}
	if !foundHypothesisAction {
		t.Errorf("expected targeted validation action for BOLA hypothesis")
	}

	// 3. Mark action completed
	plan := p.GetPlan()
	if len(plan.PlannedActions) == 0 {
		t.Fatalf("expected planned actions in plan")
	}
	actionID := plan.PlannedActions[0].ID
	p.MarkActionCompleted(actionID, "completed")

	updatedPlan := p.GetPlan()
	if len(updatedPlan.CompletedActions) != 1 {
		t.Errorf("expected 1 completed action, got %d", len(updatedPlan.CompletedActions))
	}
}
