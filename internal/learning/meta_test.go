package learning

import (
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/strategy"
)

func TestMetaLearnerCreditAndRecombination(t *testing.T) {
	ml := NewMetaLearner()
	synthesizer := strategy.NewStrategySynthesizer()

	parentA := synthesizer.SynthesizeStrategy("http://127.0.0.1:8080/api/v1/wallet", "TemporalConcurrency", false)
	parentB := synthesizer.SynthesizeStrategy("http://127.0.0.1:8080/api/v1/reports", "EncodingNormalization", true)

	// Initial credit for CausalIntervention
	initialCredit := ml.GetActionCredit(strategy.ActionCausalIntervention)

	// Record successful evaluation for parentA
	evalA := StrategyEvaluation{
		StrategyID:          parentA.ID,
		Target:              parentA.TargetDomain,
		FindingsCount:       1,
		TotalRequestsIssued: 45,
		ExecutionDurationMs: 120,
		NoveltyYield:        0.90,
		CompletedAt:         time.Now().UTC(),
	}

	ml.RecordOutcome(parentA, evalA)

	newCredit := ml.GetActionCredit(strategy.ActionCausalIntervention)
	if newCredit <= initialCredit {
		t.Errorf("expected credit reinforcement for ActionCausalIntervention, got %.2f -> %.2f", initialCredit, newCredit)
	}

	// Verify parentA added to elites
	elite, ok := ml.GetElite("TemporalConcurrency")
	if !ok || elite == nil {
		t.Fatalf("expected elite for TemporalConcurrency")
	}

	if elite.ID != parentA.ID {
		t.Errorf("expected elite to be parentA")
	}

	// Test Recombination
	offspring := ml.RecombineStrategies(parentA, parentB, "http://127.0.0.1:8080/api/v1/telemetry")
	if offspring == nil {
		t.Fatalf("expected non-nil recombined strategy")
	}

	if len(offspring.Steps) < 4 {
		t.Errorf("expected at least 4 steps in recombined strategy, got %d", len(offspring.Steps))
	}

	t.Logf("Recombined Strategy Created: %s (Steps: %d, Gain: %.2f, Risk: %.2f)",
		offspring.ID, len(offspring.Steps), offspring.EstimatedInfoGain, offspring.RiskScore)
}
