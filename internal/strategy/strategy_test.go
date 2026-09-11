package strategy

import (
	"testing"
)

func TestStrategyDSLAndTypeCheckerValid(t *testing.T) {
	synthesizer := NewStrategySynthesizer()
	prog := synthesizer.SynthesizeStrategy("http://127.0.0.1:8080/api/v1/wallet", "TemporalConcurrency", false)

	if prog == nil {
		t.Fatalf("expected synthesized program")
	}

	policy := ScopePolicy{
		AllowedHosts: []string{"127.0.0.1", "localhost"},
		MaxCost:      100,
		MaxRisk:      0.5,
	}

	err := TypeCheck(prog, policy)
	if err != nil {
		t.Fatalf("expected strategy to pass typecheck, got: %v", err)
	}

	dslOutput := prog.FormatDSL()
	if dslOutput == "" {
		t.Errorf("expected non-empty DSL output")
	}
	t.Logf("Generated DSL:\n%s", dslOutput)
}

func TestStrategyDSLTypeCheckerRejectsOutOfScope(t *testing.T) {
	synthesizer := NewStrategySynthesizer()
	prog := synthesizer.SynthesizeStrategy("http://malicious-external-target.com/exploit", "TemporalConcurrency", false)

	policy := ScopePolicy{
		AllowedHosts: []string{"127.0.0.1", "api.internal.target"},
		MaxCost:      100,
		MaxRisk:      0.5,
	}

	err := TypeCheck(prog, policy)
	if err == nil {
		t.Fatalf("expected typecheck to reject out-of-scope host")
	}
	t.Logf("Successfully rejected out-of-scope strategy: %v", err)
}

func TestStrategyDSLTypeCheckerRejectsPrematureImpact(t *testing.T) {
	invalidProg := &StrategyProgram{
		ID:           "STRAT_INVALID_IMPACT",
		Name:         "Invalid Premature Impact Strategy",
		TargetDomain: "http://127.0.0.1:8080/test",
		Steps: []StrategyStep{
			{Index: 0, ActionType: ActionRecon, Target: "http://127.0.0.1:8080/test", MaxRequests: 5},
			// Skipped validation! Directly executing impact!
			{Index: 1, ActionType: ActionImpactDemonstration, Target: "http://127.0.0.1:8080/test", MaxRequests: 5},
		},
		RiskScore: 0.2,
	}

	policy := ScopePolicy{
		AllowedHosts: []string{"127.0.0.1"},
		MaxCost:      100,
		MaxRisk:      0.5,
	}

	err := TypeCheck(invalidProg, policy)
	if err == nil {
		t.Fatalf("expected typecheck to reject impact demonstration without prior validation")
	}
	t.Logf("Successfully caught illegal step sequence: %v", err)
}

func TestParetoFrontierSelection(t *testing.T) {
	synthesizer := NewStrategySynthesizer()

	prog1 := synthesizer.SynthesizeStrategy("http://127.0.0.1:8080/ep1", "TemporalConcurrency", false)
	prog2 := synthesizer.SynthesizeStrategy("http://127.0.0.1:8080/ep2", "EncodingNormalization", true)

	frontier := synthesizer.ComputeParetoFrontier()
	if len(frontier) == 0 {
		t.Fatalf("expected non-empty Pareto frontier")
	}

	best := synthesizer.SelectBestFromFrontier()
	if best == nil {
		t.Fatalf("expected best strategy from frontier")
	}

	if best.ID != prog1.ID && best.ID != prog2.ID {
		t.Errorf("expected selected program to be from candidates")
	}
	t.Logf("Selected Best Strategy on Pareto Frontier: %s (Gain=%.2f, Novelty=%.2f, Cost=%.0f)",
		best.ID, best.EstimatedInfoGain, best.NoveltyScore, best.EstimatedCost)
}
