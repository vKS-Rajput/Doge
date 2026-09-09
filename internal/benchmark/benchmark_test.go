package benchmark

import (
	"context"
	"testing"
	"time"
)

func TestAdversarialBenchmarkSuite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	suite := DefaultBenchmarkSuite()
	if len(suite) < 3 {
		t.Fatalf("expected at least 3 benchmark scenarios, got %d", len(suite))
	}

	runner := NewRunner()
	scorecard, err := runner.RunSuite(ctx, suite)
	if err != nil {
		t.Fatalf("failed to run benchmark suite: %v", err)
	}

	t.Logf("=== BENCHMARK SCORECARD ===")
	t.Logf("Total Scenarios:      %d", scorecard.TotalScenarios)
	t.Logf("Passed Scenarios:     %d", scorecard.PassedScenarios)
	t.Logf("Failed Scenarios:     %d", scorecard.FailedScenarios)
	t.Logf("Pass Rate:            %.1f%%", scorecard.PassRatePercent)
	t.Logf("Distractors Refuted:  %d/%d (%.1f%%)", scorecard.FalsifiedDistractors, scorecard.TotalDistractors, scorecard.FalsificationRate)
	t.Logf("Average Iterations:   %.1f", scorecard.AverageIterations)

	for _, res := range scorecard.ScenarioResults {
		t.Logf("  Scenario [%s]: Passed=%v Iterations=%d/%d Notes=%s", res.ScenarioID, res.Passed, res.IterationsUsed, res.MaxAllowedIter, res.Notes)
	}

	if scorecard.PassedScenarios < scorecard.TotalScenarios {
		t.Errorf("expected 100%% benchmark pass rate, got %d/%d", scorecard.PassedScenarios, scorecard.TotalScenarios)
	}

	t.Log("✓ Verified Adversarial Research Benchmark Suite successfully")
}
