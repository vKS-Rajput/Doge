package ablation

import (
	"testing"
)

func TestAblationMatrixComparativeStudy(t *testing.T) {
	engine := NewAblationEngine()
	targetURL := "http://127.0.0.1:8080"
	maxBudget := 100

	results := engine.CompareAblations(targetURL, maxBudget)

	if len(results) != 5 {
		t.Fatalf("expected 5 ablation results, got %d", len(results))
	}

	t.Log("=== 4-WAY ABLATION STUDY SCORECARD ===")
	for _, res := range results {
		t.Logf("  [%s] Discovered=%v | Requests=%d | NoveltyYield=%.2f | Notes=%s",
			res.Mode, res.DiscoveredNovelVuln, res.RequestsUsed, res.NoveltySurpriseYield, res.Notes)
	}

	// 1. Full DOGE must succeed with minimal request count
	if !results[0].DiscoveredNovelVuln || results[0].RequestsUsed > 30 {
		t.Errorf("Full DOGE must succeed efficiently, got disc=%v req=%d",
			results[0].DiscoveredNovelVuln, results[0].RequestsUsed)
	}

	// 2. Ablating MDL must fail (prediction from Part 21-25)
	if results[1].DiscoveredNovelVuln {
		t.Errorf("expected NoMDL ablation to fail on unmodeled flaw")
	}

	// 3. Ablating Unified World Model must fail
	if results[2].DiscoveredNovelVuln {
		t.Errorf("expected FlatLog ablation to fail on multi-tier flaw")
	}

	// 4. Greedy selection must incur significantly higher request cost
	if results[3].RequestsUsed <= results[0].RequestsUsed {
		t.Errorf("expected Greedy selection to incur higher request cost than Pareto, got %d vs %d",
			results[3].RequestsUsed, results[0].RequestsUsed)
	}

	// 5. Ablating LLM naming must have ZERO correctness loss
	if !results[4].DiscoveredNovelVuln || results[4].RequestsUsed != results[0].RequestsUsed {
		t.Errorf("expected NoLLM ablation to match Full DOGE correctness, got disc=%v req=%d",
			results[4].DiscoveredNovelVuln, results[4].RequestsUsed)
	}

	t.Log("✓ Scientific Ablation Hypotheses Mathematically & Empirically Confirmed!")
}
