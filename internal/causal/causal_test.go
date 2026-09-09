package causal

import (
	"testing"
)

func TestSCMGraph_InterventionAndDSeparation(t *testing.T) {
	g := NewSCMGraph()

	// Build DAG: RequestTiming -> LatentLockState -> ResponseStatus -> ClientData
	g.AddVariable("req_timing", "Request Timing Delta", VariableObserved, 10)
	g.AddVariable("latent_lock", "Race Window Mutex Lock", VariableLatent, "unlocked")
	g.AddVariable("resp_status", "Response Status", VariableObserved, 200)
	g.AddVariable("client_data", "Client Data Received", VariableObserved, "funds_transferred")

	if err := g.AddEdge("req_timing", "latent_lock", 0.9, "Concurrency timing window"); err != nil {
		t.Fatalf("AddEdge failed: %v", err)
	}
	if err := g.AddEdge("latent_lock", "resp_status", 0.95, "Lock state dictates status"); err != nil {
		t.Fatalf("AddEdge failed: %v", err)
	}
	if err := g.AddEdge("resp_status", "client_data", 0.99, "Status gates data"); err != nil {
		t.Fatalf("AddEdge failed: %v", err)
	}

	if g.VariableCount() != 4 {
		t.Errorf("expected 4 variables, got %d", g.VariableCount())
	}
	if g.EdgeCount() != 3 {
		t.Errorf("expected 3 edges, got %d", g.EdgeCount())
	}

	// Test d-separation: req_timing and resp_status should NOT be d-separated without conditioning
	if g.DSeparated("req_timing", "resp_status", nil) {
		t.Errorf("req_timing and resp_status should be causally connected")
	}

	// When conditioning on latent_lock, req_timing and resp_status should be d-separated
	if !g.DSeparated("req_timing", "resp_status", []string{"latent_lock"}) {
		t.Errorf("req_timing and resp_status should be d-separated when conditioning on latent_lock")
	}

	// Test causal chain extraction
	chain := g.ExtractCausalChain("req_timing", "client_data")
	if len(chain) != 4 {
		t.Errorf("expected chain length 4, got %v", chain)
	}

	// Test Pearl hard intervention: do(latent_lock = "locked")
	// This must sever incoming edge from req_timing to latent_lock
	if err := g.Intervene("latent_lock", "locked"); err != nil {
		t.Fatalf("Intervene failed: %v", err)
	}

	// After intervention, req_timing should now be d-separated from latent_lock even without conditioning!
	if !g.DSeparated("req_timing", "latent_lock", nil) {
		t.Errorf("req_timing and latent_lock must be independent after hard intervention do(latent_lock)")
	}
}

func TestEvaluateCausalSurprise(t *testing.T) {
	// Case 1: Status code 403 Forbidden under baseline, 200 OK under intervened (Authorization boundary shift)
	surprise := EvaluateCausalSurprise(
		403, "{\"error\": \"forbidden\"}", map[string]string{},
		200, "{\"secret\": \"classified-token-xyz\"}", map[string]string{"X-Cache": "HIT"},
		"CacheNormalizationDuality",
	)

	if !surprise.IsSignificant {
		t.Errorf("expected significant surprise on authorization shift")
	}
	if !surprise.ViolatesConfidential {
		t.Errorf("expected confidentiality violation flag")
	}
	if surprise.Magnitude < 0.80 {
		t.Errorf("expected high magnitude >= 0.80, got %.2f", surprise.Magnitude)
	}

	// Case 2: Symmetric non-security noise (both return 200, slightly different length)
	noise := EvaluateCausalSurprise(
		200, "{\"time\": 100}", map[string]string{},
		200, "{\"time\": 101}", map[string]string{},
		"NetworkJitter",
	)

	if noise.IsSignificant {
		t.Errorf("symmetric minor jitter must NOT be flagged as significant surprise")
	}
}
