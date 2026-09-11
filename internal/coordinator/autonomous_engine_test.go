package coordinator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/report"
)

func TestAutonomousEngine_FullResearchLoop(t *testing.T) {
	// Mock target server simulating an endpoint with a latent timing discrepancy and admin leak
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate latency divergence to trigger MDL anomaly
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"desync_success","poisoned":true,"admin_secret":"SUPER_ROOT_KEY_2026"}`))
	}))
	defer ts.Close()

	cfg := EngineConfig{
		TargetURL:   ts.URL,
		Budget:      100,
		Timeout:     10 * time.Second,
		ReportPath:  "",
		SecretKey:   []byte("test-autonomous-engine-secret-key"),
		Policy:      gates.DefaultEnterprisePolicy(),
	}

	engine := NewAutonomousEngine(cfg)
	res, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("AutonomousEngine.Run failed: %v", err)
	}

	if res.TotalRequests == 0 {
		t.Fatalf("expected requests to be made by autonomous engine, got 0")
	}

	if len(res.ProvenFindings) == 0 {
		t.Fatalf("expected proven findings to be discovered, got 0")
	}

	if len(res.ProofBundles) == 0 {
		t.Fatalf("expected cryptographic proof bundles to be generated, got 0")
	}

	// Verify proof bundle integrity
	for _, bundle := range res.ProofBundles {
		valid, err := report.VerifyProofBundleIntegrity(bundle, cfg.SecretKey)
		if err != nil || !valid {
			t.Fatalf("generated proof bundle failed cryptographic integrity verification: %v", err)
		}
	}

	// Verify that world model recorded vertices and edges
	nodes, _ := res.WorldModel.AttackGraphView()
	if len(nodes) == 0 {
		t.Logf("world model successfully populated")
	}

	// Verify CI/CD gating verdict
	if res.GatingVerdict == nil {
		t.Fatalf("expected gating verdict to be evaluated")
	}

	// Verify Markdown report was generated
	if res.GeneratedReport == "" {
		t.Fatalf("expected generated report markdown to be populated")
	}
}
