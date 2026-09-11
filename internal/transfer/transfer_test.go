package transfer

import (
	"testing"

	"github.com/vKS-Rajput/doge/internal/strategy"
)

func TestCrossTargetStructuralIsomorphismAndTransfer(t *testing.T) {
	// 1. Target A: Financial Wallet Transfer (BENCH-004)
	graphWallet := NewAbstractRelationalGraph("target_wallet_app")
	graphWallet.AddNode("wallet_actor", RoleUnprivilegedActor, "user_account")
	graphWallet.AddNode("wallet_guard", RoleStateGuard, "balance_check")
	graphWallet.AddNode("wallet_async", RoleAsyncExecution, "async_transfer_goroutine")
	graphWallet.AddNode("wallet_asset", RoleResourceAsset, "financial_balance")

	graphWallet.AddEdge("wallet_actor", "wallet_guard", CausalBypasses)
	graphWallet.AddEdge("wallet_guard", "wallet_async", CausalRacesWith)
	graphWallet.AddEdge("wallet_async", "wallet_asset", CausalMutates)

	// Strategy synthesized on Target A
	synthesizer := strategy.NewStrategySynthesizer()
	strategyA := synthesizer.SynthesizeStrategy("http://127.0.0.1:8001/api/v1/wallet/transfer", "TemporalConcurrency", false)

	// Store experience in TransferEngine
	engine := NewTransferEngine()
	engine.StoreExperience(
		"CONCEPT_LATENT_RACE_WINDOW",
		"TemporalConcurrency",
		graphWallet,
		strategyA,
	)

	// 2. Target B: IoT Medical Device Telemetry Gateway (BENCH-007)
	// Completely different domain, different routes, different terms
	graphIoT := NewAbstractRelationalGraph("target_iot_medical")
	graphIoT.AddNode("iot_client", RoleUnprivilegedActor, "device_client")
	graphIoT.AddNode("iot_guard", RoleStateGuard, "checksum_calibration_guard")
	graphIoT.AddNode("iot_async", RoleAsyncExecution, "firmware_flash_async")
	graphIoT.AddNode("iot_asset", RoleResourceAsset, "calibration_register")

	graphIoT.AddEdge("iot_client", "iot_guard", CausalBypasses)
	graphIoT.AddEdge("iot_guard", "iot_async", CausalRacesWith)
	graphIoT.AddEdge("iot_async", "iot_asset", CausalMutates)

	// 3. Test Structural Isomorphism: G_wallet =~= G_iot
	isoScore := IsomorphismScore(graphWallet, graphIoT)
	t.Logf("Structural Isomorphism Score G_wallet =~= G_iot: %.2f", isoScore)

	if isoScore < 0.90 {
		t.Fatalf("expected isomorphism score >= 0.90, got %.2f", isoScore)
	}

	if !IsStructurallyIsomorphic(graphWallet, graphIoT, 0.85) {
		t.Fatalf("expected IsStructurallyIsomorphic to return true")
	}

	// 4. Test Finding Matching Experience
	matchedExp, matchScore := engine.FindMatchingExperience(graphIoT, 0.80)
	if matchedExp == nil {
		t.Fatalf("expected matched experience for Target B")
	}
	t.Logf("Successfully retrieved isomorphic experience: %s (score=%.2f)", matchedExp.ConceptID, matchScore)

	// 5. Test Strategy Transfer to Target B
	iotEndpoints := map[string]string{
		"calibration": "http://127.0.0.1:8002/api/v1/telemetry/device/dev_123/calibrate",
	}

	transferredProg, err := engine.TransferStrategy(matchedExp, graphIoT, iotEndpoints, "http://127.0.0.1:8002")
	if err != nil {
		t.Fatalf("failed to transfer strategy: %v", err)
	}

	if transferredProg.TargetDomain != iotEndpoints["calibration"] {
		t.Errorf("expected target domain %s, got %s", iotEndpoints["calibration"], transferredProg.TargetDomain)
	}

	// Verify ZERO URL leakage from Target A into transferred strategy
	for _, step := range transferredProg.Steps {
		if step.Target == "http://127.0.0.1:8001/api/v1/wallet/transfer" {
			t.Fatalf("CRITICAL: Detected URL leakage from Target A into transferred strategy step!")
		}
	}

	// 6. Verify Transferred Strategy passes static type checking on Target B
	policyB := strategy.ScopePolicy{
		AllowedHosts: []string{"127.0.0.1"},
		MaxCost:      100,
		MaxRisk:      0.50,
	}

	err = strategy.TypeCheck(transferredProg, policyB)
	if err != nil {
		t.Fatalf("transferred strategy failed type checking: %v", err)
	}

	t.Logf("Transferred Strategy Validated: %s (Total Requests: %d, Gain: %.2f)",
		transferredProg.ID, transferredProg.TotalRequests(), transferredProg.EstimatedInfoGain)
}
