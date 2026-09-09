package learning

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

func TestLayeredMemoryHierarchy_WorkingAndEpisodic(t *testing.T) {
	wm := worldmodel.NewWorldModel("app.target.com")
	lm := NewLayeredMemoryHierarchy(wm, nil)

	hyp := &hypothesis.ResearchHypothesis{
		ID:         uuid.New(),
		Title:      "BOLA on /api/users/123",
		Target:     "app.target.com",
		Tier:       hypothesis.TierHypothesis,
		Status:     hypothesis.StatusUnvalidated,
		Category:   hypothesis.CatBOLA,
		Confidence: 0.60,
	}

	actionID := uuid.New()
	lm.UpdateWorkingMemory(1, hyp, actionID, "Test BOLA Cross-Tenant", "https://app.target.com/api/users/123", nil)

	if lm.Working.IterationIndex != 1 || lm.Working.ActiveHypothesis.Title != hyp.Title {
		t.Errorf("working memory not updated properly")
	}

	// Record step execution
	statusRejected := hypothesis.StatusRejected
	entry := lm.RecordStepExecution(
		1,
		"Test BOLA Cross-Tenant",
		"bola_differential",
		"https://app.target.com/api/users/123",
		hyp,
		false,
		&statusRejected,
		-0.60,
		"Tenant 403 Forbidden received",
		"HTTP/1.1 403 Forbidden",
		"",
		0,
	)

	if entry == nil {
		t.Fatalf("expected episodic entry returned")
	}

	if len(lm.Episodic) != 1 {
		t.Fatalf("expected 1 episodic memory entry, got %d", len(lm.Episodic))
	}

	// Verify procedural adjustment
	eff := lm.Procedural.ToolEffectiveness["bola_differential"]
	if eff >= 0 {
		t.Errorf("expected negative procedural effectiveness for failed tool, got %f", eff)
	}

	t.Logf("✓ Verified Layered Memory Working & Episodic layers (Procedural penalty: %.2f)", eff)
}

func TestFailureSignature_ClassifyAndAvoidRepetition(t *testing.T) {
	wm := worldmodel.NewWorldModel("app.target.com")
	lm := NewLayeredMemoryHierarchy(wm, nil)

	endpoint := "https://app.target.com/api/v1/internal/data"
	actionType := "admin_access_probe"

	// 1. Classify failure from 403 Forbidden
	sig := ClassifyFailureMode(actionType, endpoint, 403, "HTTP/1.1 403 Forbidden\nAccess Denied", "")
	if sig == nil {
		t.Fatalf("expected failure signature classified")
	}

	if sig.FailureMode != FailureModeTenantAccessDenied {
		t.Errorf("expected FailureModeTenantAccessDenied, got %s", sig.FailureMode)
	}

	// 2. Record signature in Layered Memory
	lm.RecordFailureSignature(sig)

	// 3. Check for existence before executing next action
	retrievedSig, exists := lm.HasFailedActionSignature(actionType, endpoint)
	if !exists || retrievedSig == nil {
		t.Fatalf("expected failure signature to be found in procedural memory")
	}

	if retrievedSig.PenaltyFactor >= 0.0 {
		t.Errorf("expected penalty factor < 0, got %f", retrievedSig.PenaltyFactor)
	}

	t.Logf("✓ Verified Failure Signature: %s (Penalty: %.2f, Reason: %s)", retrievedSig.FailureMode, retrievedSig.PenaltyFactor, retrievedSig.Reason)
}
