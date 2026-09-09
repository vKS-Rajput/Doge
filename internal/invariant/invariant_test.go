package invariant

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/property"
)

func TestInvariant_MinerAndVerifier(t *testing.T) {
	miner := NewMiner()

	// Feed trace of batch endpoint
	miner.AddTrace(ExecutionTrace{
		ID:             uuid.New(),
		Endpoint:       "/api/v1/batch",
		Method:         "POST",
		ResponseStatus: 200,
		Principal:      "user-alpha-001",
		Timestamp:      time.Now().UTC(),
	})

	invariants := miner.MineInvariants()
	if len(invariants) < 2 {
		t.Fatalf("expected at least 2 induced invariants for batch endpoint, got %d", len(invariants))
	}

	foundIsolation := false
	var isolationInv *Invariant
	for _, inv := range invariants {
		if inv.Type == InvariantContextIsolation {
			foundIsolation = true
			isolationInv = inv
			break
		}
	}

	if !foundIsolation || isolationInv == nil {
		t.Fatal("expected InvariantContextIsolation to be induced")
	}

	t.Logf("Induced Invariant: [%s] %s", isolationInv.Type, isolationInv.Statement)

	// Test Verifier
	verifier := NewVerifier(invariants)
	evidenceID := uuid.New()
	emergentProp, err := verifier.RecordContradiction(
		isolationInv.ID,
		evidenceID,
		"Context bleed detected: unprivileged sub-operation executed with preceding admin rights",
	)
	if err != nil {
		t.Fatalf("failed to record contradiction: %v", err)
	}

	if emergentProp == nil {
		t.Fatal("expected non-nil emergent security property")
	}

	if emergentProp.State != property.StateViolated {
		t.Fatalf("expected StateViolated, got %s", emergentProp.State)
	}

	if len(verifier.ViolatedInvariants()) != 1 {
		t.Fatalf("expected 1 violated invariant, got %d", len(verifier.ViolatedInvariants()))
	}
}
