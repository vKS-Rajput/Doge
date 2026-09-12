package reasoning

import (
	"context"
	"testing"
)

func TestEnsembleCouncil(t *testing.T) {
	council := NewEnsembleCouncil()
	specs := council.GetSpecialists()
	if len(specs) != 6 {
		t.Fatalf("expected 6 specialist divisions, got %d", len(specs))
	}

	delib := council.Deliberate(context.Background(), "https://example.com/api", "StructuralInvariantDivergence", 0.92)
	if delib == nil {
		t.Fatal("expected deliberation output, got nil")
	}

	if !delib.RequiresHumanGate {
		t.Errorf("expected high anomaly score with structural divergence to require human gate")
	}

	if delib.ConsensusScore < 0.85 {
		t.Errorf("expected high consensus score, got %.2f", delib.ConsensusScore)
	}

	if len(delib.AgreedHypotheses) == 0 {
		t.Errorf("expected agreed hypotheses from deliberation")
	}
}
