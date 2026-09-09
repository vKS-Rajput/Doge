package synthesis

import (
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/internal/causal"
	"github.com/vKS-Rajput/doge/internal/dimension"
)

func TestCEGARSynthesizer_Synthesize(t *testing.T) {
	synthesizer := NewCEGARSynthesizer()

	// 1. Test Temporal Concurrency predicate synthesis
	tempDim := &dimension.Dimension{
		Type: dimension.DimTemporalConcurrency,
		Name: "Temporal Concurrency Interleaving",
	}
	surprise := &causal.CausalSurprise{
		Dimension:     "Temporal Concurrency Interleaving",
		Magnitude:     0.9,
		IsSignificant: true,
	}

	pred1 := synthesizer.Synthesize(tempDim, "/api/v1/wallet/transfer", surprise, map[string]any{"window_ms": 35})
	if !strings.Contains(pred1.Formula, "Delta_t < 35ms") {
		t.Errorf("expected formula to contain 'Delta_t < 35ms', got: %s", pred1.Formula)
	}
	if len(pred1.Reproduction) < 4 {
		t.Errorf("expected detailed reproduction steps, got %d", len(pred1.Reproduction))
	}

	// 2. Test Encoding Normalization predicate synthesis
	encDim := &dimension.Dimension{
		Type: dimension.DimEncodingNormalization,
		Name: "URI Path Normalization Duality",
	}
	pred2 := synthesizer.Synthesize(encDim, "/api/v1/reports", surprise, map[string]any{"encoding": "..%2F"})
	if !strings.Contains(pred2.Formula, "CONTAINS '..%2F'") {
		t.Errorf("expected formula to contain traversal encoding constraint, got: %s", pred2.Formula)
	}
}
