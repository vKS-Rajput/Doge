package dimension

import (
	"testing"

	"github.com/vKS-Rajput/doge/internal/causal"
)

func TestLatentBasisMiner_InduceDimensions(t *testing.T) {
	miner := NewLatentBasisMiner()

	endpoints := []string{
		"/health",
		"/api/v1/wallet/transfer",
		"/api/v1/reports/public",
		"/api/v1/batch",
	}
	headers := map[string]string{
		"Cache-Control": "max-age=3600",
		"X-Cache":       "MISS",
	}

	dims := miner.InduceDimensions(endpoints, headers)
	if len(dims) != 3 {
		t.Fatalf("expected 3 induced dimensions, got %d", len(dims))
	}

	hasTemporal := false
	hasEncoding := false
	hasPipeline := false

	for _, d := range dims {
		switch d.Type {
		case DimTemporalConcurrency:
			hasTemporal = true
		case DimEncodingNormalization:
			hasEncoding = true
		case DimPipelineInterleaving:
			hasPipeline = true
		}
	}

	if !hasTemporal {
		t.Errorf("expected TemporalConcurrency dimension for wallet endpoint")
	}
	if !hasEncoding {
		t.Errorf("expected EncodingNormalization dimension for cached report endpoint")
	}
	if !hasPipeline {
		t.Errorf("expected PipelineInterleaving dimension for batch endpoint")
	}

	// Test CCS calculation
	surprise := &causal.CausalSurprise{
		Magnitude:            0.85,
		Asymmetry:            0.95,
		ViolatesConfidential: true,
	}

	temporalDim := miner.GetDimension(DimTemporalConcurrency)
	ccs := miner.ComputeContrastiveCausalSensitivity(temporalDim, surprise)
	if ccs < 0.90 {
		t.Errorf("expected high CCS score >= 0.90, got %.2f", ccs)
	}
}
