package dimension

import (
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/internal/causal"
)

// LatentBasisMiner mines latent dimensions of target behavior from reconnaissance observations.
type LatentBasisMiner struct {
	discoveredDimensions map[DimensionType]*Dimension
}

// NewLatentBasisMiner creates a new latent behavioral dimension miner.
func NewLatentBasisMiner() *LatentBasisMiner {
	return &LatentBasisMiner{
		discoveredDimensions: make(map[DimensionType]*Dimension),
	}
}

// InduceDimensions analyzes endpoints, headers, and schemas to discover latent dimensions.
func (m *LatentBasisMiner) InduceDimensions(endpoints []string, headers map[string]string) []*Dimension {
	var induced []*Dimension

	hasStateMutation := false
	hasCaching := false
	hasBatch := false

	// Check response headers for caching hints
	for k := range headers {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "cache") || lowerK == "age" || lowerK == "etag" {
			hasCaching = true
		}
	}

	// Analyze endpoint semantics
	for _, ep := range endpoints {
		lowerEP := strings.ToLower(ep)
		if strings.Contains(lowerEP, "wallet") ||
			strings.Contains(lowerEP, "transfer") ||
			strings.Contains(lowerEP, "pay") ||
			strings.Contains(lowerEP, "balance") ||
			strings.Contains(lowerEP, "checkout") {
			hasStateMutation = true
		}
		if strings.Contains(lowerEP, "report") ||
			strings.Contains(lowerEP, "public") ||
			strings.Contains(lowerEP, "private") ||
			strings.Contains(lowerEP, "static") {
			hasCaching = true
		}
		if strings.Contains(lowerEP, "batch") || strings.Contains(lowerEP, "pipeline") {
			hasBatch = true
		}
	}

	// 1. Induce Temporal Concurrency Dimension
	if hasStateMutation {
		dim := &Dimension{
			Type:         DimTemporalConcurrency,
			Name:         "Temporal Concurrency Interleaving",
			Description:  "Sub-millisecond packet interleaving to probe asynchronous lock/check race windows",
			Sensitivity:  0.85,
			Confidence:   0.80,
			DiscoveredAt: time.Now().UTC(),
			Parameters: map[string]any{
				"window_ms":      40,
				"burst_size":     2,
				"sync_mechanism": "goroutine_barrier",
			},
		}
		m.discoveredDimensions[DimTemporalConcurrency] = dim
		induced = append(induced, dim)
	}

	// 2. Induce Encoding Normalization Dimension
	if hasCaching {
		dim := &Dimension{
			Type:         DimEncodingNormalization,
			Name:         "URI Path Normalization Duality",
			Description:  "Evaluation of path canonicalization divergence between edge cache proxy and origin backend",
			Sensitivity:  0.80,
			Confidence:   0.75,
			DiscoveredAt: time.Now().UTC(),
			Parameters: map[string]any{
				"encodings": []string{"..%2F", "%2e%2e%2f", "%2e%2e/", "..;/"},
				"probe_header": "X-Cache",
			},
		}
		m.discoveredDimensions[DimEncodingNormalization] = dim
		induced = append(induced, dim)
	}

	// 3. Induce Pipeline Interleaving Dimension
	if hasBatch {
		dim := &Dimension{
			Type:         DimPipelineInterleaving,
			Name:         "Batch Execution Context Commutativity",
			Description:  "Order permutation of heterogeneous operations inside single pipeline requests",
			Sensitivity:  0.85,
			Confidence:   0.85,
			DiscoveredAt: time.Now().UTC(),
			Parameters: map[string]any{
				"invert_order": true,
				"cross_tenant": true,
			},
		}
		m.discoveredDimensions[DimPipelineInterleaving] = dim
		induced = append(induced, dim)
	}

	return induced
}

// ComputeContrastiveCausalSensitivity evaluates the sensitivity score along a dimension
// using the empirical surprise measured by the SCM causal engine.
func (m *LatentBasisMiner) ComputeContrastiveCausalSensitivity(dim *Dimension, surprise *causal.CausalSurprise) float64 {
	if surprise == nil {
		return 0.0
	}

	// CCS(d) = Magnitude * Asymmetry
	// Symmetrical jitter (asymmetry ~ 0) scales to 0
	ccs := surprise.Magnitude * surprise.Asymmetry
	if surprise.ViolatesConfidential || surprise.ViolatesIntegrity {
		ccs += 0.20 // Security boundary bonus
	}
	if ccs > 1.0 {
		ccs = 1.0
	}

	dim.Sensitivity = ccs
	return ccs
}

// GetDimension returns a previously discovered dimension if present.
func (m *LatentBasisMiner) GetDimension(dimType DimensionType) *Dimension {
	return m.discoveredDimensions[dimType]
}
