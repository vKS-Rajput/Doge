package dimension

import (
	"fmt"
	"time"
)

// DimensionType identifies the behavioral dimension category.
type DimensionType string

const (
	DimTemporalConcurrency   DimensionType = "temporal_concurrency"   // Asynchronous race windows & timing interleaving
	DimEncodingNormalization DimensionType = "encoding_normalization" // Path normalization, dot-slash canonicalization, cache keys
	DimSerializationDuality  DimensionType = "serialization_duality"  // Duplicate keys, parser differential, JSON vs query
	DimPipelineInterleaving  DimensionType = "pipeline_interleaving"  // Batch order inversion & cross-frame context retention
	DimIdempotencyReplay     DimensionType = "idempotency_replay"     // Replaying unique transaction keys across identities
)

// Dimension represents an induced latent dimension of software behavior.
type Dimension struct {
	Type          DimensionType  `json:"type"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Sensitivity   float64        `json:"sensitivity"`   // Causal sensitivity score [0.0, 1.0]
	Confidence    float64        `json:"confidence"`    // Epistemic certainty
	DiscoveredAt  time.Time      `json:"discovered_at"`
	Parameters    map[string]any `json:"parameters,omitempty"` // Dimension-specific knobs (e.g. window_ms, encodings)
}

// ProbedCoordinate represents a point tested along a behavioral dimension.
type ProbedCoordinate struct {
	DimensionName string `json:"dimension_name"`
	Value         any    `json:"value"`
	ResultStatus  int    `json:"result_status"`
	OutcomeDelta  string `json:"outcome_delta"`
}

// FormatCoordinate provides a readable summary of the probed dimension state.
func (c *ProbedCoordinate) FormatCoordinate() string {
	return fmt.Sprintf("[%s = %v] -> status %d (%s)", c.DimensionName, c.Value, c.ResultStatus, c.OutcomeDelta)
}
