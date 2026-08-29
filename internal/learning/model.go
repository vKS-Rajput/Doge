// Package learning implements Adaptive Evidence-Based Research Memory.
//
// The learning system continuously improves DOGE's research prioritization
// and recommendations from accumulated evidence — without modifying
// observations, bypassing human approval, or executing tools.
//
// Architecture:
//
//	Evidence → Learning Signal → Pattern → Recommendation
//
// Hard boundaries:
//   - Learning NEVER modifies immutable observations
//   - Learning NEVER converts hypotheses into facts
//   - Learning NEVER executes tools
//   - Learning NEVER weakens safety constraints
//   - Learning only changes: ranking, context, recommendations
//
// Everything is traceable. Every learned pattern retains:
//   - Supporting evidence references
//   - Confidence score
//   - Occurrence count
//   - First/last seen timestamps
package learning

import (
	"time"

	"github.com/google/uuid"
)

// ResearchPattern represents a recurring pattern learned from evidence.
//
// Example:
//
//	Pattern: "endpoint_with_object_id"
//	Description: "Resource endpoint with numeric ID parameter"
//	Confidence: 0.72
//	Occurrences: 7
//	HistoricalOutcome: "high-value investigation"
type ResearchPattern struct {
	// ID uniquely identifies this pattern.
	ID uuid.UUID `json:"id"`

	// Name is a machine-readable pattern identifier.
	Name string `json:"name"`

	// Description is a human-readable explanation.
	Description string `json:"description"`

	// Category classifies the pattern.
	Category PatternCategory `json:"category"`

	// Confidence ranges from 0.0 (speculative) to 1.0 (well-established).
	Confidence float64 `json:"confidence"`

	// Occurrences is how many times this pattern has been observed.
	Occurrences int `json:"occurrences"`

	// HistoricalOutcome summarizes what happened when this pattern was investigated.
	HistoricalOutcome string `json:"historical_outcome"`

	// EvidenceIDs are the observations that support this pattern.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// InvestigationIDs are the investigations where this pattern appeared.
	InvestigationIDs []uuid.UUID `json:"investigation_ids"`

	// PriorityBoost is the additional priority weight this pattern contributes.
	PriorityBoost float64 `json:"priority_boost"`

	// FirstSeen is when this pattern was first observed.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is when this pattern was last observed.
	LastSeen time.Time `json:"last_seen"`

	// DecayFactor reduces confidence over time for stale patterns (0.0-1.0).
	DecayFactor float64 `json:"decay_factor"`
}

// PatternCategory classifies what kind of research pattern this is.
type PatternCategory string

const (
	PatternEndpoint      PatternCategory = "endpoint"
	PatternParameter     PatternCategory = "parameter"
	PatternAuth          PatternCategory = "authentication"
	PatternAuthz         PatternCategory = "authorization"
	PatternTechnology    PatternCategory = "technology"
	PatternResponse      PatternCategory = "response_behavior"
	PatternWorkflow      PatternCategory = "workflow"
	PatternNoise         PatternCategory = "noise"
)

// ResearchOutcome records what happened when a pattern was investigated.
type ResearchOutcome struct {
	// ID uniquely identifies this outcome.
	ID uuid.UUID `json:"id"`

	// PatternID links to the pattern this outcome relates to.
	PatternID uuid.UUID `json:"pattern_id"`

	// InvestigationID is the investigation context.
	InvestigationID uuid.UUID `json:"investigation_id"`

	// Productive indicates whether this investigation yielded useful evidence.
	Productive bool `json:"productive"`

	// FindingsProduced is how many findings resulted.
	FindingsProduced int `json:"findings_produced"`

	// ObservationsProduced is how many observations resulted.
	ObservationsProduced int `json:"observations_produced"`

	// Notes describes what happened.
	Notes string `json:"notes"`

	// Timestamp.
	RecordedAt time.Time `json:"recorded_at"`
}

// LearningEvent represents a single learning signal extracted from evidence.
type LearningEvent struct {
	// ID uniquely identifies this event.
	ID uuid.UUID `json:"id"`

	// Type classifies the learning signal.
	Type LearningEventType `json:"type"`

	// PatternName is the pattern this event relates to.
	PatternName string `json:"pattern_name"`

	// Context describes what triggered this learning event.
	Context string `json:"context"`

	// EvidenceIDs are the supporting observations.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// ConfidenceDelta is how much this event changed the pattern's confidence.
	ConfidenceDelta float64 `json:"confidence_delta"`

	// RecordedAt is when this event occurred.
	RecordedAt time.Time `json:"recorded_at"`
}

// LearningEventType classifies learning signals.
type LearningEventType string

const (
	// EventPatternObserved: a known pattern was seen again.
	EventPatternObserved LearningEventType = "pattern_observed"

	// EventNewPattern: a previously unseen pattern emerged.
	EventNewPattern LearningEventType = "new_pattern"

	// EventPatternConfirmed: investigation confirmed the pattern's value.
	EventPatternConfirmed LearningEventType = "pattern_confirmed"

	// EventPatternContradicted: evidence contradicts the pattern.
	EventPatternContradicted LearningEventType = "pattern_contradicted"

	// EventNoiseDetected: repeated low-value observation identified.
	EventNoiseDetected LearningEventType = "noise_detected"

	// EventDecay: pattern confidence reduced due to staleness.
	EventDecay LearningEventType = "decay"
)

// PriorityExplanation explains why a recommendation has a particular priority.
// The researcher can inspect this to understand DOGE's reasoning.
type PriorityExplanation struct {
	// BasePriority is the raw priority before learning adjustments.
	BasePriority float64 `json:"base_priority"`

	// FinalPriority is the adjusted priority after learning.
	FinalPriority float64 `json:"final_priority"`

	// Adjustments lists each factor that changed the priority.
	Adjustments []PriorityAdjustment `json:"adjustments"`
}

// PriorityAdjustment is a single factor in priority computation.
type PriorityAdjustment struct {
	// Reason explains this adjustment.
	Reason string `json:"reason"`

	// Delta is the priority change (+/-).
	Delta float64 `json:"delta"`

	// PatternID links to the learned pattern (if applicable).
	PatternID uuid.UUID `json:"pattern_id,omitempty"`
}
