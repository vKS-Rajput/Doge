package domain

import (
	"time"

	"github.com/google/uuid"
)

// EvidenceType classifies whether a piece of evidence supports,
// refutes, or is neutral toward a claim.
type EvidenceType string

const (
	// EvidenceSupports indicates the evidence supports the claim.
	EvidenceSupports EvidenceType = "supports"

	// EvidenceRefutes indicates the evidence contradicts the claim.
	EvidenceRefutes EvidenceType = "refutes"

	// EvidenceNeutral indicates the evidence is relevant but
	// neither supports nor refutes the claim.
	EvidenceNeutral EvidenceType = "neutral"
)

// ClaimType identifies what kind of higher-level object a piece
// of evidence is linked to.
type ClaimType string

const (
	ClaimInsight      ClaimType = "insight"
	ClaimFinding      ClaimType = "finding"
	ClaimHypothesis   ClaimType = "hypothesis"
	ClaimAIConclusion ClaimType = "ai_conclusion"
)

// Evidence is an immutable provenance link connecting a claim
// (insight, finding, hypothesis, or AI conclusion) to the specific
// observation and artifact that support it.
// It is Immutable Pillar #2 of the system.
//
// Invariants:
//   - Once created, an Evidence record is never modified or deleted.
//   - Every higher-level claim (insight, finding, hypothesis, AI conclusion)
//     must have at least one Evidence link or it cannot exist.
//   - The chain Claim → Evidence → Observation → Artifact is always traversable.
type Evidence struct {
	// ID is the unique identifier for this evidence link.
	ID uuid.UUID `json:"id"`

	// ObservationID links to the source observation.
	ObservationID uuid.UUID `json:"observation_id"`

	// ArtifactID links to the source artifact for direct file reference.
	ArtifactID uuid.UUID `json:"artifact_id"`

	// EntityID links to the entity this evidence relates to.
	// Nullable: not all evidence is entity-specific.
	EntityID *uuid.UUID `json:"entity_id,omitempty"`

	// ClaimType identifies what kind of object this evidence supports.
	ClaimType ClaimType `json:"claim_type"`

	// ClaimID is the identifier of the claim this evidence supports.
	ClaimID uuid.UUID `json:"claim_id"`

	// Type indicates whether this evidence supports, refutes, or is
	// neutral toward the claim.
	Type EvidenceType `json:"type"`

	// Description is a human-readable explanation of what this
	// evidence shows and how it relates to the claim.
	Description string `json:"description"`

	// SourceLocation identifies where in the artifact this evidence
	// was found (e.g., "line:42", "field:headers.set-cookie").
	SourceLocation string `json:"source_location"`

	// Strength indicates how strongly this evidence supports or
	// refutes the claim, from 0.0 (very weak) to 1.0 (definitive).
	Strength float64 `json:"strength"`

	// CreatedAt is when this evidence link was established.
	CreatedAt time.Time `json:"created_at"`
}
