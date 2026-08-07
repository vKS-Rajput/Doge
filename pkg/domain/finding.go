package domain

import (
	"time"

	"github.com/google/uuid"
)

// Severity classifies the impact level of a finding, insight, or
// similar security-relevant object.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingStatus tracks the lifecycle of a researcher-confirmed finding.
type FindingStatus string

const (
	FindingDraft         FindingStatus = "draft"
	FindingConfirmed     FindingStatus = "confirmed"
	FindingReported      FindingStatus = "reported"
	FindingResolved      FindingStatus = "resolved"
	FindingFalsePositive FindingStatus = "false_positive"
)

// Finding is a researcher-confirmed observation with severity,
// status, and supporting evidence. Findings are the outputs that
// feed into reports and bounty submissions.
//
// A Finding differs from a Hypothesis in that it represents something
// the researcher has verified, not something speculative. Findings may
// originate from confirmed hypotheses.
type Finding struct {
	// ID is the unique identifier for this finding.
	ID uuid.UUID `json:"id"`

	// Title is a short, descriptive name for the finding.
	Title string `json:"title"`

	// Description provides a detailed explanation of the finding,
	// including impact and reproduction steps.
	Description string `json:"description"`

	// Severity classifies the impact level.
	Severity Severity `json:"severity"`

	// Status tracks the lifecycle stage of the finding.
	Status FindingStatus `json:"status"`

	// EntityIDs lists the entities involved in this finding.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// EvidenceIDs lists the evidence supporting this finding.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// HypothesisID links to the hypothesis that originated this finding,
	// if applicable.
	HypothesisID *uuid.UUID `json:"hypothesis_id,omitempty"`

	// Notes holds the researcher's freeform notes about this finding.
	Notes string `json:"notes"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this finding was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this finding was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// ConfirmedAt is when the researcher confirmed this finding.
	// Nil if the finding is still in draft status.
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}
