package domain

import (
	"time"

	"github.com/google/uuid"
)

// HypothesisType classifies the category of a hypothesis.
type HypothesisType string

const (
	HypothesisVulnerability         HypothesisType = "vulnerability"
	HypothesisMisconfiguration      HypothesisType = "misconfiguration"
	HypothesisInfoDisclosure        HypothesisType = "information_disclosure"
	HypothesisLogicFlaw             HypothesisType = "logic_flaw"
	HypothesisAccessControl         HypothesisType = "access_control"
)

// HypothesisStatus tracks the lifecycle of a hypothesis as evidence
// accumulates for or against it.
type HypothesisStatus string

const (
	HypothesisProposed      HypothesisStatus = "proposed"
	HypothesisInvestigating  HypothesisStatus = "investigating"
	HypothesisConfirmed     HypothesisStatus = "confirmed"
	HypothesisRejected      HypothesisStatus = "rejected"
	HypothesisInconclusive  HypothesisStatus = "inconclusive"
)

// HypothesisProposer identifies who or what proposed a hypothesis.
type HypothesisProposer string

const (
	ProposerSystem     HypothesisProposer = "system"
	ProposerResearcher HypothesisProposer = "researcher"
	ProposerAI         HypothesisProposer = "ai"
)

// Hypothesis represents a proposed vulnerability or condition that
// the researcher is investigating. It tracks an evidence chain,
// confidence score, and status that evolve over time.
//
// This mirrors how experienced security researchers think: they
// maintain mental models of possible issues and update them as
// evidence accumulates. A hypothesis may eventually become a
// confirmed Finding or be rejected.
type Hypothesis struct {
	// ID is the unique identifier for this hypothesis.
	ID uuid.UUID `json:"id"`

	// Title is a short, descriptive name.
	Title string `json:"title"`

	// Description provides a detailed explanation of what is hypothesized
	// and why.
	Description string `json:"description"`

	// Type classifies the category of the hypothesis.
	Type HypothesisType `json:"type"`

	// Status tracks the current lifecycle stage.
	Status HypothesisStatus `json:"status"`

	// Confidence is a score from 0.0 to 1.0 indicating how likely
	// this hypothesis is to be true, derived from the balance of
	// supporting and refuting evidence.
	Confidence float64 `json:"confidence"`

	// EntityIDs lists the entities involved in this hypothesis.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// SupportingEvidence lists evidence IDs that support this hypothesis.
	SupportingEvidence []uuid.UUID `json:"supporting_evidence"`

	// RefutingEvidence lists evidence IDs that refute this hypothesis.
	RefutingEvidence []uuid.UUID `json:"refuting_evidence"`

	// Notes holds freeform researcher notes.
	Notes string `json:"notes"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// ProposedBy indicates who or what originated this hypothesis.
	ProposedBy HypothesisProposer `json:"proposed_by"`

	// CreatedAt is when this hypothesis was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this hypothesis was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// ResolvedAt is when this hypothesis was confirmed, rejected, or
	// marked inconclusive. Nil if still active.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// HypothesisUpdate represents a partial update to a hypothesis.
type HypothesisUpdate struct {
	Status     *HypothesisStatus `json:"status,omitempty"`
	Confidence *float64          `json:"confidence,omitempty"`
	Notes      *string           `json:"notes,omitempty"`
	ResolvedAt *time.Time        `json:"resolved_at,omitempty"`
}

// HypothesisFilter specifies criteria for listing hypotheses.
type HypothesisFilter struct {
	ProjectID *uuid.UUID        `json:"project_id,omitempty"`
	Status    *HypothesisStatus `json:"status,omitempty"`
	Type      *HypothesisType   `json:"type,omitempty"`
	Limit     int               `json:"limit,omitempty"`
	Offset    int               `json:"offset,omitempty"`
}
