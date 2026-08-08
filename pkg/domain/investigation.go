package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// InvestigationStatus tracks the lifecycle of an investigation.
//
// Lifecycle:
//
//	ACTIVE → PAUSED → ACTIVE  (pause/resume)
//	ACTIVE → CONCLUDED        (conclude)
//
// CONCLUDED is effectively immutable. If the researcher discovers
// something later, they create a new investigation or explicitly
// reopen this one.
type InvestigationStatus string

const (
	InvestigationActive    InvestigationStatus = "active"
	InvestigationPaused    InvestigationStatus = "paused"
	InvestigationConcluded InvestigationStatus = "concluded"
)

// Investigation is a research journey that connects hypotheses,
// tasks, findings, sessions, and tested surfaces into a coherent
// line of inquiry.
//
// This is NOT a "project" (which owns all workspace data).
// An investigation is a focused line of research within a project.
//
// Example:
//
//	Investigation: Admin Interface Security
//	  Targets:     admin.example.com, api.example.com
//	  Hypotheses:  "Admin panel may expose privileged functionality"
//	  Tasks:       "Test authorization on admin endpoints"
//	  Findings:    "Admin panel requires authentication"
//	  Surfaces:    Authentication=TESTED, Authorization=UNTESTED
//	  Conclusions: "Admin auth present, authz needs testing"
type Investigation struct {
	// ID is the unique identifier for this investigation.
	ID uuid.UUID `json:"id"`

	// Title is a short, descriptive name for the investigation.
	Title string `json:"title"`

	// Objective describes what the researcher is trying to learn.
	Objective string `json:"objective"`

	// Status tracks the lifecycle stage.
	Status InvestigationStatus `json:"status"`

	// TargetIDs lists the entity IDs being investigated.
	// Kept as a JSON array for v0.5; will become a join table later.
	TargetIDs []uuid.UUID `json:"target_ids"`

	// Conclusions are structured, evidence-backed research conclusions.
	// Each conclusion must have provenance (evidence/finding IDs).
	Conclusions []Conclusion `json:"conclusions"`

	// Notes holds freeform researcher notes.
	Notes string `json:"notes"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this investigation started.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this investigation was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// ConcludedAt is when this investigation was concluded.
	ConcludedAt *time.Time `json:"concluded_at,omitempty"`
}

// Conclusion is a structured research conclusion with provenance.
//
// A conclusion is NOT a free-text opinion. It must link to
// evidence and/or findings that established it.
//
// If Doge cannot explain where a conclusion came from,
// it should not be treated as established fact.
type Conclusion struct {
	// Text is the conclusion statement.
	Text string `json:"text"`

	// Status classifies the conclusion's certainty.
	Status ConclusionStatus `json:"status"`

	// EvidenceIDs lists evidence that supports this conclusion.
	EvidenceIDs []string `json:"evidence_ids"`

	// FindingIDs lists findings that support this conclusion.
	FindingIDs []string `json:"finding_ids"`

	// Author identifies who drew this conclusion.
	Author string `json:"author"` // "researcher", "system"

	// CreatedAt is when this conclusion was recorded.
	CreatedAt time.Time `json:"created_at"`
}

// ConclusionStatus classifies certainty.
type ConclusionStatus string

const (
	ConclusionConfirmed    ConclusionStatus = "confirmed"
	ConclusionLikely       ConclusionStatus = "likely"
	ConclusionInconclusive ConclusionStatus = "inconclusive"
)

// ValidateConclusion checks that a conclusion has provenance.
func ValidateConclusion(c Conclusion) error {
	if c.Text == "" {
		return fmt.Errorf("conclusion text is empty")
	}
	if len(c.EvidenceIDs) == 0 && len(c.FindingIDs) == 0 {
		return fmt.Errorf("conclusion must have at least one evidence ID or finding ID as provenance")
	}
	if c.Author == "" {
		return fmt.Errorf("conclusion must have an author")
	}
	return nil
}

// TestedSurfaceStatus tracks what has been checked.
type TestedSurfaceStatus string

const (
	SurfaceUntested     TestedSurfaceStatus = "untested"
	SurfaceTested       TestedSurfaceStatus = "tested"
	SurfaceInconclusive TestedSurfaceStatus = "inconclusive"
)

// TestedSurface tracks what attack surfaces or test categories have
// been checked during an investigation.
//
// This answers: "What remains unexplored?"
type TestedSurface struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// InvestigationID links to the parent investigation.
	InvestigationID uuid.UUID `json:"investigation_id"`

	// EntityID optionally links to a specific entity being tested.
	EntityID *uuid.UUID `json:"entity_id,omitempty"`

	// Category is the test category (e.g., "authentication",
	// "authorization", "file_upload", "rate_limiting").
	Category string `json:"category"`

	// Status tracks whether this surface has been tested.
	Status TestedSurfaceStatus `json:"status"`

	// EvidenceIDs lists evidence from testing this surface.
	EvidenceIDs []string `json:"evidence_ids"`

	// Notes holds freeform testing notes.
	Notes string `json:"notes"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// TestedAt is when this surface was tested (nil if untested).
	TestedAt *time.Time `json:"tested_at,omitempty"`

	// CreatedAt is when this surface was registered.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this surface was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// InvestigationUpdate represents a partial update.
type InvestigationUpdate struct {
	Status      *InvestigationStatus `json:"status,omitempty"`
	Objective   *string              `json:"objective,omitempty"`
	Notes       *string              `json:"notes,omitempty"`
	ConcludedAt *time.Time           `json:"concluded_at,omitempty"`
}

// InvestigationFilter specifies listing criteria.
type InvestigationFilter struct {
	ProjectID *uuid.UUID           `json:"project_id,omitempty"`
	Status    *InvestigationStatus `json:"status,omitempty"`
	Limit     int                  `json:"limit,omitempty"`
}
