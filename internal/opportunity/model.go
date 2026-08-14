// Package opportunity implements the Research Opportunity Engine.
//
// This is the bridge between "Doge detected something unusual" and
// "here's what a researcher should actually investigate, and why."
//
// The Research Opportunity Engine converts novelty signals into
// actionable research opportunities. Each opportunity includes:
//
//   - WHY this deserves investigation (evidence + novelty)
//   - WHAT questions need answering
//   - HOW to approach validation
//   - WHAT evidence to expect
//
// This is NOT a vulnerability scanner. An opportunity is:
// "This configuration is unusual enough to deserve investigation."
//
// It is NOT:
// "There is a vulnerability here."
//
// The epistemic hierarchy remains:
//
//	Observation → Correlation → Attack Surface → Novelty →
//	Research Opportunity → Hypothesis → Human Testing → Finding
package opportunity

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/surface"
)

// Opportunity is an actionable research recommendation derived from
// novelty signals and attack-surface analysis.
//
// An opportunity tells the researcher:
//   - What to investigate
//   - Why it's worth investigating
//   - What questions to answer
//   - What evidence to look for
type Opportunity struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// Title is a concise, actionable description.
	Title string `json:"title"`

	// Target identifies the primary entity being investigated.
	Target string `json:"target"`

	// SurfaceType classifies the attack surface involved.
	SurfaceType surface.Category `json:"surface_type"`

	// Description explains why this configuration deserves investigation.
	Description string `json:"description"`

	// Questions are the specific research questions to answer.
	// Each question is investigatable and evidence-producible.
	Questions []ResearchQuestion `json:"questions"`

	// Priority ranks this opportunity relative to others.
	Priority Priority `json:"priority"`

	// NoveltySignals lists the signals that generated this opportunity.
	NoveltySignals []novelty.Signal `json:"novelty_signals"`

	// EntityIDs lists all entities involved.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// ProjectID is the owning project.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this opportunity was generated.
	CreatedAt time.Time `json:"created_at"`
}

// ResearchQuestion is a specific, answerable question that the
// researcher should investigate for this opportunity.
type ResearchQuestion struct {
	// Question is the question to answer.
	Question string `json:"question"`

	// Why explains why this question matters for this opportunity.
	Why string `json:"why"`

	// ExpectedEvidence describes what evidence would answer this question.
	ExpectedEvidence string `json:"expected_evidence"`

	// Effort estimates how much work this question requires.
	Effort string `json:"effort"` // "quick", "moderate", "deep"
}

// Priority classifies opportunity urgency.
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
)
