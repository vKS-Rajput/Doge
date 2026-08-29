// Package coverage implements evidence-derived investigation coverage tracking.
//
// Coverage is NOT a guess. Every percentage comes from actual evidence:
//   - No observations about authorization → 0% authorization coverage
//   - 5 endpoints with auth evidence out of 20 total → 25% auth coverage
//
// The coverage engine answers: "How much of this application have I actually
// investigated, based on the evidence I've collected?"
package coverage

import (
	"time"

	"github.com/google/uuid"
)

// Category represents a dimension of investigation coverage.
type Category string

const (
	CategoryDiscovery      Category = "discovery"
	CategoryWebMapping     Category = "web_mapping"
	CategoryAuthentication Category = "authentication"
	CategoryAuthorization  Category = "authorization"
	CategoryAPISurface     Category = "api_surface"
	CategoryBusinessLogic  Category = "business_logic"
	CategoryFileHandling   Category = "file_handling"
	CategoryTechnology     Category = "technology"
)

// AllCategories returns all coverage categories in display order.
func AllCategories() []Category {
	return []Category{
		CategoryDiscovery,
		CategoryWebMapping,
		CategoryAuthentication,
		CategoryAuthorization,
		CategoryAPISurface,
		CategoryBusinessLogic,
		CategoryFileHandling,
		CategoryTechnology,
	}
}

// Report is the complete coverage assessment for a target.
type Report struct {
	// Target being assessed.
	Target string `json:"target"`

	// Categories with individual coverage scores.
	Categories []CategoryCoverage `json:"categories"`

	// TotalScore is the weighted average across all categories (0.0 - 1.0).
	TotalScore float64 `json:"total_score"`

	// TotalObservations across the investigation.
	TotalObservations int `json:"total_observations"`

	// TotalEntities discovered.
	TotalEntities int `json:"total_entities"`

	// GeneratedAt is when this report was produced.
	GeneratedAt time.Time `json:"generated_at"`
}

// CategoryCoverage describes coverage within a single category.
type CategoryCoverage struct {
	// Category name.
	Category Category `json:"category"`

	// Score from 0.0 (no evidence) to 1.0 (fully investigated).
	Score float64 `json:"score"`

	// Evidence is the number of supporting observations.
	Evidence int `json:"evidence"`

	// Total is the total possible items in this category.
	// For example, total endpoints, total parameters.
	Total int `json:"total"`

	// Investigated is how many items have been examined.
	Investigated int `json:"investigated"`

	// Gaps are specific items that lack evidence.
	Gaps []Gap `json:"gaps,omitempty"`

	// LastUpdated is when this category was last affected by new evidence.
	LastUpdated time.Time `json:"last_updated"`
}

// Gap represents a specific missing piece of investigation evidence.
type Gap struct {
	// ID uniquely identifies this gap.
	ID uuid.UUID `json:"id"`

	// Type classifies the gap.
	Type GapType `json:"type"`

	// Target is the specific item (endpoint, parameter, entity).
	Target string `json:"target"`

	// Description explains what evidence is missing.
	Description string `json:"description"`

	// Priority ranks importance.
	Priority string `json:"priority"` // "critical", "high", "medium", "low"

	// Suggestion recommends what to do about it.
	Suggestion string `json:"suggestion"`

	// EntityIDs are the entities involved.
	EntityIDs []uuid.UUID `json:"entity_ids,omitempty"`

	// Category this gap belongs to.
	Category Category `json:"category"`
}

// GapType classifies what kind of evidence gap this is.
type GapType string

const (
	// GapUntested: entity exists in surface but has no investigation evidence.
	GapUntested GapType = "untested"

	// GapPartial: some aspects tested, others unknown.
	GapPartial GapType = "partial"

	// GapStale: evidence exists but is old.
	GapStale GapType = "stale"

	// GapContradictory: conflicting observations.
	GapContradictory GapType = "contradictory"
)
