// Package novelty implements the Novelty Engine — deterministic detection
// of unusual, new, or contradictory patterns in the attack surface.
//
// The Novelty Engine transitions Doge from:
//
//	"I know what exists"
//
// to:
//
//	"I know what changed, why it is unusual, and why you might want
//	to investigate it."
//
// It operates on four dimensions:
//
//  1. Structural Novelty — new surfaces, disappeared surfaces, changed relationships
//  2. Temporal Novelty — frequency changes, new things after stability
//  3. Cross-tool Contradiction — conflicting reports, missing corroboration
//  4. Surface Combination Novelty — new combinations of interesting surfaces
//
// All novelty detection is deterministic. No LLM. No guessing.
// Each signal has evidence, a rule name, and a novelty score.
package novelty

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/surface"
)

// Signal is a single detected novelty.
//
// A signal is NOT a vulnerability claim. It is:
// "This is unusual compared to what Doge already knows."
type Signal struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// Type classifies the kind of novelty.
	Type SignalType `json:"type"`

	// Category classifies which dimension this belongs to.
	Category Category `json:"category"`

	// Title is a human-readable summary.
	Title string `json:"title"`

	// Description explains what was detected and why it's unusual.
	Description string `json:"description"`

	// NoveltyScore ranges from 0.0 (mundane) to 1.0 (highly unusual).
	// This is NOT a vulnerability score. It is:
	// "How surprising is this compared to what Doge already knows?"
	NoveltyScore float64 `json:"novelty_score"`

	// EntityIDs lists entities involved in this signal.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// ObservationIDs lists supporting observations.
	ObservationIDs []uuid.UUID `json:"observation_ids"`

	// SurfaceCategories lists the attack-surface categories involved.
	SurfaceCategories []surface.Category `json:"surface_categories"`

	// ProjectID is the owning project.
	ProjectID uuid.UUID `json:"project_id"`

	// DetectedAt is when this novelty was discovered.
	DetectedAt time.Time `json:"detected_at"`
}

// SignalType classifies specific novelty signals.
type SignalType string

const (
	// Structural novelty.
	SignalNewSubdomain     SignalType = "new_subdomain"
	SignalNewPort          SignalType = "new_port"
	SignalNewEndpoint      SignalType = "new_endpoint"
	SignalNewAPISurface    SignalType = "new_api_surface"
	SignalNewUploadSurface SignalType = "new_upload_surface"
	SignalNewAuthSurface   SignalType = "new_auth_surface"
	SignalSurfaceRemoved   SignalType = "surface_removed"
	SignalRelationChanged  SignalType = "relationship_changed"

	// Cross-tool contradiction.
	SignalContradiction       SignalType = "cross_tool_contradiction"
	SignalMissingCorroboration SignalType = "missing_corroboration"

	// Surface combination novelty.
	SignalNovelCombination SignalType = "novel_surface_combination"
)

// Category classifies the novelty dimension.
type Category string

const (
	CategoryStructural  Category = "structural"
	CategoryTemporal    Category = "temporal"
	CategoryContradiction Category = "contradiction"
	CategoryCombination Category = "combination"
)
