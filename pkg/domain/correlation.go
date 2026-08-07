package domain

import (
	"time"

	"github.com/google/uuid"
)

// CorrelationType classifies the kind of link between correlated entities.
type CorrelationType string

const (
	// CorrelationSameTarget groups entities that likely belong to the same target.
	CorrelationSameTarget CorrelationType = "same_target"

	// CorrelationAttackChain groups entities that form a potential attack path.
	CorrelationAttackChain CorrelationType = "attack_chain"

	// CorrelationTechStack groups entities that form a technology stack.
	CorrelationTechStack CorrelationType = "technology_stack"

	// CorrelationAuthFlow groups entities involved in an authentication flow.
	CorrelationAuthFlow CorrelationType = "auth_flow"
)

// Correlation represents a discovered link between related entities
// that originated from independent observations. The Correlation Engine
// identifies these links by analyzing patterns across tools and time.
//
// Example: subfinder finds admin.example.com, httpx probes it and gets
// 200 OK, katana crawls /login, JS analysis finds an admin API endpoint.
// These are four independent observations that the Correlation Engine
// connects into a single correlation.
type Correlation struct {
	// ID is the unique identifier for this correlation.
	ID uuid.UUID `json:"id"`

	// EntityIDs lists the entities in this correlation group.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// Type classifies the kind of link.
	Type CorrelationType `json:"type"`

	// Confidence indicates how confident the system is in this
	// correlation, from 0.0 (weak) to 1.0 (strong).
	Confidence float64 `json:"confidence"`

	// Description explains why these entities are correlated.
	Description string `json:"description"`

	// ObservationIDs lists the observations that support this correlation.
	ObservationIDs []uuid.UUID `json:"observation_ids"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this correlation was discovered.
	CreatedAt time.Time `json:"created_at"`
}
