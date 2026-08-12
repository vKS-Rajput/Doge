package domain

import (
	"time"

	"github.com/google/uuid"
)

// CorrelationType classifies the kind of link between correlated entities.
type CorrelationType string

const (
	// CorrelationSameTarget groups entities that likely belong to the same target.
	// Requires: ≥2 observations from different tools referencing the same host.
	CorrelationSameTarget CorrelationType = "same_target"

	// CorrelationAttackChain groups entities that form a potential attack path.
	CorrelationAttackChain CorrelationType = "attack_chain"

	// CorrelationTechStack groups entities that form a technology stack.
	CorrelationTechStack CorrelationType = "technology_stack"

	// CorrelationAuthFlow groups entities involved in an authentication flow.
	CorrelationAuthFlow CorrelationType = "auth_flow"

	// CorrelationResolvesTo links a hostname to its resolved IP address.
	// Evidence: DNS observation + network scan on the resolved IP.
	CorrelationResolvesTo CorrelationType = "resolves_to"

	// CorrelationServiceStack groups port, service, and technology entities
	// into a unified stack for a single host.
	CorrelationServiceStack CorrelationType = "service_stack"

	// CorrelationConvergence marks an endpoint discovered independently
	// by multiple tools. Stronger existence signal than single-tool discovery.
	CorrelationConvergence CorrelationType = "independent_convergence"

	// CorrelationEndpointCluster groups related endpoints on the same host.
	// Allowed as a single-tool correlation (e.g., katana crawl results).
	CorrelationEndpointCluster CorrelationType = "endpoint_cluster"
)

// Correlation represents a discovered link between related entities
// that originated from independent observations. The Correlation Engine
// identifies these links by analyzing patterns across tools and time.
//
// Every correlation requires three things:
//
//  1. Evidence — at least 2 supporting observations
//  2. Deterministic Rule — a named, testable rule that produced it
//  3. Provenance — traceable back to specific observations
//
// IMPORTANT: Correlation confidence is confidence in the correlation
// rule's inference, NOT probability that a vulnerability exists.
//
//	Confidence 0.90 on a resolves_to correlation means:
//	"90% confident the evidence supports this DNS resolution."
//
//	It does NOT mean:
//	"90% chance the target is vulnerable."
//
// Correlation identity is: Type + sorted EntityIDs + RuleName.
// Correlation evidence accumulates: ObservationIDs grow over time
// as new observations reinforce the same correlation.
type Correlation struct {
	// ID is the unique identifier for this correlation.
	ID uuid.UUID `json:"id"`

	// EntityIDs lists the entities in this correlation group.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// Type classifies the kind of link.
	Type CorrelationType `json:"type"`

	// RuleName identifies which deterministic rule produced this
	// correlation. Enables auditing: "why does this correlation exist?"
	RuleName string `json:"rule_name"`

	// Confidence indicates how confident the rule's inference is,
	// from 0.0 (weak) to 1.0 (strong).
	//
	// This is NOT vulnerability probability.
	Confidence float64 `json:"confidence"`

	// Description explains why these entities are correlated.
	Description string `json:"description"`

	// ObservationIDs lists ALL observations that have ever supported
	// this correlation. This accumulates over time — if the same
	// correlation is rediscovered with new observations, they are
	// appended, preserving the full historical evidence trail.
	ObservationIDs []uuid.UUID `json:"observation_ids"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this correlation was first discovered.
	CreatedAt time.Time `json:"created_at"`

	// LastSeenAt is when this correlation was most recently confirmed
	// by a rule evaluation. Updated on rediscovery without creating
	// a duplicate.
	LastSeenAt time.Time `json:"last_seen_at"`
}
