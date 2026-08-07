package domain

import (
	"time"

	"github.com/google/uuid"
)

// RelationshipType classifies the kind of connection between two entities
// in the Knowledge Graph. Relationships are directed (source → target).
type RelationshipType string

const (
	RelHasSubdomain    RelationshipType = "has_subdomain"
	RelResolvesTo      RelationshipType = "resolves_to"
	RelServes          RelationshipType = "serves"
	RelHasEndpoint     RelationshipType = "has_endpoint"
	RelHasParameter    RelationshipType = "has_parameter"
	RelReturnsHeader   RelationshipType = "returns_header"
	RelSetsCookie      RelationshipType = "sets_cookie"
	RelUsesTechnology  RelationshipType = "uses_technology"
	RelListensOn       RelationshipType = "listens_on"
	RelRunsService     RelationshipType = "runs_service"
	RelHasCertificate  RelationshipType = "has_certificate"
	RelHasDNSRecord    RelationshipType = "has_dns_record"
	RelIncludesScript  RelationshipType = "includes_script"
	RelHasScreenshot   RelationshipType = "has_screenshot"
	RelContainsSecret  RelationshipType = "contains_secret"
	RelUsesAuth        RelationshipType = "uses_auth"
	RelContainsClaim   RelationshipType = "contains_claim"
	RelExposesOp       RelationshipType = "exposes_operation"
	RelHasCSP          RelationshipType = "has_csp"
	RelHasCORS         RelationshipType = "has_cors"
	RelLinksTo         RelationshipType = "links_to"
	RelRedirectsTo     RelationshipType = "redirects_to"
	RelRelatedTo       RelationshipType = "related_to"
	RelPartOf          RelationshipType = "part_of"
)

// Relationship is a typed, directed edge in the Knowledge Graph
// connecting two entities.
//
// Relationships are enriched over time: if the same relationship
// (same source, target, and type) is observed again, LastSeenAt
// is updated rather than creating a duplicate.
type Relationship struct {
	// ID is the unique identifier for this relationship.
	ID uuid.UUID `json:"id"`

	// SourceEntityID is the "from" node in the directed edge.
	SourceEntityID uuid.UUID `json:"source_entity_id"`

	// TargetEntityID is the "to" node in the directed edge.
	TargetEntityID uuid.UUID `json:"target_entity_id"`

	// Type classifies the kind of connection.
	Type RelationshipType `json:"type"`

	// Attributes holds edge-specific metadata (e.g., HTTP status code
	// on a "serves" relationship, TTL on a "has_dns_record" relationship).
	Attributes map[string]any `json:"attributes,omitempty"`

	// ObservationID links to the observation that first established
	// this relationship.
	ObservationID *uuid.UUID `json:"observation_id,omitempty"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// FirstSeenAt is when this relationship was first observed.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// LastSeenAt is when this relationship was most recently confirmed.
	LastSeenAt time.Time `json:"last_seen_at"`

	// CreatedAt is when this record was created in the database.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this record was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}
