package domain

import (
	"time"

	"github.com/google/uuid"
)

// EntityType classifies the kind of real-world concept an entity represents.
// Entities are the nodes of the Knowledge Graph.
type EntityType string

const (
	EntityDomain          EntityType = "domain"
	EntitySubdomain       EntityType = "subdomain"
	EntityIPAddress       EntityType = "ip_address"
	EntityURL             EntityType = "url"
	EntityEndpoint        EntityType = "endpoint"
	EntityParameter       EntityType = "parameter"
	EntityHeader          EntityType = "header"
	EntityCookie          EntityType = "cookie"
	EntityTechnology      EntityType = "technology"
	EntityPort            EntityType = "port"
	EntityService         EntityType = "service"
	EntityCertificate     EntityType = "certificate"
	EntityDNSRecord       EntityType = "dns_record"
	EntityJavaScriptFile  EntityType = "javascript_file"
	EntityScreenshot      EntityType = "screenshot"
	EntitySecret          EntityType = "secret"
	EntityAPIKey          EntityType = "api_key"
	EntityJWT             EntityType = "jwt"
	EntityGraphQLType     EntityType = "graphql_type"
	EntityGraphQLOp       EntityType = "graphql_operation"
	EntityCSPDirective    EntityType = "csp_directive"
	EntityCORSConfig      EntityType = "cors_config"
	EntityAuthMechanism   EntityType = "auth_mechanism"
	EntityNote            EntityType = "note"
	EntityFindingRef      EntityType = "finding_ref"
)

// Entity is a node in the Knowledge Graph representing a real-world concept.
// It is Immutable Pillar #3 of the system.
//
// Invariants:
//   - The core identity (Type + Value) of an entity never changes.
//   - Attributes accumulate over time as new observations enrich the entity.
//   - CanonicalID enables the Entity Resolver to merge duplicates:
//     alias entities point their CanonicalID to the resolved canonical entity.
//   - Every entity can be traced back to the observations that created it
//     via the entity_observations join table.
type Entity struct {
	// ID is the unique identifier for this entity.
	ID uuid.UUID `json:"id"`

	// CanonicalID points to the resolved canonical entity after
	// deduplication. For canonical entities, this equals ID.
	// For aliases (merged entities), this points to the canonical form.
	CanonicalID uuid.UUID `json:"canonical_id"`

	// Type classifies what kind of concept this entity represents.
	Type EntityType `json:"type"`

	// Value is the canonical string representation of this entity
	// (e.g., "admin.example.com", "POST /api/users", "nginx 1.24").
	Value string `json:"value"`

	// Attributes holds type-specific metadata that may be enriched
	// over time as new observations arrive. Keys and structure
	// depend on EntityType.
	Attributes map[string]any `json:"attributes,omitempty"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// ObservationCount tracks how many observations reference this entity.
	ObservationCount int `json:"observation_count"`

	// FirstSeenAt is the timestamp of the earliest observation that
	// contributed to this entity.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// LastSeenAt is the timestamp of the most recent observation that
	// contributed to this entity.
	LastSeenAt time.Time `json:"last_seen_at"`

	// CreatedAt is when this entity record was created in the database.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this entity was last enriched with new attributes.
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityUpdate represents a partial update to an entity's mutable fields.
// Used by the Knowledge Graph's UpdateEntity method.
type EntityUpdate struct {
	// Attributes to merge into the entity's existing attributes.
	// Existing keys are overwritten; new keys are added.
	Attributes map[string]any `json:"attributes,omitempty"`

	// LastSeenAt updates the last-seen timestamp.
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`

	// ObservationCount sets the new observation count.
	ObservationCount *int `json:"observation_count,omitempty"`
}

// EntityFilter specifies criteria for listing entities.
type EntityFilter struct {
	// ProjectID limits results to a specific project.
	ProjectID *uuid.UUID `json:"project_id,omitempty"`

	// Type limits results to a specific entity type.
	Type *EntityType `json:"type,omitempty"`

	// ValueContains filters entities whose Value contains this substring.
	ValueContains string `json:"value_contains,omitempty"`

	// Limit caps the number of results returned. Zero means no limit.
	Limit int `json:"limit,omitempty"`

	// Offset for pagination.
	Offset int `json:"offset,omitempty"`
}

// Direction specifies the traversal direction for relationship queries.
type Direction string

const (
	// DirectionOutgoing returns relationships where the entity is the source.
	DirectionOutgoing Direction = "outgoing"

	// DirectionIncoming returns relationships where the entity is the target.
	DirectionIncoming Direction = "incoming"

	// DirectionBoth returns relationships in either direction.
	DirectionBoth Direction = "both"
)

// Subgraph represents a subset of the Knowledge Graph returned by
// neighborhood queries. Contains entities and the relationships
// connecting them.
type Subgraph struct {
	// Entities in the subgraph, keyed by ID.
	Entities map[uuid.UUID]Entity `json:"entities"`

	// Relationships connecting entities in the subgraph.
	Relationships []Relationship `json:"relationships"`
}

// GraphStats holds summary statistics for the Knowledge Graph.
type GraphStats struct {
	// EntityCount is the total number of entities.
	EntityCount int `json:"entity_count"`

	// RelationshipCount is the total number of relationships.
	RelationshipCount int `json:"relationship_count"`

	// ObservationCount is the total number of observations.
	ObservationCount int `json:"observation_count"`

	// ArtifactCount is the total number of stored artifacts.
	ArtifactCount int `json:"artifact_count"`

	// EntityCountByType breaks down entity count by type.
	EntityCountByType map[EntityType]int `json:"entity_count_by_type"`
}
