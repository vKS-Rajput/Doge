// Package surface implements the Attack-Surface Graph — a security-oriented
// projection over the existing Knowledge Graph.
//
// The Attack-Surface Graph does NOT create a parallel data model.
// It provides a security-research lens over existing entities, relationships,
// observations, and correlations.
//
// It answers: "Show me everything that makes this target reachable,
// exposed, interesting, and connected."
//
// Architecture:
//
//	Entities + Relationships + Observations + Correlations
//	                         │
//	                         ▼
//	              Attack-Surface Projection
//	                         │
//	           ┌─────────────┼─────────────┐
//	           ▼             ▼             ▼
//	   Classification   Traversal    Research Paths
//
// This is NOT a vulnerability scanner. It makes the attack surface
// understandable as a connected security graph.
package surface

import (
	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Category classifies an entity's role in the attack surface.
type Category string

const (
	CategoryNetwork        Category = "network"
	CategoryWeb            Category = "web"
	CategoryAPI            Category = "api"
	CategoryAuthentication Category = "authentication"
	CategoryAuthorization  Category = "authorization"
	CategoryUpload         Category = "upload"
	CategoryInfrastructure Category = "infrastructure"
	CategoryTechnology     Category = "technology"
	CategoryDNS            Category = "dns"
	CategoryExposure       Category = "exposure"
	CategoryUnclassified   Category = "unclassified"
)

// Node is a single node in the attack-surface graph.
// It wraps an existing Entity with security classification.
type Node struct {
	// Entity is the underlying Knowledge Graph entity.
	Entity domain.Entity `json:"entity"`

	// Category classifies this node's security role.
	Category Category `json:"category"`

	// ObservationCount is how many observations support this node.
	ObservationCount int `json:"observation_count"`

	// ToolSources lists which tools observed this entity.
	ToolSources []string `json:"tool_sources"`

	// Correlated indicates whether this node participates in
	// any correlations (cross-tool evidence).
	Correlated bool `json:"correlated"`
}

// Edge is a directed edge in the attack-surface graph.
type Edge struct {
	// Relationship is the underlying Knowledge Graph relationship.
	Relationship domain.Relationship `json:"relationship"`

	// SourceNode is the edge source.
	SourceNode uuid.UUID `json:"source_node"`

	// TargetNode is the edge target.
	TargetNode uuid.UUID `json:"target_node"`
}

// Graph is the attack-surface projection over the Knowledge Graph.
type Graph struct {
	// Nodes are all entities in the attack surface, keyed by ID.
	Nodes map[uuid.UUID]Node `json:"nodes"`

	// Edges are all relationships.
	Edges []Edge `json:"edges"`

	// Stats summarizes the attack surface.
	Stats Stats `json:"stats"`
}

// Stats summarizes the attack-surface graph.
type Stats struct {
	TotalNodes       int            `json:"total_nodes"`
	TotalEdges       int            `json:"total_edges"`
	NodesByCategory  map[Category]int `json:"nodes_by_category"`
	CorrelatedNodes  int            `json:"correlated_nodes"`
	MultiToolNodes   int            `json:"multi_tool_nodes"`
}

// ResearchPath represents a chain of connected entities through the
// attack surface. NOT a vulnerability claim — a structural observation.
//
// Example:
//
//	Internet → admin.example.com → 443 → nginx → /admin → /admin/upload
//
// Doge does NOT say "this is vulnerable." It says:
// "This is an externally reachable chain containing an administrative
// upload surface."
type ResearchPath struct {
	// Nodes in order from entry point to deepest surface.
	Nodes []Node `json:"nodes"`

	// Edges connecting the nodes.
	Edges []Edge `json:"edges"`

	// Description is a human-readable summary of the path.
	Description string `json:"description"`

	// SurfaceCategories lists the distinct categories traversed.
	SurfaceCategories []Category `json:"surface_categories"`

	// Depth is the number of hops.
	Depth int `json:"depth"`
}

// ClassifyEntity assigns a security surface category to an entity.
func ClassifyEntity(e domain.Entity) Category {
	switch e.Type {
	case domain.EntityIPAddress, domain.EntityPort:
		return CategoryNetwork
	case domain.EntityDomain, domain.EntitySubdomain, domain.EntityURL:
		return CategoryWeb
	case domain.EntityEndpoint:
		return classifyEndpoint(e)
	case domain.EntityTechnology, domain.EntityJavaScriptFile:
		return CategoryTechnology
	case domain.EntityService:
		return CategoryInfrastructure
	case domain.EntityCertificate:
		return CategoryInfrastructure
	case domain.EntityDNSRecord:
		return CategoryDNS
	case domain.EntityParameter, domain.EntityHeader, domain.EntityCookie:
		return CategoryWeb
	case domain.EntityGraphQLType, domain.EntityGraphQLOp:
		return CategoryAPI
	case domain.EntitySecret, domain.EntityAPIKey, domain.EntityJWT:
		return CategoryAuthentication
	case domain.EntityAuthMechanism:
		return CategoryAuthentication
	case domain.EntityCORSConfig, domain.EntityCSPDirective:
		return CategoryWeb
	default:
		return CategoryUnclassified
	}
}

// classifyEndpoint uses heuristics on the endpoint value to determine
// whether it belongs to a specific surface category.
func classifyEndpoint(e domain.Entity) Category {
	value := e.Value

	// Upload surfaces.
	for _, pattern := range uploadPatterns {
		if containsCI(value, pattern) {
			return CategoryUpload
		}
	}

	// Authentication surfaces.
	for _, pattern := range authPatterns {
		if containsCI(value, pattern) {
			return CategoryAuthentication
		}
	}

	// Authorization / admin surfaces.
	for _, pattern := range adminPatterns {
		if containsCI(value, pattern) {
			return CategoryAuthorization
		}
	}

	// API surfaces.
	for _, pattern := range apiPatterns {
		if containsCI(value, pattern) {
			return CategoryAPI
		}
	}

	return CategoryWeb
}

var uploadPatterns = []string{
	"upload", "file", "import", "attach", "media",
}

var authPatterns = []string{
	"login", "signin", "sign-in", "auth", "oauth",
	"token", "session", "register", "signup", "sign-up",
	"password", "reset", "forgot", "verify", "confirm",
	"logout", "signout",
}

var adminPatterns = []string{
	"admin", "dashboard", "manage", "console",
	"control", "panel", "config", "settings",
	"internal", "debug", "staff", "superuser",
}

var apiPatterns = []string{
	"/api/", "/api.", "/graphql", "/rest/",
	"/v1/", "/v2/", "/v3/", "/rpc",
}

func containsCI(s, substr string) bool {
	sLower := toLower(s)
	subLower := toLower(substr)
	return len(sLower) >= len(subLower) && contains(sLower, subLower)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
