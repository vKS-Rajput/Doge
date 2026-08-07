package domain

import (
	"time"

	"github.com/google/uuid"
)

// InsightType classifies the kind of pattern detected by the
// Rule Engine or Insight Engine.
type InsightType string

const (
	InsightNewEndpoint      InsightType = "new_endpoint"
	InsightEndpointRemoved  InsightType = "endpoint_removed"
	InsightAuthChanged      InsightType = "auth_changed"
	InsightNewCookie        InsightType = "new_cookie"
	InsightCookieFlagMissing InsightType = "cookie_flag_missing"
	InsightNewTechnology    InsightType = "new_technology"
	InsightTechUpgrade      InsightType = "technology_upgrade"
	InsightCSPChange        InsightType = "csp_change"
	InsightCORSPermissive   InsightType = "cors_permissive"
	InsightAdminRoute       InsightType = "admin_route"
	InsightSecretFound      InsightType = "secret_found"
	InsightGraphQLMutation  InsightType = "graphql_mutation"
	InsightSequentialIDs    InsightType = "sequential_ids"
	InsightVersionDisclosure InsightType = "version_disclosure"
	InsightNewSubdomain     InsightType = "new_subdomain"
)

// Insight is a pattern automatically detected by the Rule Engine
// (deterministic) or Insight Engine (higher-level analysis).
//
// Insights are generated without AI involvement — they are the result
// of deterministic rules applied to incoming observations, entity
// changes, and diff results. This implements the principle:
// "deterministic before probabilistic."
type Insight struct {
	// ID is the unique identifier for this insight.
	ID uuid.UUID `json:"id"`

	// Type classifies what pattern was detected.
	Type InsightType `json:"type"`

	// Title is a human-readable summary of the insight.
	Title string `json:"title"`

	// Description provides a detailed explanation of what was detected
	// and why it may be significant.
	Description string `json:"description"`

	// Severity indicates the potential impact level.
	Severity Severity `json:"severity"`

	// EntityIDs lists the entities involved in this insight.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// EvidenceIDs lists the evidence supporting this insight.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// RuleID identifies the deterministic rule that generated this
	// insight, if applicable. Nil for insights from the Insight Engine.
	RuleID *string `json:"rule_id,omitempty"`

	// DiffID links to the diff that triggered this insight,
	// if it was generated from a structural comparison.
	DiffID *uuid.UUID `json:"diff_id,omitempty"`

	// Acknowledged indicates whether the researcher has seen and
	// acknowledged this insight.
	Acknowledged bool `json:"acknowledged"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// DetectedAt is when this insight was discovered.
	DetectedAt time.Time `json:"detected_at"`
}
