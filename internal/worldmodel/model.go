package worldmodel

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// PrincipalType defines categories of actors and security contexts in an application.
type PrincipalType string

const (
	PrincipalAnonymous      PrincipalType = "anonymous"
	PrincipalUser           PrincipalType = "authenticated_user"
	PrincipalTenantAdmin    PrincipalType = "tenant_admin"
	PrincipalSystemAdmin    PrincipalType = "system_admin"
	PrincipalServiceAccount PrincipalType = "service_account"
	PrincipalAPIClient      PrincipalType = "api_client"
)

// Principal represents a security identity with specific permissions, tenant affiliation, and credentials.
type Principal struct {
	ID            uuid.UUID         `json:"id"`
	Name          string            `json:"name"`
	Type          PrincipalType     `json:"type"`
	TenantID      *uuid.UUID        `json:"tenant_id,omitempty"`
	Roles         []string          `json:"roles"`
	Permissions   []string          `json:"permissions"`
	Headers       map[string]string `json:"headers"`
	SessionTokens map[string]string `json:"session_tokens"`
	Attributes    map[string]any    `json:"attributes"`
	CreatedAt     time.Time         `json:"created_at"`
}

// Tenant represents an organizational boundary or tenant partition in a multi-tenant application.
type Tenant struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Domain     string         `json:"domain"`
	Tier       string         `json:"tier"`
	Attributes map[string]any `json:"attributes"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Account represents a user account record belonging to a tenant and principal.
type Account struct {
	ID          uuid.UUID      `json:"id"`
	PrincipalID uuid.UUID      `json:"principal_id"`
	TenantID    *uuid.UUID     `json:"tenant_id,omitempty"`
	Email       string         `json:"email"`
	Status      string         `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
}

// ObjectResource represents an addressable entity/resource inside the application (e.g. invoice, order, user profile).
type ObjectResource struct {
	ID               uuid.UUID      `json:"id"`
	Type             string         `json:"type"` // e.g. "invoice", "user", "order", "document"
	Identifier       string         `json:"identifier"` // e.g. "1001", "inv_99281"
	TenantID         *uuid.UUID     `json:"tenant_id,omitempty"`
	OwnerPrincipalID *uuid.UUID     `json:"owner_principal_id,omitempty"`
	EndpointID       *uuid.UUID     `json:"endpoint_id,omitempty"`
	EndpointURL      string         `json:"endpoint_url,omitempty"`
	Attributes       map[string]any `json:"attributes"`
	CreatedAt        time.Time      `json:"created_at"`
}

// ParameterModel represents a query, path, body, or header parameter on an endpoint.
type ParameterModel struct {
	ID                 uuid.UUID `json:"id"`
	EndpointID         uuid.UUID `json:"endpoint_id"`
	Name               string    `json:"name"`
	Location           string    `json:"location"` // query, path, body, header, cookie
	Type               string    `json:"type"`
	IsObjectIdentifier bool      `json:"is_object_identifier"`
	IsURLParameter     bool      `json:"is_url_parameter"`
	SampleValues       []string  `json:"sample_values"`
}

// EndpointModel represents an API route or web endpoint within the world model.
type EndpointModel struct {
	ID             uuid.UUID         `json:"id"`
	Host           string            `json:"host"`
	Path           string            `json:"path"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	RequiresAuth   bool              `json:"requires_auth"`
	RequiredRoles  []string          `json:"required_roles"`
	Parameters     []*ParameterModel `json:"parameters"`
	StateRequired  string            `json:"state_required,omitempty"`
	Attributes     map[string]any    `json:"attributes"`
	FirstSeenAt    time.Time         `json:"first_seen_at"`
}

// StateNode represents a distinct business logic state in an application workflow (e.g. UNVERIFIED, ACTIVE, SUSPENDED).
type StateNode struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Domain        string    `json:"domain"`
	Preconditions []string  `json:"preconditions"`
	Invariants    []string  `json:"invariants"`
}

// StateTransition represents a valid or observed state transition action.
type StateTransition struct {
	ID                uuid.UUID       `json:"id"`
	FromState         string          `json:"from_state"`
	ToState           string          `json:"to_state"`
	ActionName        string          `json:"action_name"`
	EndpointID        *uuid.UUID      `json:"endpoint_id,omitempty"`
	RequiredRole      string          `json:"required_role"`
	AllowedPrincipals []PrincipalType `json:"allowed_principals"`
}

// ResearchGapType classifies the domain of missing knowledge or uncertainty.
type ResearchGapType string

const (
	GapUnknownAuthBoundary        ResearchGapType = "UNKNOWN_AUTHORIZATION_BOUNDARY"
	GapUnknownTenantIsolation     ResearchGapType = "UNKNOWN_TENANT_ISOLATION"
	GapUnknownWorkflowTransition  ResearchGapType = "UNKNOWN_WORKFLOW_TRANSITION"
	GapUnknownObjectOwnership     ResearchGapType = "UNKNOWN_OBJECT_OWNERSHIP"
	GapUnknownParamBehavior       ResearchGapType = "UNKNOWN_PARAMETER_BEHAVIOR"
	GapUnknownStateRequirement    ResearchGapType = "UNKNOWN_STATE_REQUIREMENT"
	GapUnknownSessionBoundary     ResearchGapType = "UNKNOWN_SESSION_BOUNDARY"
	GapUnknownPrivilegeBoundary   ResearchGapType = "UNKNOWN_PRIVILEGE_BOUNDARY"
	GapUnknownDataFlow            ResearchGapType = "UNKNOWN_DATA_FLOW"
	GapUnknownExternalInteraction ResearchGapType = "UNKNOWN_EXTERNAL_INTERACTION"
)

// GapStatus tracks the investigation lifecycle of a research gap.
type GapStatus string

const (
	GapStatusOpen              GapStatus = "open"
	GapStatusInvestigating     GapStatus = "investigating"
	GapStatusResolved          GapStatus = "resolved"
	GapStatusAcceptedUnknown   GapStatus = "accepted_unknown"
)

// CandidateExperiment represents a concrete experiment designed to reduce uncertainty for a research gap.
type CandidateExperiment struct {
	ID                 uuid.UUID  `json:"id"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	Tool               string     `json:"tool"`
	Command            string     `json:"command"`
	Target             string     `json:"target"`
	PrimaryPrincipal   *Principal `json:"primary_principal,omitempty"`
	SecondaryPrincipal *Principal `json:"secondary_principal,omitempty"`
	ExpectedInfoGain   float64    `json:"expected_info_gain"`
	Risk               string     `json:"risk"`
	Cost               float64    `json:"cost"`
}

// ResearchGap represents an explicit unknown or unverified boundary in the application's security model.
type ResearchGap struct {
	ID                   uuid.UUID              `json:"id"`
	Type                 ResearchGapType        `json:"type"`
	Description          string                 `json:"description"`
	Uncertainty          float64                `json:"uncertainty"` // 0.0 (certain) to 1.0 (completely unprobed)
	AffectedEntityIDs    []uuid.UUID            `json:"affected_entity_ids"`
	AffectedEndpoints    []string               `json:"affected_endpoints"`
	Evidence             []string               `json:"evidence"`
	CandidateExperiments []*CandidateExperiment `json:"candidate_experiments"`
	ExpectedInfoGain     float64                `json:"expected_info_gain"`
	Risk                 string                 `json:"risk"`
	Cost                 float64                `json:"cost"`
	Status               GapStatus              `json:"status"`
	DiscoveredAt         time.Time              `json:"discovered_at"`
	ResolvedAt           *time.Time             `json:"resolved_at,omitempty"`
	ResolutionProof      string                 `json:"resolution_proof,omitempty"`
}

// WorldRelationship represents a directed relational edge in the world model graph.
type WorldRelationship struct {
	ID         uuid.UUID               `json:"id"`
	SourceID   uuid.UUID               `json:"source_id"`
	TargetID   uuid.UUID               `json:"target_id"`
	Type       domain.RelationshipType `json:"type"`
	Attributes map[string]any          `json:"attributes"`
	CreatedAt  time.Time               `json:"created_at"`
}
