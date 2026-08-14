// Package validation implements controlled validation execution.
//
// v0.9.5 is NOT "give the LLM a shell." It is a structured,
// bounded, scope-enforced execution layer that:
//
//  1. Takes a human-approved ValidationPlan from v0.9.4
//  2. Translates it into typed, bounded actions
//  3. Checks every action against scope and safety policy
//  4. Executes permitted actions via bounded HTTP
//  5. Captures results as new immutable observations
//  6. Feeds results back into the evidence pipeline
//  7. Re-evaluates the hypothesis
//
// Critical boundaries:
//   - The AI NEVER constructs raw HTTP requests
//   - The AI NEVER sees credential values
//   - GET ≠ non-destructive (lower-risk transport method only)
//   - Every redirect is a new security decision
//   - Approved plans are immutable (digest-verified)
package validation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// --- Action Types ---

// ActionType classifies what a validation action does.
type ActionType string

const (
	// ActionHTTPRequest sends a single HTTP request.
	ActionHTTPRequest ActionType = "http_request"

	// ActionHTTPCompare sends two requests and compares responses.
	ActionHTTPCompare ActionType = "http_compare"

	// ActionRoleCompare sends the same request as different roles.
	ActionRoleCompare ActionType = "http_role_compare"

	// ActionHeaderCheck inspects response headers.
	ActionHeaderCheck ActionType = "header_check"

	// ActionEndpointProbe checks if an endpoint responds.
	ActionEndpointProbe ActionType = "endpoint_probe"
)

// SafetyClass classifies action risk.
type SafetyClass string

const (
	// SafetyReadOnly indicates GET/HEAD/OPTIONS transport methods.
	// NOTE: HTTP method safety ≠ application safety.
	// GET /admin/delete?id=123 is a GET that deletes data.
	SafetyReadOnly SafetyClass = "read_only"

	// SafetyLowImpact indicates read-only transport that may trigger logging.
	SafetyLowImpact SafetyClass = "low_impact"
)

// SafetyDisclaimer is attached to every validation result.
//
// HTTP method safety and application safety are NOT the same.
const SafetyDisclaimer = "HTTP method does not establish non-destructiveness. " +
	"Review target application behavior before approving validation plans."

// AllowedMethods are the ONLY HTTP methods permitted in v0.9.5.
var AllowedMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"OPTIONS": true,
}

// --- Action ---

// Action is a typed, structured validation action.
//
// The AI never sees or constructs this. The Action Translator
// produces it from an approved ValidationPlan.
type Action struct {
	// ID uniquely identifies this action.
	ID uuid.UUID `json:"id"`

	// PlanID links to the parent validation plan.
	PlanID uuid.UUID `json:"plan_id"`

	// HypothesisID links to the hypothesis being tested.
	HypothesisID uuid.UUID `json:"hypothesis_id"`

	// Type classifies the action.
	Type ActionType `json:"type"`

	// Target is the hostname or IP (must be in scope).
	Target string `json:"target"`

	// Method is the HTTP method (GET, HEAD, OPTIONS only in v0.9.5).
	Method string `json:"method"`

	// Path is the URL path component.
	Path string `json:"path"`

	// QueryParams are URL query parameters.
	QueryParams map[string]string `json:"query_params,omitempty"`

	// CredentialProfileID references a pre-registered credential.
	// Empty string = anonymous. The AI never sees the credential value.
	CredentialProfileID string `json:"credential_profile_id,omitempty"`

	// ExpectedResult describes what we expect to observe.
	ExpectedResult string `json:"expected_result"`

	// SafetyClass classifies the risk level.
	SafetyClass SafetyClass `json:"safety_class"`

	// Timeout per-request.
	Timeout time.Duration `json:"timeout"`
}

// --- Result ---

// Result is the raw HTTP response from a validation action.
type Result struct {
	// StatusCode is the HTTP status code.
	StatusCode int `json:"status_code"`

	// Headers are the response headers.
	Headers map[string][]string `json:"headers"`

	// BodyHash is the SHA-256 of the response body.
	// The actual body is NOT stored (could contain attacker data).
	BodyHash string `json:"body_hash"`

	// BodySize is the response body size in bytes.
	BodySize int `json:"body_size"`

	// Duration is how long the request took.
	Duration time.Duration `json:"duration"`

	// Timestamp is when the response was received.
	Timestamp time.Time `json:"timestamp"`
}

// ActionResult pairs an action with its result (or error).
type ActionResult struct {
	Action     Action    `json:"action"`
	Result     *Result   `json:"result,omitempty"`
	Error      error     `json:"error,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}

// PlanResult is the complete result of executing a validation plan.
type PlanResult struct {
	PlanID         uuid.UUID      `json:"plan_id"`
	HypothesisID   uuid.UUID      `json:"hypothesis_id"`
	Results        []ActionResult `json:"results"`
	Completed      bool           `json:"completed"`
	BudgetExhausted bool          `json:"budget_exhausted"`
	SafetyDisclaimer string       `json:"safety_disclaimer"`
}

// --- Credential Profiles ---

// CredentialProfile is a pre-registered set of authentication
// credentials for testing authorization boundaries.
//
// CRITICAL: The AI receives ONLY the profile ID and role name.
// It NEVER receives the actual token, password, or cookie value.
type CredentialProfile struct {
	// ID identifies this profile (e.g., "admin-test-user").
	ID string `json:"id"`

	// Role describes the authorization level (e.g., "admin", "user", "anonymous").
	Role string `json:"role"`

	// Description provides context for humans reviewing the plan.
	Description string `json:"description"`

	// ProjectID scopes credentials to a project.
	ProjectID uuid.UUID `json:"project_id"`

	// Headers are stored encrypted at rest.
	// Only the executor reads them. Never exposed to AI or logs.
	Headers map[string]string `json:"-"` // Excluded from JSON serialization
}

// AllowedCredentialHeaders are the ONLY headers that credentials
// may inject. Everything else is rejected.
var AllowedCredentialHeaders = map[string]bool{
	"authorization": true,
	"cookie":        true,
}

// --- Request Budgets ---

// RequestBudget enforces three-tier request limits.
//
// No collection of plans can bypass a higher-level budget.
//
//	Per-plan:        20 (default)
//	Per-hypothesis:  60 (default, 3 plans × 20)
//	Per-engagement:  configurable per project
type RequestBudget struct {
	// PerPlan is the max requests per validation plan. Default: 20.
	PerPlan int `json:"per_plan"`

	// PerHypothesis is the aggregate max per hypothesis. Default: 60.
	PerHypothesis int `json:"per_hypothesis"`

	// PerEngagement is the engagement-wide max. Configurable.
	PerEngagement int `json:"per_engagement"`

	// Current counters.
	planCounts       map[uuid.UUID]int
	hypothesisCounts map[uuid.UUID]int
	engagementCount  int
}

// NewRequestBudget creates a budget with defaults.
func NewRequestBudget(perPlan, perHypothesis, perEngagement int) *RequestBudget {
	if perPlan <= 0 {
		perPlan = 20
	}
	if perHypothesis <= 0 {
		perHypothesis = 60
	}
	if perEngagement <= 0 {
		perEngagement = 200
	}
	return &RequestBudget{
		PerPlan:          perPlan,
		PerHypothesis:    perHypothesis,
		PerEngagement:    perEngagement,
		planCounts:       make(map[uuid.UUID]int),
		hypothesisCounts: make(map[uuid.UUID]int),
	}
}

// CheckBudget returns nil if the request is within all three budgets.
func (b *RequestBudget) CheckBudget(planID, hypothesisID uuid.UUID) error {
	if b.planCounts[planID] >= b.PerPlan {
		return fmt.Errorf("plan budget exhausted (%d/%d)", b.planCounts[planID], b.PerPlan)
	}
	if b.hypothesisCounts[hypothesisID] >= b.PerHypothesis {
		return fmt.Errorf("hypothesis budget exhausted (%d/%d)",
			b.hypothesisCounts[hypothesisID], b.PerHypothesis)
	}
	if b.engagementCount >= b.PerEngagement {
		return fmt.Errorf("engagement budget exhausted (%d/%d)",
			b.engagementCount, b.PerEngagement)
	}
	return nil
}

// RecordRequest increments all three counters.
func (b *RequestBudget) RecordRequest(planID, hypothesisID uuid.UUID) {
	b.planCounts[planID]++
	b.hypothesisCounts[hypothesisID]++
	b.engagementCount++
}

// Remaining returns the requests remaining at each tier.
func (b *RequestBudget) Remaining(planID, hypothesisID uuid.UUID) (plan, hypothesis, engagement int) {
	return b.PerPlan - b.planCounts[planID],
		b.PerHypothesis - b.hypothesisCounts[hypothesisID],
		b.PerEngagement - b.engagementCount
}

// --- Approval Binding ---

// ApprovalRecord binds a human approval to a specific plan version.
//
// An approved plan is IMMUTABLE. Any modification to target, action,
// method, path, query parameters, credential profile, or safety
// properties invalidates the approval.
//
// The executor MUST verify the plan digest before execution.
type ApprovalRecord struct {
	// PlanID identifies the approved plan.
	PlanID uuid.UUID `json:"plan_id"`

	// PlanDigest is the SHA-256 of the canonical plan representation.
	// If the plan changes after approval, the digest won't match.
	PlanDigest string `json:"plan_digest"`

	// Approver identifies who approved the plan.
	Approver string `json:"approver"`

	// ApprovedAt is when the approval was granted.
	ApprovedAt time.Time `json:"approved_at"`

	// ProjectID scopes the approval to a project.
	ProjectID uuid.UUID `json:"project_id"`
}

// ExecutablePlan is a plan that has been approved and is ready
// for execution. It carries the approval record and the actions.
type ExecutablePlan struct {
	// ID is the plan identifier.
	ID uuid.UUID `json:"id"`

	// HypothesisID links to the hypothesis being tested.
	HypothesisID uuid.UUID `json:"hypothesis_id"`

	// Actions are the typed actions to execute.
	Actions []Action `json:"actions"`

	// Approval is the human approval record.
	Approval ApprovalRecord `json:"approval"`

	// ProjectID scopes execution to a project.
	ProjectID uuid.UUID `json:"project_id"`
}

// ComputePlanDigest computes the SHA-256 digest of a plan's
// security-relevant fields. Any change to these fields
// invalidates the approval.
func ComputePlanDigest(actions []Action) string {
	// Create a canonical representation of all security-relevant fields.
	type digestAction struct {
		Type                ActionType        `json:"type"`
		Target              string            `json:"target"`
		Method              string            `json:"method"`
		Path                string            `json:"path"`
		QueryParams         map[string]string `json:"query_params,omitempty"`
		CredentialProfileID string            `json:"credential_profile_id,omitempty"`
		SafetyClass         SafetyClass       `json:"safety_class"`
	}

	canonical := make([]digestAction, len(actions))
	for i, a := range actions {
		canonical[i] = digestAction{
			Type:                a.Type,
			Target:              a.Target,
			Method:              a.Method,
			Path:                a.Path,
			QueryParams:         a.QueryParams,
			CredentialProfileID: a.CredentialProfileID,
			SafetyClass:         a.SafetyClass,
		}
	}

	data, _ := json.Marshal(canonical)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// VerifyApproval checks that the plan has not been modified
// since it was approved.
func VerifyApproval(plan ExecutablePlan) error {
	currentDigest := ComputePlanDigest(plan.Actions)
	if currentDigest != plan.Approval.PlanDigest {
		return fmt.Errorf(
			"plan has been modified since approval (expected digest %s, got %s)",
			plan.Approval.PlanDigest, currentDigest)
	}
	return nil
}
