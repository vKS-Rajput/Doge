package learning

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FailureMode classifies why a specific research action or probe was unsuccessful.
type FailureMode string

const (
	FailureModeTenantAccessDenied    FailureMode = "TENANT_403_DENIAL"
	FailureModeWAFBlocked             FailureMode = "WAF_BLOCK_TRIGGERED"
	FailureModeURLWhitelistRejection FailureMode = "URL_WHITELIST_ENFORCED"
	FailureModeStrictAuthRequired     FailureMode = "AUTH_BOUNDARY_ENFORCED"
	FailureModeSchemaValidationError  FailureMode = "SCHEMA_VALIDATION_REJECTION"
	FailureModeStatePreconditionError FailureMode = "STATE_MACHINE_PRECONDITION_ENFORCED"
	FailureModeEndpointNotFound       FailureMode = "ENDPOINT_404_NOT_FOUND"
	FailureModeTimeoutNoResponse      FailureMode = "NETWORK_TIMEOUT_NO_EGRESS"
)

// FailureSignature records a repeatable failure pattern to prevent futile probe repetition.
type FailureSignature struct {
	ID             uuid.UUID   `json:"id"`
	ActionType     string      `json:"action_type"`
	TargetEndpoint string      `json:"target_endpoint"`
	FailureMode    FailureMode `json:"failure_mode"`
	Reason         string      `json:"reason"`
	PenaltyFactor  float64     `json:"penalty_factor"` // e.g., -0.85
	FirstFailedAt  time.Time   `json:"first_failed_at"`
	LastFailedAt   time.Time   `json:"last_failed_at"`
	FailureCount   int         `json:"failure_count"`
}

// ClassifyFailureMode inspects HTTP response status and body to extract a failure signature.
func ClassifyFailureMode(actionType, endpoint string, statusCode int, stdout, stderr string) *FailureSignature {
	combined := strings.ToLower(stdout + "\n" + stderr)
	now := time.Now().UTC()

	var mode FailureMode
	var reason string
	var penalty float64 = -0.60

	switch {
	case statusCode == 403 || strings.Contains(combined, "403 forbidden") || strings.Contains(combined, "access denied") || strings.Contains(combined, "tenant mismatch"):
		mode = FailureModeTenantAccessDenied
		reason = "Strict multi-tenant isolation or RBAC middleware actively rejected unauthorized access"
		penalty = -0.80

	case statusCode == 401 || strings.Contains(combined, "401 unauthorized") || strings.Contains(combined, "jwt expired") || strings.Contains(combined, "login required"):
		mode = FailureModeStrictAuthRequired
		reason = "Route strictly requires authenticated high-privilege session token"
		penalty = -0.70

	case strings.Contains(combined, "cloudflare") || strings.Contains(combined, "waf") || strings.Contains(combined, "403 error: request blocked"):
		mode = FailureModeWAFBlocked
		reason = "Payload triggered perimeter WAF rule; probe signature blocked"
		penalty = -0.90

	case strings.Contains(combined, "whitelist") || strings.Contains(combined, "invalid host") || strings.Contains(combined, "domain not allowed"):
		mode = FailureModeURLWhitelistRejection
		reason = "Target enforces strict URL domain whitelist; remote egress blocked"
		penalty = -0.85

	case statusCode == 409 || strings.Contains(combined, "invalid state") || strings.Contains(combined, "precondition failed"):
		mode = FailureModeStatePreconditionError
		reason = "State machine precondition check strictly enforced"
		penalty = -0.75

	case statusCode == 404 || strings.Contains(combined, "404 not found"):
		mode = FailureModeEndpointNotFound
		reason = "Target resource or endpoint does not exist"
		penalty = -0.95

	case strings.Contains(combined, "timeout") || strings.Contains(combined, "connection refused"):
		mode = FailureModeTimeoutNoResponse
		reason = "Network connection timed out or socket dropped"
		penalty = -0.50

	default:
		return nil
	}

	return &FailureSignature{
		ID:             uuid.New(),
		ActionType:     actionType,
		TargetEndpoint: endpoint,
		FailureMode:    mode,
		Reason:         fmt.Sprintf("[%s] %s", mode, reason),
		PenaltyFactor:  penalty,
		FirstFailedAt:  now,
		LastFailedAt:   now,
		FailureCount:   1,
	}
}
