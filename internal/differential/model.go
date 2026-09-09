package differential

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

// AuthEvaluationOutcome classifies the security implication of a differential test between principals.
type AuthEvaluationOutcome string

const (
	OutcomeBOLAConfirmed           AuthEvaluationOutcome = "BOLA_CONFIRMED"
	OutcomePrivEscConfirmed        AuthEvaluationOutcome = "PRIVILEGE_ESCALATION_CONFIRMED"
	OutcomeAuthBypassConfirmed      AuthEvaluationOutcome = "AUTHENTICATION_BYPASS_CONFIRMED"
	OutcomeStrictIsolationEnforced AuthEvaluationOutcome = "STRICT_ISOLATION_ENFORCED"
	OutcomeRoleRestricted          AuthEvaluationOutcome = "ROLE_RESTRICTED"
	OutcomePublicEndpoint          AuthEvaluationOutcome = "PUBLIC_ENDPOINT_IDENTICAL"
	OutcomeInconclusive            AuthEvaluationOutcome = "INCONCLUSIVE"
)

// OperationSpec defines the normalized HTTP request parameters for an operation.
type OperationSpec struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

// ExecutionResponse represents the observed raw HTTP response from a target.
type ExecutionResponse struct {
	StatusCode     int                 `json:"status_code"`
	Headers        map[string][]string `json:"headers"`
	Body           string              `json:"body"`
	ResponseTimeMs int64               `json:"response_time_ms"`
	Error          string              `json:"error,omitempty"`
}

// PrincipalObservation binds a specific principal context to their observed execution response.
type PrincipalObservation struct {
	Principal *worldmodel.Principal `json:"principal"`
	Response  *ExecutionResponse    `json:"response"`
}

// StructuralDiff details the multi-dimensional variances between two principal observations.
type StructuralDiff struct {
	StatusA              int                   `json:"status_a"`
	StatusB              int                   `json:"status_b"`
	IsStatusMatch        bool                  `json:"is_status_match"`
	FieldCountA          int                   `json:"field_count_a"`
	FieldCountB          int                   `json:"field_count_b"`
	ExtraKeysInA         []string              `json:"extra_keys_in_a"`
	ExtraKeysInB         []string              `json:"extra_keys_in_b"`
	ValueMismatches      []string              `json:"value_mismatches"`
	ObjectLeakDetected   bool                  `json:"object_leak_detected"`
	LeakedIdentifiers    []string              `json:"leaked_identifiers"`
	Outcome              AuthEvaluationOutcome `json:"outcome"`
	Confidence           float64               `json:"confidence"`
	MinimalProof         string                `json:"minimal_proof"`
	Explanation          string                `json:"explanation"`
}

// DifferentialTestResult encapsulates a complete cross-principal comparative experiment.
type DifferentialTestResult struct {
	ID           uuid.UUID             `json:"id"`
	TargetURL    string                `json:"target_url"`
	Operation    OperationSpec         `json:"operation"`
	ObservationA *PrincipalObservation `json:"observation_a"`
	ObservationB *PrincipalObservation `json:"observation_b"`
	Diff         *StructuralDiff       `json:"diff"`
	EvaluatedAt  time.Time             `json:"evaluated_at"`
}
