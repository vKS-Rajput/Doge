package workflow

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

// WorkflowAnomalyType classifies vulnerabilities arising from broken business logic and state machine violations.
type WorkflowAnomalyType string

const (
	AnomalyStepSkip          WorkflowAnomalyType = "STEP_SKIPPED_UNAUTHORIZED_PROGRESSION"
	AnomalyOutOfOrder        WorkflowAnomalyType = "OUT_OF_ORDER_STATE_TRANSITION"
	AnomalyReplay            WorkflowAnomalyType = "REPLAY_OF_EXHAUSTED_TRANSITION"
	AnomalyUnauthorizedActor WorkflowAnomalyType = "UNAUTHORIZED_PRINCIPAL_TRANSITION"
	AnomalyPrivilegeJump     WorkflowAnomalyType = "ILLEGAL_PRIVILEGE_STATE_JUMP"
)

// WorkflowStep models an individual state transition action within an application workflow.
type WorkflowStep struct {
	ID                    uuid.UUID                 `json:"id"`
	SequenceOrder         int                       `json:"sequence_order"`
	Name                  string                    `json:"name"`
	FromState             string                    `json:"from_state"`
	ToState               string                    `json:"to_state"`
	ActionEndpoint        string                    `json:"action_endpoint"`
	HTTPMethod            string                    `json:"http_method"`
	RequiredPayload       map[string]any            `json:"required_payload,omitempty"`
	RequiredPrincipalType worldmodel.PrincipalType  `json:"required_principal_type"`
	IsPrivileged          bool                      `json:"is_privileged"`
}

// WorkflowGraph defines an entire multi-step business process with defined entry, intermediate, and terminal states.
type WorkflowGraph struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	InitialState   string          `json:"initial_state"`
	TerminalStates []string        `json:"terminal_states"`
	Steps          []*WorkflowStep `json:"steps"`
	CreatedAt      time.Time       `json:"created_at"`
}

// WorkflowVulnerability represents a verified business logic or state machine flaw.
type WorkflowVulnerability struct {
	ID                  uuid.UUID           `json:"id"`
	WorkflowID          uuid.UUID           `json:"workflow_id"`
	Type                WorkflowAnomalyType `json:"type"`
	Title               string              `json:"title"`
	Description         string              `json:"description"`
	AttackingPrincipal  string              `json:"attacking_principal"`
	AttemptedTransition string              `json:"attempted_transition"`
	ObservedResultState string              `json:"observed_result_state"`
	Confidence          float64             `json:"confidence"`
	MinimalProof        string              `json:"minimal_proof"`
	Remediation         string              `json:"remediation"`
	DiscoveredAt        time.Time           `json:"discovered_at"`
}
