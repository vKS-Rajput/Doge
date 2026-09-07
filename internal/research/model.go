package research

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/planner"
)

// LoopState defines the state machine states for the autonomous research loop.
type LoopState string

const (
	StateIdle          LoopState = "IDLE"
	StateObserving     LoopState = "OBSERVING"
	StateUnderstanding LoopState = "UNDERSTANDING"
	StateHypothesizing LoopState = "HYPOTHESIZING"
	StatePrioritizing  LoopState = "PRIORITIZING"
	StatePlanning      LoopState = "PLANNING"
	StateGated         LoopState = "GATED"
	StateExecuting     LoopState = "EXECUTING"
	StateEvaluating    LoopState = "EVALUATING"
	StateLearning      LoopState = "LEARNING"
	StateCompleted     LoopState = "COMPLETED"
	StatePaused        LoopState = "PAUSED"
	StateFailed        LoopState = "FAILED"
)

// AuditEntry records a tamper-evident audit record of an autonomous action or decision.
type AuditEntry struct {
	ID          uuid.UUID              `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	State       LoopState              `json:"state"`
	Action      string                 `json:"action"`
	Target      string                 `json:"target,omitempty"`
	Tool        string                 `json:"tool,omitempty"`
	Reason      string                 `json:"reason"`
	ScopeCheck  string                 `json:"scope_check"`
	GateID      *uuid.UUID             `json:"gate_id,omitempty"`
	Details     map[string]any         `json:"details,omitempty"`
}

// SessionSnapshot provides a full serialized state for session resume and monitoring.
type SessionSnapshot struct {
	SessionID        uuid.UUID                      `json:"session_id"`
	Target           string                         `json:"target"`
	Environment      string                         `json:"environment"`
	CurrentState     LoopState                      `json:"current_state"`
	CurrentPhase     planner.ResearchPhase          `json:"current_phase"`
	Iteration        int                            `json:"iteration"`
	EntityCount      int                            `json:"entity_count"`
	ObservationCount int                            `json:"observation_count"`
	Hypotheses       []*hypothesis.ResearchHypothesis `json:"hypotheses"`
	PendingGates     []*gates.Gate                  `json:"pending_gates"`
	CompletedActions int                            `json:"completed_actions"`
	PlannedActions   int                            `json:"planned_actions"`
	StartedAt        time.Time                      `json:"started_at"`
	LastUpdatedAt    time.Time                      `json:"last_updated_at"`
}

// StepResult summarizes the outcome of a single research loop execution cycle.
type StepResult struct {
	PreviousState   LoopState              `json:"previous_state"`
	CurrentState    LoopState              `json:"current_state"`
	ActionExecuted  *planner.ResearchAction `json:"action_executed,omitempty"`
	NewHypotheses   int                    `json:"new_hypotheses"`
	NewObservations int                    `json:"new_observations"`
	PendingGate     *gates.Gate            `json:"pending_gate,omitempty"`
	Message         string                 `json:"message"`
}
