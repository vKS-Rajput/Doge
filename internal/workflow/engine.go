package workflow

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

// WorkflowProbe represents an executable security test against a state machine transition.
type WorkflowProbe struct {
	ID                uuid.UUID           `json:"id"`
	WorkflowID        uuid.UUID           `json:"workflow_id"`
	Type              WorkflowAnomalyType `json:"type"`
	Title             string              `json:"title"`
	Description       string              `json:"description"`
	EndpointURL       string              `json:"endpoint_url"`
	Method            string              `json:"method"`
	Payload           map[string]any      `json:"payload,omitempty"`
	TargetState       string              `json:"target_state"`
	ExpectedFromState string              `json:"expected_from_state"`
	ActualStateAtTest string              `json:"actual_state_at_test"`
}

// Engine manages workflow modeling and state-machine vulnerability detection.
type Engine struct {
	mu        sync.RWMutex
	workflows map[uuid.UUID]*WorkflowGraph
}

// NewEngine creates a new workflow research engine.
func NewEngine() *Engine {
	return &Engine{
		workflows: make(map[uuid.UUID]*WorkflowGraph),
	}
}

// RegisterWorkflow stores a workflow state machine graph.
func (e *Engine) RegisterWorkflow(w *WorkflowGraph) error {
	if w == nil {
		return fmt.Errorf("cannot register nil workflow")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now().UTC()
	}
	e.workflows[w.ID] = w
	return nil
}

// GetWorkflow retrieves a workflow graph by ID.
func (e *Engine) GetWorkflow(id uuid.UUID) (*WorkflowGraph, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	w, ok := e.workflows[id]
	return w, ok
}

// GenerateStepSkipProbes generates probes that attempt to bypass prerequisite steps.
func (e *Engine) GenerateStepSkipProbes(w *WorkflowGraph) []*WorkflowProbe {
	if w == nil || len(w.Steps) <= 1 {
		return nil
	}

	var probes []*WorkflowProbe
	// For each step after the first, attempt to invoke it directly from the initial state
	for i := 1; i < len(w.Steps); i++ {
		step := w.Steps[i]
		probe := &WorkflowProbe{
			ID:                uuid.New(),
			WorkflowID:        w.ID,
			Type:              AnomalyStepSkip,
			Title:             fmt.Sprintf("Skip to %s (Bypass %s)", step.ToState, step.FromState),
			Description:       fmt.Sprintf("Attempt to invoke %s directly from %s without completing intermediate prerequisites", step.Name, w.InitialState),
			EndpointURL:       step.ActionEndpoint,
			Method:            step.HTTPMethod,
			Payload:           step.RequiredPayload,
			TargetState:       step.ToState,
			ExpectedFromState: step.FromState,
			ActualStateAtTest: w.InitialState,
		}
		probes = append(probes, probe)
	}

	return probes
}

// GenerateCrossPrincipalProbe generates a probe attempting an unauthorized role transition.
func (e *Engine) GenerateCrossPrincipalProbe(w *WorkflowGraph, step *WorkflowStep, actor *worldmodel.Principal) *WorkflowProbe {
	if w == nil || step == nil {
		return nil
	}

	actorName := "unprivileged"
	if actor != nil {
		actorName = actor.Name
	}

	return &WorkflowProbe{
		ID:                uuid.New(),
		WorkflowID:        w.ID,
		Type:              AnomalyUnauthorizedActor,
		Title:             fmt.Sprintf("Unauthorized Transition %s by %s", step.Name, actorName),
		Description:       fmt.Sprintf("Attempt to invoke privileged transition %s (%s -> %s) using principal %s", step.Name, step.FromState, step.ToState, actorName),
		EndpointURL:       step.ActionEndpoint,
		Method:            step.HTTPMethod,
		Payload:           step.RequiredPayload,
		TargetState:       step.ToState,
		ExpectedFromState: step.FromState,
		ActualStateAtTest: step.FromState,
	}
}

// EvaluateExecution evaluates the outcome of a state transition test.
func (e *Engine) EvaluateExecution(
	w *WorkflowGraph,
	probeType WorkflowAnomalyType,
	attemptedStep *WorkflowStep,
	initialState string,
	finalState string,
	statusCode int,
	responseBody string,
	actorName string,
) *WorkflowVulnerability {
	// If the server accepted the transition (2xx) and mutated state out-of-order
	if statusCode >= 200 && statusCode < 300 {
		switch probeType {
		case AnomalyStepSkip:
			if finalState == attemptedStep.ToState && initialState != attemptedStep.FromState {
				return &WorkflowVulnerability{
					ID:                  uuid.New(),
					WorkflowID:          w.ID,
					Type:                AnomalyStepSkip,
					Title:               fmt.Sprintf("Workflow Step Skip: %s directly to %s", initialState, finalState),
					Description:         fmt.Sprintf("Application allowed state transition to %s without executing required intermediate step (%s). Precondition validation missing.", finalState, attemptedStep.FromState),
					AttackingPrincipal:  actorName,
					AttemptedTransition: fmt.Sprintf("%s -> %s", initialState, finalState),
					ObservedResultState: finalState,
					Confidence:          0.95,
					MinimalProof:        fmt.Sprintf("Issued %s on %s in state %s; server returned HTTP %d and mutated state to %s", attemptedStep.HTTPMethod, attemptedStep.ActionEndpoint, initialState, statusCode, finalState),
					Remediation:         "Enforce strict server-side state machine precondition assertions before executing state mutation handlers.",
					DiscoveredAt:        time.Now().UTC(),
				}
			}

		case AnomalyUnauthorizedActor:
			if finalState == attemptedStep.ToState {
				return &WorkflowVulnerability{
					ID:                  uuid.New(),
					WorkflowID:          w.ID,
					Type:                AnomalyUnauthorizedActor,
					Title:               fmt.Sprintf("Unauthorized Workflow Transition: %s executed by %s", attemptedStep.Name, actorName),
					Description:         fmt.Sprintf("Unprivileged principal %s successfully triggered privileged workflow action %s causing transition to %s", actorName, attemptedStep.Name, finalState),
					AttackingPrincipal:  actorName,
					AttemptedTransition: fmt.Sprintf("%s -> %s", attemptedStep.FromState, attemptedStep.ToState),
					ObservedResultState: finalState,
					Confidence:          0.95,
					MinimalProof:        fmt.Sprintf("Principal %s issued %s %s resulting in HTTP %d and state mutation to %s", actorName, attemptedStep.HTTPMethod, attemptedStep.ActionEndpoint, statusCode, finalState),
					Remediation:         "Implement explicit role-based access control (RBAC) checks on all workflow transition endpoints.",
					DiscoveredAt:        time.Now().UTC(),
				}
			}
		}
	}

	// Clean rejection (e.g. 400 Bad Request, 403 Forbidden, 409 Conflict, 422 Unprocessable Entity)
	return nil
}
