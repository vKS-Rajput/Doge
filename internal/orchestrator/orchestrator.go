// Package orchestrator connects the DOGE research pipeline into
// one event-driven machine.
//
// The orchestrator is a WORKFLOW COORDINATOR, not an autonomous agent.
// It listens for pipeline events and triggers the next deterministic
// stage automatically. Human gates are NEVER bypassed.
//
// Automatic (deterministic) pipeline:
//
//	observation.created  → correlation
//	correlation.discovered → surface update
//	surface.updated → novelty detection
//	novelty.detected → opportunity generation
//	opportunity.created → AI reasoning
//	reasoning.completed → (hypothesis created, awaiting approval)
//	validation.completed → re-evaluation → candidate creation
//
// Human gates (NEVER automatic):
//
//	hypothesis → HUMAN APPROVAL → validation
//	candidate → HUMAN CONFIRMATION → finding
//
// The orchestrator does NOT:
//   - Make epistemic decisions
//   - Override human approval
//   - Auto-confirm findings
//   - Auto-approve validation plans
package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// PipelineStage names each stage in the research pipeline.
type PipelineStage string

const (
	StageCorrelation PipelineStage = "correlation"
	StageSurface     PipelineStage = "surface"
	StageNovelty     PipelineStage = "novelty"
	StageOpportunity PipelineStage = "opportunity"
	StageReasoning   PipelineStage = "reasoning"
	StageValidation  PipelineStage = "validation"
	StageReeval      PipelineStage = "re-evaluation"
	StageCandidate   PipelineStage = "candidate"
	StageFinding     PipelineStage = "finding"
)

// StageResult captures what happened when a stage ran.
type StageResult struct {
	Stage     PipelineStage `json:"stage"`
	ProjectID uuid.UUID     `json:"project_id"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// StageHandler is a function the orchestrator calls for each pipeline stage.
// Each handler wraps the actual subsystem (correlation engine, novelty engine, etc.).
// The orchestrator doesn't know the internals — it just calls handlers.
type StageHandler func(ctx context.Context, projectID uuid.UUID, triggerEventID uuid.UUID) error

// Orchestrator connects the research pipeline stages via the event bus.
type Orchestrator struct {
	eventBus *bus.Bus
	logger   *slog.Logger

	// Stage handlers — one per pipeline stage.
	handlers map[PipelineStage]StageHandler

	// subscriptionIDs tracks event bus subscriptions for cleanup.
	subscriptionIDs []bus.SubscriptionID

	// Pipeline stats.
	mu      sync.RWMutex
	results []StageResult
}

// New creates an orchestrator connected to the event bus.
func New(eventBus *bus.Bus, logger *slog.Logger) *Orchestrator {
	return &Orchestrator{
		eventBus: eventBus,
		logger:   logger,
		handlers: make(map[PipelineStage]StageHandler),
	}
}

// RegisterHandler registers a handler for a pipeline stage.
func (o *Orchestrator) RegisterHandler(stage PipelineStage, handler StageHandler) {
	o.handlers[stage] = handler
}

// Start subscribes to pipeline events and begins orchestration.
func (o *Orchestrator) Start() {
	// Automatic pipeline: deterministic stages.
	o.subscribe(events.TopicObservationCreated, StageCorrelation)
	o.subscribe(events.TopicObservationBatch, StageCorrelation)
	o.subscribe(events.TopicCorrelationDiscovered, StageSurface)
	o.subscribe(events.TopicSurfaceUpdated, StageNovelty)
	o.subscribe(events.TopicNoveltyDetected, StageOpportunity)
	o.subscribe(events.TopicOpportunityCreated, StageReasoning)
	o.subscribe(events.TopicValidationCompleted, StageReeval)

	o.logger.Info("orchestrator started",
		"stages", len(o.handlers),
		"subscriptions", len(o.subscriptionIDs),
	)
}

// subscribe creates an event bus subscription that triggers a stage.
func (o *Orchestrator) subscribe(topic events.Topic, stage PipelineStage) {
	subID := o.eventBus.Subscribe(topic, func(ctx context.Context, event events.Event) error {
		return o.runStage(ctx, stage, extractProjectID(event), event.EventID())
	})
	o.subscriptionIDs = append(o.subscriptionIDs, subID)

	o.logger.Debug("orchestrator subscribed",
		"topic", string(topic),
		"stage", string(stage),
	)
}

// runStage executes a pipeline stage handler and records the result.
func (o *Orchestrator) runStage(ctx context.Context, stage PipelineStage, projectID uuid.UUID, triggerID uuid.UUID) error {
	handler, ok := o.handlers[stage]
	if !ok {
		o.logger.Debug("no handler registered for stage, skipping",
			"stage", string(stage),
		)
		return nil
	}

	o.logger.Info("pipeline stage triggered",
		"stage", string(stage),
		"project_id", projectID,
		"trigger_event", triggerID,
	)

	start := time.Now()
	err := handler(ctx, projectID, triggerID)
	duration := time.Since(start)

	result := StageResult{
		Stage:     stage,
		ProjectID: projectID,
		Success:   err == nil,
		Duration:  duration,
		Timestamp: time.Now().UTC(),
	}
	if err != nil {
		result.Error = err.Error()
		o.logger.Error("pipeline stage failed",
			"stage", string(stage),
			"project_id", projectID,
			"error", err,
			"duration_ms", duration.Milliseconds(),
		)
	} else {
		o.logger.Info("pipeline stage completed",
			"stage", string(stage),
			"project_id", projectID,
			"duration_ms", duration.Milliseconds(),
		)
	}

	o.mu.Lock()
	o.results = append(o.results, result)
	o.mu.Unlock()

	return err
}

// Stop unsubscribes from all events.
func (o *Orchestrator) Stop() {
	for _, subID := range o.subscriptionIDs {
		o.eventBus.Unsubscribe(subID)
	}
	o.subscriptionIDs = nil
	o.logger.Info("orchestrator stopped")
}

// Results returns the pipeline execution history.
func (o *Orchestrator) Results() []StageResult {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]StageResult, len(o.results))
	copy(out, o.results)
	return out
}

// Stats returns pipeline statistics.
func (o *Orchestrator) Stats() PipelineStats {
	o.mu.RLock()
	defer o.mu.RUnlock()

	stats := PipelineStats{
		StageCounts: make(map[PipelineStage]int),
		StageErrors: make(map[PipelineStage]int),
	}

	for _, r := range o.results {
		stats.TotalRuns++
		stats.StageCounts[r.Stage]++
		if !r.Success {
			stats.TotalErrors++
			stats.StageErrors[r.Stage]++
		}
	}

	return stats
}

// PipelineStats summarizes orchestrator activity.
type PipelineStats struct {
	TotalRuns   int                      `json:"total_runs"`
	TotalErrors int                      `json:"total_errors"`
	StageCounts map[PipelineStage]int    `json:"stage_counts"`
	StageErrors map[PipelineStage]int    `json:"stage_errors"`
}

// extractProjectID extracts the project ID from known event types.
func extractProjectID(event events.Event) uuid.UUID {
	switch e := event.(type) {
	case events.ObservationCreated:
		return e.ProjectID
	case events.ObservationBatch:
		return e.ProjectID
	case events.CorrelationDiscovered:
		return uuid.UUID{} // Correlations don't carry project ID directly.
	case events.SurfaceUpdated:
		return e.ProjectID
	case events.NoveltyDetected:
		return e.ProjectID
	case events.OpportunityCreated:
		return e.ProjectID
	case events.ValidationCompleted:
		return e.ProjectID
	default:
		return uuid.UUID{}
	}
}

// --- Investigation State Machine ---

// InvestigationState tracks the state of an active investigation
// through the pipeline.
type InvestigationState struct {
	InvestigationID uuid.UUID     `json:"investigation_id"`
	ProjectID       uuid.UUID     `json:"project_id"`
	CurrentStage    PipelineStage `json:"current_stage"`
	StartedAt       time.Time     `json:"started_at"`
	UpdatedAt       time.Time     `json:"updated_at"`

	// Counters.
	ObservationsProcessed int `json:"observations_processed"`
	CorrelationsFound     int `json:"correlations_found"`
	NoveltySignals        int `json:"novelty_signals"`
	OpportunitiesCreated  int `json:"opportunities_created"`
	HypothesesGenerated   int `json:"hypotheses_generated"`
	ValidationsExecuted   int `json:"validations_executed"`
	CandidatesCreated     int `json:"candidates_created"`
	FindingsConfirmed     int `json:"findings_confirmed"`

	// Human gates pending.
	PendingApprovals      int `json:"pending_approvals"`
	PendingConfirmations  int `json:"pending_confirmations"`
}

// StateTracker manages investigation state across the pipeline.
type StateTracker struct {
	mu     sync.RWMutex
	states map[uuid.UUID]*InvestigationState
}

// NewStateTracker creates a new state tracker.
func NewStateTracker() *StateTracker {
	return &StateTracker{
		states: make(map[uuid.UUID]*InvestigationState),
	}
}

// GetOrCreate returns the investigation state, creating it if needed.
func (t *StateTracker) GetOrCreate(investigationID, projectID uuid.UUID) *InvestigationState {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[investigationID]
	if !ok {
		state = &InvestigationState{
			InvestigationID: investigationID,
			ProjectID:       projectID,
			CurrentStage:    StageCorrelation,
			StartedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
		}
		t.states[investigationID] = state
	}
	return state
}

// Update applies a function to the investigation state.
func (t *StateTracker) Update(investigationID uuid.UUID, fn func(*InvestigationState)) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[investigationID]
	if !ok {
		return fmt.Errorf("investigation %s not found", investigationID)
	}

	fn(state)
	state.UpdatedAt = time.Now().UTC()
	return nil
}

// Get returns the current state of an investigation.
func (t *StateTracker) Get(investigationID uuid.UUID) (*InvestigationState, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	state, ok := t.states[investigationID]
	return state, ok
}

// All returns all tracked investigation states.
func (t *StateTracker) All() []*InvestigationState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]*InvestigationState, 0, len(t.states))
	for _, state := range t.states {
		out = append(out, state)
	}
	return out
}
