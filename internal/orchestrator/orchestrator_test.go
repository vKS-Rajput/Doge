package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

func newTestBus() *bus.Bus {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	b := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	b.Start()
	return b
}

func newTestOrchestrator(b *bus.Bus) *Orchestrator {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(b, logger)
}

// --- Pipeline Trigger Tests ---

func TestObservationTriggersCorrelation(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageCorrelation, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	// Publish observation.
	projectID := uuid.New()
	b.Publish(context.Background(), events.ObservationCreated{
		BaseEvent:     events.NewBaseEvent(),
		ObservationID: uuid.New(),
		Type:          "subdomain",
		ProjectID:     projectID,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("observation should trigger correlation stage")
	}
	mu.Unlock()
}

func TestBatchObservationTriggersCorrelation(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageCorrelation, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.ObservationBatch{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: uuid.New(),
		Count:     5,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("batch observation should trigger correlation stage")
	}
	mu.Unlock()
}

func TestCorrelationTriggersSurface(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageSurface, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.CorrelationDiscovered{
		BaseEvent:     events.NewBaseEvent(),
		CorrelationID: uuid.New(),
		Confidence:    0.85,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("correlation should trigger surface stage")
	}
	mu.Unlock()
}

func TestSurfaceTriggersNovelty(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageNovelty, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.SurfaceUpdated{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: uuid.New(),
		PathCount: 12,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("surface update should trigger novelty stage")
	}
	mu.Unlock()
}

func TestNoveltyTriggersOpportunity(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageOpportunity, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.NoveltyDetected{
		BaseEvent:    events.NewBaseEvent(),
		ProjectID:    uuid.New(),
		NoveltyScore: 0.9,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("novelty should trigger opportunity stage")
	}
	mu.Unlock()
}

func TestOpportunityTriggersReasoning(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageReasoning, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.OpportunityCreated{
		BaseEvent:     events.NewBaseEvent(),
		OpportunityID: uuid.New(),
		ProjectID:     uuid.New(),
		Title:         "Test opportunity",
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("opportunity should trigger reasoning stage")
	}
	mu.Unlock()
}

func TestValidationTriggersReeval(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var triggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageReeval, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		triggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.ValidationCompleted{
		BaseEvent:    events.NewBaseEvent(),
		PlanID:       uuid.New(),
		HypothesisID: uuid.New(),
		ProjectID:    uuid.New(),
		ResultCount:  3,
		Completed:    true,
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !triggered {
		t.Error("validation should trigger re-evaluation stage")
	}
	mu.Unlock()
}

// --- Human Gate Tests ---

func TestHypothesisApprovalIsNotAutomatic(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var validationTriggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageValidation, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		validationTriggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	// Reasoning completes → hypotheses created.
	b.Publish(context.Background(), events.ReasoningCompleted{
		BaseEvent:     events.NewBaseEvent(),
		ProjectID:     uuid.New(),
		HypothesisIDs: []uuid.UUID{uuid.New()},
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if validationTriggered {
		t.Error("validation should NOT be automatically triggered by reasoning — requires human approval")
	}
	mu.Unlock()
}

func TestCandidateConfirmationIsNotAutomatic(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	var findingTriggered bool
	var mu sync.Mutex
	o.RegisterHandler(StageFinding, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		findingTriggered = true
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	// Candidate created.
	b.Publish(context.Background(), events.CandidateCreated{
		BaseEvent:    events.NewBaseEvent(),
		CandidateID:  uuid.New(),
		HypothesisID: uuid.New(),
		ProjectID:    uuid.New(),
	})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if findingTriggered {
		t.Error("finding should NOT be automatically triggered by candidate — requires human confirmation")
	}
	mu.Unlock()
}

// --- Error Handling ---

func TestStageErrorIsRecorded(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	o.RegisterHandler(StageCorrelation, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		return fmt.Errorf("correlation engine unavailable")
	})
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.ObservationCreated{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: uuid.New(),
	})

	time.Sleep(100 * time.Millisecond)

	results := o.Results()
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Success {
		t.Error("failed stage should be recorded as not successful")
	}
	if results[0].Error == "" {
		t.Error("failed stage should have error message")
	}
}

func TestMissingHandlerIsSkipped(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)
	// Don't register any handlers.
	o.Start()
	defer o.Stop()

	b.Publish(context.Background(), events.ObservationCreated{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: uuid.New(),
	})

	time.Sleep(100 * time.Millisecond)

	results := o.Results()
	if len(results) != 0 {
		t.Error("missing handler should be silently skipped, not recorded")
	}
}

// --- Stats ---

func TestStatsAccumulate(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)

	callCount := 0
	var mu sync.Mutex
	o.RegisterHandler(StageCorrelation, func(ctx context.Context, projectID uuid.UUID, triggerID uuid.UUID) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		return nil
	})
	o.Start()
	defer o.Stop()

	for i := 0; i < 3; i++ {
		b.Publish(context.Background(), events.ObservationCreated{
			BaseEvent: events.NewBaseEvent(),
			ProjectID: uuid.New(),
		})
	}

	time.Sleep(200 * time.Millisecond)

	stats := o.Stats()
	if stats.TotalRuns != 3 {
		t.Errorf("expected 3 total runs, got %d", stats.TotalRuns)
	}
	if stats.StageCounts[StageCorrelation] != 3 {
		t.Errorf("expected 3 correlation runs, got %d", stats.StageCounts[StageCorrelation])
	}
}

// --- State Tracker ---

func TestStateTrackerGetOrCreate(t *testing.T) {
	tracker := NewStateTracker()
	invID := uuid.New()
	projID := uuid.New()

	state := tracker.GetOrCreate(invID, projID)
	if state.InvestigationID != invID {
		t.Error("state should have the correct investigation ID")
	}
	if state.ProjectID != projID {
		t.Error("state should have the correct project ID")
	}

	// Second call returns same state.
	state2 := tracker.GetOrCreate(invID, projID)
	if state != state2 {
		t.Error("GetOrCreate should return the same state for the same ID")
	}
}

func TestStateTrackerUpdate(t *testing.T) {
	tracker := NewStateTracker()
	invID := uuid.New()
	tracker.GetOrCreate(invID, uuid.New())

	err := tracker.Update(invID, func(s *InvestigationState) {
		s.ObservationsProcessed = 42
		s.CurrentStage = StageNovelty
	})
	if err != nil {
		t.Fatalf("update should succeed: %v", err)
	}

	state, ok := tracker.Get(invID)
	if !ok {
		t.Fatal("state should exist")
	}
	if state.ObservationsProcessed != 42 {
		t.Errorf("expected 42 observations, got %d", state.ObservationsProcessed)
	}
	if state.CurrentStage != StageNovelty {
		t.Errorf("expected stage novelty, got %s", state.CurrentStage)
	}
}

func TestStateTrackerUpdateNotFound(t *testing.T) {
	tracker := NewStateTracker()
	err := tracker.Update(uuid.New(), func(s *InvestigationState) {})
	if err == nil {
		t.Error("updating non-existent investigation should fail")
	}
}

func TestStateTrackerAll(t *testing.T) {
	tracker := NewStateTracker()
	tracker.GetOrCreate(uuid.New(), uuid.New())
	tracker.GetOrCreate(uuid.New(), uuid.New())
	tracker.GetOrCreate(uuid.New(), uuid.New())

	all := tracker.All()
	if len(all) != 3 {
		t.Errorf("expected 3 states, got %d", len(all))
	}
}

// --- Full Pipeline Chain Test ---

func TestFullAutomaticPipelineChain(t *testing.T) {
	b := newTestBus()
	defer b.Drain()

	o := newTestOrchestrator(b)
	projectID := uuid.New()

	// Track which stages were triggered and in what order.
	var stages []PipelineStage
	var mu sync.Mutex

	makeHandler := func(stage PipelineStage, emitNext func()) StageHandler {
		return func(ctx context.Context, pid uuid.UUID, triggerID uuid.UUID) error {
			mu.Lock()
			stages = append(stages, stage)
			mu.Unlock()
			if emitNext != nil {
				emitNext()
			}
			return nil
		}
	}

	// Wire up the full chain. Each stage emits the event that triggers the next.
	o.RegisterHandler(StageCorrelation, makeHandler(StageCorrelation, func() {
		b.Publish(context.Background(), events.CorrelationDiscovered{
			BaseEvent: events.NewBaseEvent(),
		})
	}))
	o.RegisterHandler(StageSurface, makeHandler(StageSurface, func() {
		b.Publish(context.Background(), events.SurfaceUpdated{
			BaseEvent: events.NewBaseEvent(),
			ProjectID: projectID,
		})
	}))
	o.RegisterHandler(StageNovelty, makeHandler(StageNovelty, func() {
		b.Publish(context.Background(), events.NoveltyDetected{
			BaseEvent: events.NewBaseEvent(),
			ProjectID: projectID,
		})
	}))
	o.RegisterHandler(StageOpportunity, makeHandler(StageOpportunity, func() {
		b.Publish(context.Background(), events.OpportunityCreated{
			BaseEvent:     events.NewBaseEvent(),
			OpportunityID: uuid.New(),
			ProjectID:     projectID,
		})
	}))
	o.RegisterHandler(StageReasoning, makeHandler(StageReasoning, nil))
	// Reasoning does NOT emit validation. That requires human approval.

	o.Start()
	defer o.Stop()

	// Trigger the chain.
	b.Publish(context.Background(), events.ObservationCreated{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: projectID,
	})

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	expected := []PipelineStage{
		StageCorrelation,
		StageSurface,
		StageNovelty,
		StageOpportunity,
		StageReasoning,
	}

	if len(stages) != len(expected) {
		t.Fatalf("expected %d stages, got %d: %v", len(expected), len(stages), stages)
	}

	for i, stage := range expected {
		if stages[i] != stage {
			t.Errorf("stage %d: expected %s, got %s", i, stage, stages[i])
		}
	}
}
