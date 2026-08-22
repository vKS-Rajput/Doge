package session

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/orchestrator"
	"github.com/vKS-Rajput/doge/internal/scheduler"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// SessionStatus tracks the runtime lifecycle.
type SessionStatus string

const (
	StatusStarting SessionStatus = "starting"
	StatusActive   SessionStatus = "active"
	StatusStopping SessionStatus = "stopping"
	StatusStopped  SessionStatus = "stopped"
)

// Session is the persistent DOGE runtime. It owns every subsystem
// and keeps the investigation alive independently of any UI.
//
// The TUI, console, logs, and approvals are ATTACHABLE WINDOWS
// into the session — not the session itself.
//
// Lifecycle:
//
//	New() → Start(ctx) → [running] → Stop()
//	Open() → Resume(ctx) → [running] → Stop()
type Session struct {
	// Target and investigation.
	Target          *domain.Target
	InvestigationID uuid.UUID

	// Infrastructure.
	EventBus     *bus.Bus
	Orchestrator *orchestrator.Orchestrator
	Tracker      *orchestrator.StateTracker
	Scheduler    *scheduler.Scheduler
	Controller   *InvestigationController

	// Config.
	Policy scheduler.ResearchPolicy
	Logger *slog.Logger

	// Runtime.
	status SessionStatus
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// Config holds session creation parameters.
type Config struct {
	Target        *domain.Target
	EventBus      *bus.Bus
	Logger        *slog.Logger
	Executor      scheduler.Executor // nil for test mode
	WorkspacePath string             // for authorization file I/O
}

// New creates a new session for a target.
func New(cfg Config) (*Session, error) {
	if err := domain.ValidateTarget(*cfg.Target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	investigationID := uuid.New()
	policy := scheduler.DefaultPolicy(cfg.Target.Environment)

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	registry := scheduler.NewToolRegistry()
	tracker := orchestrator.NewStateTracker()
	controller := NewController(investigationID)

	orch := orchestrator.New(cfg.EventBus, logger)

	sched := scheduler.New(cfg.EventBus, registry, scheduler.Options{
		Policy:          policy,
		Target:          cfg.Target,
		InvestigationID: investigationID,
		Executor:        cfg.Executor,
		WorkspacePath:   cfg.WorkspacePath,
	}, logger)

	return &Session{
		Target:          cfg.Target,
		InvestigationID: investigationID,
		EventBus:        cfg.EventBus,
		Orchestrator:    orch,
		Tracker:         tracker,
		Scheduler:       sched,
		Controller:      controller,
		Policy:          policy,
		Logger:          logger,
		status:          StatusStarting,
	}, nil
}

// Start begins the session. All subsystems start in order.
func (s *Session) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, s.cancel = context.WithCancel(ctx)

	s.Logger.Info("starting DOGE session",
		"target", s.Target.Primary,
		"environment", s.Target.Environment,
		"investigation_id", s.InvestigationID)

	// 1. Event bus (already started by caller or config).
	s.Logger.Info("event bus ready")

	// 2. Register pipeline handlers with orchestrator.
	s.registerPipelineHandlers()
	s.Orchestrator.Start()
	s.Logger.Info("orchestrator started")

	// 3. Subscribe to events for controller updates.
	s.subscribeControllerEvents()

	// 4. Start scheduler.
	s.Scheduler.Start(ctx)
	s.Logger.Info("scheduler started")

	// 5. Schedule initial reconnaissance.
	if err := s.Scheduler.ScheduleInitialRecon(); err != nil {
		s.Logger.Warn("initial recon scheduling failed", "error", err)
		// Non-fatal: the session can still operate.
	}

	s.status = StatusActive
	s.Controller.Phase = PhaseDiscovering

	s.Logger.Info("DOGE session active",
		"target", s.Target.Primary,
		"phase", s.Controller.Phase,
		"auto_recon", s.Policy.AutoRecon)

	return nil
}

// Stop gracefully shuts down all subsystems in reverse order.
func (s *Session) Stop() {
	s.mu.Lock()
	s.status = StatusStopping
	s.mu.Unlock()

	s.Logger.Info("stopping DOGE session")

	// Stop in reverse order.
	s.Scheduler.Stop()
	s.Orchestrator.Stop()

	if s.cancel != nil {
		s.cancel()
	}

	s.mu.Lock()
	s.status = StatusStopped
	s.mu.Unlock()

	s.Logger.Info("DOGE session stopped",
		"observations", s.Controller.Observations,
		"findings", s.Controller.Findings,
		"jobs_completed", s.Controller.JobsCompleted)
}

// Status returns the current session status.
func (s *Session) Status() SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// IsActive returns true if the session is running.
func (s *Session) IsActive() bool {
	return s.Status() == StatusActive
}

// Snapshot returns the current state for UI rendering.
func (s *Session) Snapshot() SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := s.Scheduler.Stats()

	return SessionSnapshot{
		Target:          s.Target.Primary,
		Environment:     s.Target.Environment,
		Phase:           s.Controller.Phase,
		PhaseSummary:    s.Controller.Summary(),
		Status:          s.status,
		Observations:    s.Controller.Observations,
		Entities:        s.Controller.Entities,
		Correlations:    s.Controller.Correlations,
		NoveltySignals:  s.Controller.NoveltySignals,
		Opportunities:   s.Controller.Opportunities,
		Hypotheses:      s.Controller.Hypotheses,
		PendingApproval: s.Controller.PendingApproval,
		Validations:     s.Controller.Validations,
		Candidates:      s.Controller.Candidates,
		PendingConfirm:  s.Controller.PendingConfirm,
		Findings:        s.Controller.Findings,
		JobsQueued:      stats.Queued,
		JobsRunning:     stats.Running,
		JobsCompleted:   stats.Completed,
		JobsFailed:      stats.Failed,
		StartedAt:       s.Controller.StartedAt,
		NeedsHuman:      s.Controller.NeedsHuman(),
	}
}

// SessionSnapshot is a point-in-time view of the session for UI.
type SessionSnapshot struct {
	Target          string                   `json:"target"`
	Environment     domain.TargetEnvironment `json:"environment"`
	Phase           InvestigationPhase       `json:"phase"`
	PhaseSummary    string                   `json:"phase_summary"`
	Status          SessionStatus            `json:"status"`

	Observations    int `json:"observations"`
	Entities        int `json:"entities"`
	Correlations    int `json:"correlations"`
	NoveltySignals  int `json:"novelty_signals"`
	Opportunities   int `json:"opportunities"`
	Hypotheses      int `json:"hypotheses"`
	PendingApproval int `json:"pending_approval"`
	Validations     int `json:"validations"`
	Candidates      int `json:"candidates"`
	PendingConfirm  int `json:"pending_confirm"`
	Findings        int `json:"findings"`
	JobsQueued      int `json:"jobs_queued"`
	JobsRunning     int `json:"jobs_running"`
	JobsCompleted   int `json:"jobs_completed"`
	JobsFailed      int `json:"jobs_failed"`

	StartedAt  time.Time `json:"started_at"`
	NeedsHuman bool      `json:"needs_human"`
}

// --- Pipeline handler registration ---

func (s *Session) registerPipelineHandlers() {
	// Observation → correlation.
	s.Orchestrator.RegisterHandler(orchestrator.StageCorrelation,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.Observations++
			s.Controller.UpdatePhase()
			return nil
		})

	// Correlation → surface.
	s.Orchestrator.RegisterHandler(orchestrator.StageSurface,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.Correlations++
			s.Controller.CorrelationCompleted = true
			s.Controller.UpdatePhase()
			return nil
		})

	// Surface → novelty.
	s.Orchestrator.RegisterHandler(orchestrator.StageNovelty,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.UpdatePhase()
			return nil
		})

	// Novelty → opportunity.
	s.Orchestrator.RegisterHandler(orchestrator.StageOpportunity,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.NoveltySignals++
			s.Controller.NoveltyAnalyzed = true
			s.Controller.UpdatePhase()
			return nil
		})

	// Opportunity → reasoning.
	s.Orchestrator.RegisterHandler(orchestrator.StageReasoning,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.Opportunities++
			s.Controller.UpdatePhase()
			return nil
		})

	// Validation → re-evaluation.
	s.Orchestrator.RegisterHandler(orchestrator.StageReeval,
		func(ctx context.Context, pid uuid.UUID, tid uuid.UUID) error {
			s.Controller.Validations++
			s.Controller.UpdatePhase()
			return nil
		})
}

// --- Controller event subscriptions ---

func (s *Session) subscribeControllerEvents() {
	// Track pipeline events for phase updates.
	s.EventBus.Subscribe(events.TopicObservationCreated, func(_ context.Context, _ events.Event) error {
		s.Controller.Observations++
		s.Controller.UpdatePhase()
		return nil
	})

	s.EventBus.Subscribe(events.TopicReasoningCompleted, func(_ context.Context, _ events.Event) error {
		s.Controller.Hypotheses++
		s.Controller.PendingApproval++
		s.Controller.UpdatePhase()
		return nil
	})

	s.EventBus.Subscribe(events.TopicCandidateCreated, func(_ context.Context, _ events.Event) error {
		s.Controller.Candidates++
		s.Controller.PendingConfirm++
		s.Controller.UpdatePhase()
		return nil
	})

	s.EventBus.Subscribe(events.TopicFindingConfirmed, func(_ context.Context, _ events.Event) error {
		s.Controller.Findings++
		s.Controller.UpdatePhase()
		return nil
	})
}
