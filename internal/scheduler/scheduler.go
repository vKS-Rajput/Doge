package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Scheduler is the event-driven reconnaissance scheduler.
//
// It subscribes to investigation events and creates tool jobs
// according to the research policy and recon rules.
//
// The scheduler is DETERMINISTIC MACHINERY:
//   - It reacts to events with typed rules
//   - It enforces scope, policy, and concurrency limits
//   - It does NOT accept commands from the AI reasoning engine
//   - It does NOT execute exploitation tools
//
// The scheduler's authority is separate from the AI's authority.
type Scheduler struct {
	eventBus *bus.Bus
	registry *ToolRegistry
	queue    *JobQueue
	policy   ResearchPolicy
	target   *domain.Target
	logger   *slog.Logger

	// Executor runs jobs. Injected for testability.
	executor Executor

	// Investigation context.
	investigationID uuid.UUID

	// Concurrency control.
	running sync.WaitGroup
	cancel  context.CancelFunc
	mu      sync.Mutex
	stopped bool

	// Subscription IDs for cleanup.
	subscriptions []bus.SubscriptionID

	// Cooldowns prevent re-running the same tool too quickly.
	cooldowns map[string]time.Time
}

// Executor is the interface for running tool jobs.
// This is separated for testability.
type Executor interface {
	Execute(ctx context.Context, job *Job, def ToolDefinition) error
}

// Options configures the scheduler.
type Options struct {
	Policy          ResearchPolicy
	Target          *domain.Target
	InvestigationID uuid.UUID
	Executor        Executor
}

// New creates a new scheduler.
func New(eventBus *bus.Bus, registry *ToolRegistry, opts Options, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		eventBus:        eventBus,
		registry:        registry,
		queue:           NewJobQueue(opts.Policy.MaxQueueSize),
		policy:          opts.Policy,
		target:          opts.Target,
		investigationID: opts.InvestigationID,
		executor:        opts.Executor,
		logger:          logger,
		cooldowns:       make(map[string]time.Time),
	}
}

// Start begins the scheduler. It subscribes to events and
// starts the job processing loop.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, s.cancel = context.WithCancel(ctx)

	// Subscribe to pipeline events that trigger recon.
	s.subscribeToEvents()

	// Start the job processing loop.
	s.running.Add(1)
	go s.processLoop(ctx)

	s.logger.Info("scheduler started",
		"target", s.target.Primary,
		"environment", s.target.Environment,
		"auto_recon", s.policy.AutoRecon)
}

// Stop gracefully stops the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	s.running.Wait()

	// Unsubscribe from events.
	for _, id := range s.subscriptions {
		s.eventBus.Unsubscribe(id)
	}

	s.logger.Info("scheduler stopped")
}

// ScheduleInitialRecon creates the initial reconnaissance job
// based on the target and policy.
func (s *Scheduler) ScheduleInitialRecon() error {
	if !s.policy.AutoRecon {
		s.logger.Info("auto-recon disabled by policy, waiting for approval")
		return nil
	}

	// Create initial nmap job.
	job := NewJob(
		s.investigationID,
		"nmap",
		s.target.Primary,
		"Initial port discovery",
		JobPriorityHigh,
	)

	if err := s.queue.Enqueue(job); err != nil {
		return fmt.Errorf("scheduling initial recon: %w", err)
	}

	s.logger.Info("initial recon scheduled",
		"tool", "nmap",
		"target", s.target.Primary)

	return nil
}

// Queue returns the job queue for external inspection.
func (s *Scheduler) Queue() *JobQueue {
	return s.queue
}

// Stats returns scheduler statistics.
func (s *Scheduler) Stats() SchedulerStats {
	return SchedulerStats{
		TotalJobs: s.queue.Len(),
		Queued:    s.queue.Queued(),
		Running:   s.queue.Running(),
		Completed: len(s.queue.ByStatus(JobCompleted)),
		Failed:    len(s.queue.ByStatus(JobFailed)),
	}
}

// SchedulerStats holds scheduler statistics.
type SchedulerStats struct {
	TotalJobs int `json:"total_jobs"`
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// --- Event subscriptions ---

func (s *Scheduler) subscribeToEvents() {
	// Port/service discovered → HTTP probing.
	s.subscribe(events.TopicObservationCreated, func(_ context.Context, e events.Event) error {
		obs, ok := e.(events.ObservationCreated)
		if !ok {
			return nil
		}
		s.handleObservation(obs)
		return nil
	})

	// Surface update → crawling/fuzzing.
	s.subscribe(events.TopicSurfaceUpdated, func(_ context.Context, e events.Event) error {
		s.handleSurfaceUpdate(e)
		return nil
	})
}

func (s *Scheduler) subscribe(topic events.Topic, handler bus.Handler) {
	id := s.eventBus.Subscribe(topic, handler)
	s.subscriptions = append(s.subscriptions, id)
}

// --- Event handlers ---

func (s *Scheduler) handleObservation(obs events.ObservationCreated) {
	// Port observation → HTTP probe.
	if obs.Type == "port" || obs.Type == "service" {
		s.scheduleIfAllowed("httpx", s.target.Primary,
			"Service discovered, probing HTTP", JobPriorityNormal)
	}

	// Subdomain observation → DNS/HTTP probe.
	if obs.Type == "subdomain" || obs.Type == "domain" {
		s.scheduleIfAllowed("dnsx", s.target.Primary,
			"Domain discovered, probing DNS", JobPriorityNormal)
		s.scheduleIfAllowed("httpx", s.target.Primary,
			"Domain discovered, probing HTTP", JobPriorityNormal)
	}
}

func (s *Scheduler) handleSurfaceUpdate(e events.Event) {
	surface, ok := e.(events.SurfaceUpdated)
	if !ok {
		return
	}

	// Web surface → crawl + fuzz.
	if surface.PathCount > 0 {
		s.scheduleIfAllowed("katana", s.target.Primary,
			"Web surface discovered, crawling", JobPriorityNormal)
		s.scheduleIfAllowed("ffuf", s.target.Primary,
			"Web surface discovered, fuzzing directories", JobPriorityLow)
	}
}

// scheduleIfAllowed creates a job only if policy allows it.
func (s *Scheduler) scheduleIfAllowed(tool, target, reason string, priority JobPriority) {
	// Check policy.
	if !s.policy.CanAutoRun(tool) {
		s.logger.Debug("tool requires approval, not auto-scheduling",
			"tool", tool, "target", target)
		return
	}

	// Check scope.
	if !s.target.InScope(target) {
		s.logger.Warn("target out of scope, rejecting",
			"tool", tool, "target", target)
		return
	}

	// Check cooldown.
	cooldownKey := tool + ":" + target
	s.mu.Lock()
	if last, ok := s.cooldowns[cooldownKey]; ok {
		if time.Since(last) < 30*time.Second {
			s.mu.Unlock()
			return
		}
	}
	s.cooldowns[cooldownKey] = time.Now()
	s.mu.Unlock()

	// Check per-tool concurrency.
	if s.queue.RunningForTool(tool) >= s.policy.ToolConcurrency(tool) {
		s.logger.Debug("tool at concurrency limit",
			"tool", tool, "limit", s.policy.ToolConcurrency(tool))
		return
	}

	job := NewJob(s.investigationID, tool, target, reason, priority)
	if err := s.queue.Enqueue(job); err != nil {
		s.logger.Debug("job not queued", "tool", tool, "reason", err)
		return
	}

	s.logger.Info("job scheduled",
		"tool", tool,
		"target", target,
		"reason", reason,
		"priority", priority)
}

// --- Job processing loop ---

func (s *Scheduler) processLoop(ctx context.Context) {
	defer s.running.Done()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processNextJob(ctx)
		}
	}
}

func (s *Scheduler) processNextJob(ctx context.Context) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Check global concurrency.
	if s.queue.Running() >= s.policy.MaxConcurrentTools {
		return
	}

	job := s.queue.Dequeue()
	if job == nil {
		return
	}

	// Look up tool definition.
	def, ok := s.registry.Get(job.Tool)
	if !ok {
		s.logger.Error("unknown tool", "tool", job.Tool)
		job.Status = JobFailed
		job.Error = fmt.Sprintf("unknown tool: %s", job.Tool)
		s.queue.Update(*job)
		return
	}

	// Execute in background.
	s.running.Add(1)
	go func() {
		defer s.running.Done()

		now := time.Now()
		job.StartedAt = &now

		s.logger.Info("job started",
			"job_id", job.ID,
			"tool", job.Tool,
			"target", job.Target)

		if s.executor != nil {
			if err := s.executor.Execute(ctx, job, def); err != nil {
				job.Status = JobFailed
				job.Error = err.Error()
				s.logger.Error("job failed",
					"job_id", job.ID,
					"tool", job.Tool,
					"error", err)
			} else {
				job.Status = JobCompleted
				s.logger.Info("job completed",
					"job_id", job.ID,
					"tool", job.Tool,
					"observations", job.ObservationsCreated)
			}
		} else {
			// No executor configured (test mode).
			job.Status = JobCompleted
		}

		end := time.Now()
		job.CompletedAt = &end
		job.Duration = end.Sub(now)

		s.queue.Update(*job)
	}()
}
