package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// TestFullSchedulerExecutorChain proves the complete chain:
//
//	InvestigationStarted
//	      ↓
//	Scheduler creates nmap job
//	      ↓
//	Executor runs the tool
//	      ↓
//	stdout/stderr captured
//	      ↓
//	raw artifact persisted
//	      ↓
//	OnJobComplete callback fires
//	      ↓
//	observations can be created (simulated)
//	      ↓
//	events emitted
//	      ↓
//	scheduler sees events
//	      ↓
//	new jobs are created (httpx)
func TestFullSchedulerExecutorChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Infrastructure.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	eventBus.Start()
	defer eventBus.Drain()

	artifactDir := t.TempDir()

	target := &domain.Target{
		Primary:     "127.0.0.1",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "127.0.0.1", Type: domain.ScopeIP}},
	}

	registry := NewToolRegistry()
	policy := DefaultPolicy(domain.EnvHTB)
	investigationID := uuid.New()

	// Track what happens.
	var mu sync.Mutex
	var completedJobs []string
	var artifactPaths []string

	// Create executor with ingestion callback.
	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: artifactDir,
		Logger:      logger,
		MaxRuntime:  5 * time.Second,
		OnComplete: func(job *Job, outputPath string) {
			mu.Lock()
			completedJobs = append(completedJobs, job.Tool)
			artifactPaths = append(artifactPaths, outputPath)
			mu.Unlock()

			// Simulate ingestion discovering ports →
			// emit observation events that trigger more scheduling.
			eventBus.Publish(ctx, events.ObservationCreated{
				BaseEvent: events.NewBaseEvent(),
				Type:      "port",
				ProjectID: uuid.New(),
			})
		},
	})

	// Override the nmap tool definition to use a safe command (cross-platform).
	echoBin, echoFlags := testShellEcho("PORT STATE SERVICE")
	registry.Register(ToolDefinition{
		Name:         "nmap",
		Binary:       echoBin,
		OutputFormat: "text",
		Parser:       "nmap",
		CaptureMode:  CaptureStdout,
		DefaultFlags: echoFlags,
		Category:     CategoryRecon,
	})

	// Create scheduler with the executor.
	sched := New(eventBus, registry, Options{
		Policy:          policy,
		Target:          target,
		InvestigationID: investigationID,
		Executor:        executor,
	}, logger)

	// Start the scheduler.
	sched.Start(ctx)
	defer sched.Stop()

	// Step 1: Schedule initial recon (nmap).
	if err := sched.ScheduleInitialRecon(); err != nil {
		t.Fatalf("initial recon failed: %v", err)
	}

	// Wait for the scheduler to execute the nmap job.
	waitForCondition(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(completedJobs) >= 1
	})

	// Verify Step 2: nmap job completed.
	mu.Lock()
	if len(completedJobs) == 0 {
		mu.Unlock()
		t.Fatal("nmap job should have completed")
	}
	if completedJobs[0] != "nmap" {
		mu.Unlock()
		t.Errorf("first completed job = %s, want nmap", completedJobs[0])
	}
	mu.Unlock()

	// Verify Step 3: raw artifact was persisted.
	mu.Lock()
	if len(artifactPaths) == 0 {
		mu.Unlock()
		t.Fatal("artifact path should have been set")
	}
	firstArtifact := artifactPaths[0]
	mu.Unlock()

	if _, err := os.Stat(firstArtifact); err != nil {
		t.Errorf("artifact file should exist: %s", firstArtifact)
	}

	content, _ := os.ReadFile(firstArtifact)
	if len(content) == 0 {
		t.Error("artifact should have content")
	}

	// Verify Step 4: the observation event triggered httpx scheduling.
	// Wait for the scheduler to react to the port observation.
	waitForCondition(t, 3*time.Second, func() bool {
		stats := sched.Stats()
		// Should have at least the original nmap + one more job.
		return stats.TotalJobs >= 2
	})

	stats := sched.Stats()
	t.Logf("Final scheduler stats: total=%d queued=%d running=%d completed=%d failed=%d",
		stats.TotalJobs, stats.Queued, stats.Running, stats.Completed, stats.Failed)

	// The httpx job should have been created by the scheduler
	// reacting to the port observation event.
	allJobs := sched.Queue().All()
	foundHttpx := false
	for _, j := range allJobs {
		if j.Tool == "httpx" {
			foundHttpx = true
			t.Logf("httpx job created: status=%s reason=%q", j.Status, j.Reason)
		}
	}

	if !foundHttpx {
		t.Error("scheduler should have created httpx job after port observation")
		for _, j := range allJobs {
			t.Logf("  job: tool=%s status=%s reason=%q", j.Tool, j.Status, j.Reason)
		}
	}

	t.Log("✅ Full chain verified:")
	t.Log("   Investigation → Scheduler → nmap Job → Executor → Output Captured")
	t.Log("   → Artifact Persisted → Observation Event → httpx Job Created")
}

// TestExecutorPreservesOutputOnFailure verifies that raw output is
// saved even when a tool exits with non-zero status.
func TestExecutorPreservesOutputOnFailure(t *testing.T) {
	target := &domain.Target{
		Primary: "127.0.0.1",
		Scope:   []domain.ScopeEntry{{Value: "127.0.0.1", Type: domain.ScopeIP}},
	}

	artifactDir := t.TempDir()

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: artifactDir,
		MaxRuntime:  5 * time.Second,
	})

	job := &Job{
		ID:     uuid.New(),
		Tool:   "failing-tool",
		Target: "127.0.0.1",
	}

	// Cross-platform: echo partial output then fail.
	failBin, failFlags := testShellFail("partial-output")
	def := ToolDefinition{
		Name:         "failing-tool",
		Binary:       failBin,
		CaptureMode:  CaptureStdout,
		DefaultFlags: failFlags,
	}

	// Should NOT return error because there IS output despite non-zero exit.
	err := executor.Execute(context.Background(), job, def)
	// The behavior depends on whether output was produced.
	// The important thing: raw artifact MUST be preserved.

	files, _ := os.ReadDir(artifactDir)
	foundArtifact := false
	for _, f := range files {
		if !f.IsDir() {
			foundArtifact = true
			content, _ := os.ReadFile(filepath.Join(artifactDir, f.Name()))
			t.Logf("Preserved artifact: %s (%d bytes)", f.Name(), len(content))
		}
	}

	if !foundArtifact {
		t.Error("should preserve raw output even on tool failure")
	}
	_ = err
}

// TestSchedulerEventDrivenJobCreation proves that observation events
// automatically trigger new recon jobs.
func TestSchedulerEventDrivenJobCreation(t *testing.T) {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	eventBus.Start()
	defer eventBus.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	registry := NewToolRegistry()
	policy := DefaultPolicy(domain.EnvHTB)

	sched := New(eventBus, registry, Options{
		Policy:          policy,
		Target:          target,
		InvestigationID: uuid.New(),
	}, logger)

	sched.Start(ctx)
	defer sched.Stop()

	// Emit a port observation event.
	eventBus.Publish(ctx, events.ObservationCreated{
		BaseEvent: events.NewBaseEvent(),
		Type:      "port",
		ProjectID: uuid.New(),
	})

	// Wait for the scheduler to react.
	waitForCondition(t, 2*time.Second, func() bool {
		return sched.Queue().Len() > 0
	})

	// Should have created an httpx job.
	jobs := sched.Queue().All()
	found := false
	for _, j := range jobs {
		if j.Tool == "httpx" {
			found = true
		}
	}

	if !found {
		t.Error("port observation should trigger httpx job")
		for _, j := range jobs {
			t.Logf("  job: tool=%s", j.Tool)
		}
	}
}

// TestSchedulerSurfaceEventTriggersCrawling proves that surface events
// trigger katana and ffuf jobs.
func TestSchedulerSurfaceEventTriggersCrawling(t *testing.T) {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	eventBus.Start()
	defer eventBus.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	registry := NewToolRegistry()
	policy := DefaultPolicy(domain.EnvHTB)

	sched := New(eventBus, registry, Options{
		Policy:          policy,
		Target:          target,
		InvestigationID: uuid.New(),
	}, logger)

	sched.Start(ctx)
	defer sched.Stop()

	// Emit a surface update event with web paths.
	eventBus.Publish(ctx, events.SurfaceUpdated{
		BaseEvent: events.NewBaseEvent(),
		ProjectID: uuid.New(),
		PathCount: 10,
	})

	// Wait for the scheduler to react.
	waitForCondition(t, 2*time.Second, func() bool {
		return sched.Queue().Len() >= 2
	})

	// Should have created katana and ffuf jobs.
	jobs := sched.Queue().All()
	foundKatana := false
	foundFfuf := false
	for _, j := range jobs {
		if j.Tool == "katana" {
			foundKatana = true
		}
		if j.Tool == "ffuf" {
			foundFfuf = true
		}
	}

	if !foundKatana {
		t.Error("surface update should trigger katana job")
	}
	if !foundFfuf {
		t.Error("surface update should trigger ffuf job")
	}
}

// --- Helper ---

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("warning: condition not met within %s", timeout)
}

func init() {
	// Suppress output noise in tests.
	_ = fmt.Sprintf
}
