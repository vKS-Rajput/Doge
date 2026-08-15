package session

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestSessionStartStop(t *testing.T) {
	ctx := context.Background()
	b := newTestBus(t)
	defer b.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	sess, err := New(Config{
		Target:   target,
		EventBus: b,
		Logger:   testLogger(),
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	if err := sess.Start(ctx); err != nil {
		t.Fatalf("start session: %v", err)
	}

	if sess.Status() != StatusActive {
		t.Errorf("session should be active, got %s", sess.Status())
	}

	if !sess.IsActive() {
		t.Error("IsActive should be true")
	}

	sess.Stop()

	if sess.Status() != StatusStopped {
		t.Errorf("session should be stopped, got %s", sess.Status())
	}
}

func TestSessionHTBAutoRecon(t *testing.T) {
	ctx := context.Background()
	b := newTestBus(t)
	defer b.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	sess, err := New(Config{
		Target:   target,
		EventBus: b,
		Logger:   testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	// HTB target should auto-schedule initial recon.
	stats := sess.Scheduler.Stats()
	if stats.Queued == 0 && stats.Running == 0 && stats.Completed == 0 {
		t.Error("HTB session should auto-schedule initial recon")
	}
}

func TestSessionAuthorizedNoAutoRecon(t *testing.T) {
	ctx := context.Background()
	b := newTestBus(t)
	defer b.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvAuthorized,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	sess, err := New(Config{
		Target:   target,
		EventBus: b,
		Logger:   testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	// Authorized target should NOT auto-schedule recon.
	stats := sess.Scheduler.Stats()
	if stats.TotalJobs != 0 {
		t.Errorf("authorized session should NOT auto-schedule, got %d jobs", stats.TotalJobs)
	}
}

func TestSessionSnapshot(t *testing.T) {
	ctx := context.Background()
	b := newTestBus(t)
	defer b.Drain()

	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	sess, err := New(Config{
		Target:   target,
		EventBus: b,
		Logger:   testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	snap := sess.Snapshot()

	if snap.Target != "10.10.11.123" {
		t.Errorf("snapshot target = %s, want 10.10.11.123", snap.Target)
	}
	if snap.Environment != domain.EnvHTB {
		t.Errorf("snapshot env = %s, want htb", snap.Environment)
	}
	if snap.Status != StatusActive {
		t.Errorf("snapshot status = %s, want active", snap.Status)
	}
	if snap.StartedAt.IsZero() {
		t.Error("snapshot started_at should not be zero")
	}
}

func TestSessionInvalidTarget(t *testing.T) {
	b := newTestBus(t)
	defer b.Drain()

	target := &domain.Target{
		Primary: "", // invalid
	}

	_, err := New(Config{
		Target:   target,
		EventBus: b,
		Logger:   testLogger(),
	})
	if err == nil {
		t.Error("should reject invalid target")
	}
}

func TestControllerPhaseTransitions(t *testing.T) {
	ctrl := NewController([16]byte{})

	if ctrl.Phase != PhaseInitializing {
		t.Error("should start in initializing")
	}

	// Simulate port discovery completing.
	ctrl.PortDiscoveryDone = true
	ctrl.UpdatePhase()
	if ctrl.Phase != PhaseEnumerating {
		t.Errorf("after port discovery should be enumerating, got %s", ctrl.Phase)
	}

	// Simulate HTTP and DNS done.
	ctrl.HTTPDiscoveryDone = true
	ctrl.DNSDiscoveryDone = true
	ctrl.UpdatePhase()
	if ctrl.Phase != PhaseAnalyzing {
		t.Errorf("after enum should be analyzing, got %s", ctrl.Phase)
	}

	// Simulate correlation and novelty done.
	ctrl.CorrelationCompleted = true
	ctrl.NoveltyAnalyzed = true
	ctrl.Opportunities = 3
	ctrl.UpdatePhase()
	if ctrl.Phase != PhaseInvestigating {
		t.Errorf("with opportunities should be investigating, got %s", ctrl.Phase)
	}

	// Simulate pending approval.
	ctrl.Hypotheses = 1
	ctrl.PendingApproval = 1
	ctrl.UpdatePhase()
	if ctrl.Phase != PhaseValidating {
		t.Errorf("with pending approval should be validating, got %s", ctrl.Phase)
	}

	if !ctrl.NeedsHuman() {
		t.Error("should need human with pending approval")
	}
}

func TestControllerSummary(t *testing.T) {
	ctrl := NewController([16]byte{})

	tests := []struct {
		phase    InvestigationPhase
		expected string
	}{
		{PhaseInitializing, "Initializing investigation..."},
		{PhaseDiscovering, "Discovering target services..."},
		{PhaseEnumerating, "Enumerating discovered services..."},
		{PhaseAnalyzing, "Analyzing correlations and novelty..."},
		{PhaseIdle, "Investigation idle — all jobs complete."},
	}

	for _, tt := range tests {
		ctrl.Phase = tt.phase
		if ctrl.Summary() != tt.expected {
			t.Errorf("Summary for %s = %q, want %q", tt.phase, ctrl.Summary(), tt.expected)
		}
	}
}

// --- Test Helpers ---

func newTestBus(t *testing.T) *bus.Bus {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	b := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	b.Start()
	return b
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// waitFor waits for a condition to become true within a timeout.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
