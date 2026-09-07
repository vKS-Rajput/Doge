package research

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/scope"
)

func TestLoopEngine_GatedExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-research-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	scopeEngine, err := scope.NewEngine(scope.Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope:     []string{"*.example.com", "example.com"},
	})
	if err != nil {
		t.Fatalf("failed to init scope: %v", err)
	}

	gateMgr := gates.NewManager(tempDir)
	parserReg := parser.NewRegistry(slog.Default())
	mem := learning.NewMemory(nil)
	learner := learning.NewLearner(mem)

	cfg := Config{
		Target:          "example.com",
		Environment:     "authorized",
		WorkspacePath:   tempDir,
		MaxIterations:   10,
		RateLimitPerSec: 5,
		AllowAutoRecon:  false, // Requires approval gate
	}

	engine := NewLoopEngine(cfg, scopeEngine, gateMgr, parserReg, learner, mem)

	// Set mock runner for fast unit testing
	engine.SetRunner(func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult {
		return &runner.RunResult{
			Command:    cmd,
			WorkingDir: workDir,
			Stdout:     "api.example.com\nadmin.example.com\n",
			ExitCode:   0,
			Duration:   10 * time.Millisecond,
		}
	})

	// Step 1: In authorized mode without auto-recon, passive action runs or approval gate created
	res, err := engine.Step(context.Background())
	if err != nil {
		t.Fatalf("step error: %v", err)
	}

	snap := engine.GetSnapshot()
	if snap.Iteration != 1 {
		t.Errorf("expected iteration 1, got %d", snap.Iteration)
	}

	// Pause / Resume test
	engine.Pause()
	snap = engine.GetSnapshot()
	if snap.CurrentState != StatePaused {
		t.Errorf("expected state PAUSED, got %s", snap.CurrentState)
	}

	engine.Resume()
	snap = engine.GetSnapshot()
	if snap.CurrentState != StatePlanning {
		t.Errorf("expected state PLANNING, got %s", snap.CurrentState)
	}

	_ = res
}
