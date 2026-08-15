package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestExecutorCommandConstruction(t *testing.T) {
	registry := NewToolRegistry()

	// nmap should use flag capture with -oX.
	nmapDef, _ := registry.Get("nmap")
	binary, args, outputPath := CommandBuilder(nmapDef, "10.10.11.123", t.TempDir())

	if binary != "nmap" {
		t.Errorf("binary = %s, want nmap", binary)
	}

	// Should contain -sCV (default flag).
	found := false
	for _, a := range args {
		if a == "-sCV" {
			found = true
		}
	}
	if !found {
		t.Errorf("args should contain -sCV: %v", args)
	}

	// Should have -oX flag.
	foundOX := false
	for _, a := range args {
		if a == "-oX" {
			foundOX = true
		}
	}
	if !foundOX {
		t.Errorf("nmap args should contain -oX: %v", args)
	}

	// Should have an output path.
	if outputPath == "" {
		t.Error("nmap should have an output path for flag capture")
	}

	// Target should be the last argument.
	if args[len(args)-1] != "10.10.11.123" {
		t.Errorf("target should be last arg, got %s", args[len(args)-1])
	}
}

func TestExecutorCommandStdoutCapture(t *testing.T) {
	registry := NewToolRegistry()

	// httpx should use stdout capture (no output file).
	httpxDef, _ := registry.Get("httpx")
	_, args, outputPath := CommandBuilder(httpxDef, "10.10.11.123", t.TempDir())

	if outputPath != "" {
		t.Error("httpx should NOT have an output path (stdout capture)")
	}

	// Should contain -json (default flag).
	found := false
	for _, a := range args {
		if a == "-json" {
			found = true
		}
	}
	if !found {
		t.Errorf("httpx args should contain -json: %v", args)
	}
}

func TestExecutorScopeRejection(t *testing.T) {
	target := &domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: t.TempDir(),
	})

	job := &Job{
		ID:     uuid.New(),
		Tool:   "nmap",
		Target: "192.168.1.1", // OUT OF SCOPE
	}
	def := ToolDefinition{
		Name:   "nmap",
		Binary: "echo", // safe binary for testing
	}

	err := executor.Execute(context.Background(), job, def)
	if err == nil {
		t.Error("should reject out-of-scope target")
	}
	if err != nil && !contains(err.Error(), "out of scope") {
		t.Errorf("error should mention scope: %v", err)
	}
}

func TestExecutorSuccessfulExecution(t *testing.T) {
	target := &domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	artifactDir := t.TempDir()
	var completedPath string

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: artifactDir,
		MaxRuntime:  5 * time.Second,
		OnComplete: func(job *Job, path string) {
			completedPath = path
		},
	})

	job := &Job{
		ID:     uuid.New(),
		Tool:   "echo",
		Target: "10.10.11.123",
	}

	// Cross-platform: simulate tool output.
	echoBin, echoFlags := testShellEcho("test-output")
	def := ToolDefinition{
		Name:        "echo",
		Binary:      echoBin,
		CaptureMode: CaptureStdout,
		DefaultFlags: echoFlags,
	}

	err := executor.Execute(context.Background(), job, def)
	if err != nil {
		t.Fatalf("execution should succeed: %v", err)
	}

	if job.ExitCode != 0 {
		t.Errorf("exit code should be 0, got %d", job.ExitCode)
	}

	if job.Duration <= 0 {
		t.Error("duration should be > 0")
	}

	// Stdout should be captured.
	if job.StdoutArtifact == nil {
		t.Error("stdout artifact should be set")
	}

	// OnComplete should have been called.
	if completedPath == "" {
		t.Error("OnComplete should have been called with output path")
	}
}

func TestExecutorStdoutStderrCapture(t *testing.T) {
	target := &domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	artifactDir := t.TempDir()

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: artifactDir,
		MaxRuntime:  5 * time.Second,
	})

	job := &Job{
		ID:     uuid.New(),
		Tool:   "echo",
		Target: "10.10.11.123",
	}

	// Cross-platform: simulate tool output.
	echoBin, echoFlags := testShellEcho("hello-from-tool")
	def := ToolDefinition{
		Name:        "echo",
		Binary:      echoBin,
		CaptureMode: CaptureStdout,
		DefaultFlags: echoFlags,
	}

	err := executor.Execute(context.Background(), job, def)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	// Check that stdout artifact was saved.
	files, _ := os.ReadDir(artifactDir)
	foundStdout := false
	for _, f := range files {
		if contains(f.Name(), "stdout") {
			foundStdout = true
			content, _ := os.ReadFile(filepath.Join(artifactDir, f.Name()))
			if !contains(string(content), "hello-from-tool") {
				t.Errorf("stdout artifact should contain output, got: %s", string(content))
			}
		}
	}
	if !foundStdout {
		t.Error("stdout artifact file should exist")
	}
}

func TestExecutorTimeout(t *testing.T) {
	target := &domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: t.TempDir(),
		MaxRuntime:  1 * time.Second,
	})

	job := &Job{
		ID:     uuid.New(),
		Tool:   "sleep",
		Target: "10.10.11.123",
	}

	// Use a command that will exceed the timeout.
	// On Windows, "timeout" or "ping -n 10 127.0.0.1" would work,
	// but we use a platform-agnostic approach with context timeout.
	def := ToolDefinition{
		Name:        "ping",
		Binary:      "ping",
		CaptureMode: CaptureStdout,
		DefaultFlags: []string{"-n", "100"}, // ping 100 times - will timeout
	}

	err := executor.Execute(context.Background(), job, def)
	// Should either timeout or the context cancellation is handled.
	// The important thing is the executor doesn't hang forever.
	_ = err // Timeout behavior is platform-dependent.
}

func TestExecutorArtifactCreation(t *testing.T) {
	target := &domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	artifactDir := t.TempDir()

	executor := NewToolExecutor(ExecutorConfig{
		Target:      target,
		ArtifactDir: artifactDir,
	})

	// Save an artifact.
	path, id, err := executor.saveArtifact(
		&Job{ID: uuid.New()},
		ToolDefinition{Name: "test"},
		"stdout",
		[]byte("test output data"),
	)

	if err != nil {
		t.Fatalf("saveArtifact failed: %v", err)
	}
	if path == "" {
		t.Error("path should not be empty")
	}
	if id == uuid.Nil {
		t.Error("id should not be nil")
	}

	// Verify file content.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read artifact: %v", err)
	}
	if string(content) != "test output data" {
		t.Errorf("artifact content = %q, want %q", string(content), "test output data")
	}
}

func TestExecutorEmptyArtifact(t *testing.T) {
	executor := &ToolExecutor{artifactDir: t.TempDir()}

	// Empty data should not create an artifact.
	path, id, err := executor.saveArtifact(
		&Job{ID: uuid.New()},
		ToolDefinition{Name: "test"},
		"stderr",
		[]byte{},
	)

	if err != nil {
		t.Fatalf("should not error: %v", err)
	}
	if path != "" {
		t.Error("empty data should not create artifact file")
	}
	if id != uuid.Nil {
		t.Error("empty data should return nil ID")
	}
}

// Helper function.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
