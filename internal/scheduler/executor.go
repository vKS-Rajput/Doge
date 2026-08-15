package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ToolExecutor runs tool jobs as child processes.
//
// The executor is the "hands" of the scheduler. It:
//   - Constructs commands from the ToolRegistry
//   - Executes them as child processes
//   - Captures stdout and stderr independently
//   - Preserves raw output as immutable artifacts
//   - Records exit code, duration, and artifact paths
//   - Routes output to the ingestion callback
//   - Enforces job timeout
//   - Enforces scope before execution
//
// The executor does NOT:
//   - Accept commands from AI reasoning
//   - Construct arbitrary shell commands
//   - Run exploitation tools
type ToolExecutor struct {
	target      *domain.Target
	artifactDir string
	logger      *slog.Logger

	// OnJobComplete is called after a job finishes, with the
	// path to the raw output file. This is how output flows to
	// ingestion without the executor knowing about parsers.
	OnJobComplete func(job *Job, outputPath string)

	// MaxRuntime enforces per-job timeout.
	MaxRuntime time.Duration
}

// ExecutorConfig configures the executor.
type ExecutorConfig struct {
	Target      *domain.Target
	ArtifactDir string
	Logger      *slog.Logger
	MaxRuntime  time.Duration
	OnComplete  func(job *Job, outputPath string)
}

// NewToolExecutor creates a new executor.
func NewToolExecutor(cfg ExecutorConfig) *ToolExecutor {
	if cfg.MaxRuntime <= 0 {
		cfg.MaxRuntime = 10 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &ToolExecutor{
		target:        cfg.Target,
		artifactDir:   cfg.ArtifactDir,
		logger:        cfg.Logger,
		MaxRuntime:    cfg.MaxRuntime,
		OnJobComplete: cfg.OnComplete,
	}
}

// Execute runs a job as a child process.
// This is the Executor interface implementation.
func (e *ToolExecutor) Execute(ctx context.Context, job *Job, def ToolDefinition) error {
	// Gate 1: Scope enforcement before execution.
	if !e.target.InScope(job.Target) {
		return fmt.Errorf("target %q is out of scope — execution DENIED", job.Target)
	}

	// Gate 2: Verify binary exists.
	binaryPath, err := exec.LookPath(def.Binary)
	if err != nil {
		return fmt.Errorf("tool binary not found: %s: %w", def.Binary, err)
	}

	// Construct the command.
	args, outputPath := e.buildArgs(job, def)

	e.logger.Info("executing tool",
		"tool", def.Name,
		"binary", binaryPath,
		"target", job.Target,
		"args", args,
		"job_id", job.ID)

	// Apply job timeout.
	execCtx, cancel := context.WithTimeout(ctx, e.MaxRuntime)
	defer cancel()

	cmd := exec.CommandContext(execCtx, binaryPath, args...)

	// Capture stdout and stderr independently.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute.
	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	// Record exit code.
	job.ExitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			job.ExitCode = exitErr.ExitCode()
		}
	}
	job.Duration = duration

	e.logger.Info("tool execution finished",
		"tool", def.Name,
		"exit_code", job.ExitCode,
		"duration", duration,
		"stdout_bytes", stdout.Len(),
		"stderr_bytes", stderr.Len(),
		"job_id", job.ID)

	// Persist raw output as immutable artifacts.
	// ALWAYS save the raw output, even on failure.
	stdoutPath, stdoutID, _ := e.saveArtifact(job, def, "stdout", stdout.Bytes())
	stderrPath, stderrID, _ := e.saveArtifact(job, def, "stderr", stderr.Bytes())

	if stdoutID != uuid.Nil {
		job.StdoutArtifact = &stdoutID
	}
	if stderrID != uuid.Nil {
		job.StderrArtifact = &stderrID
	}

	// Determine the output path for ingestion.
	var ingestPath string
	switch def.CaptureMode {
	case CaptureFlag:
		// Output was written to a file via the flag.
		if outputPath != "" {
			if _, err := os.Stat(outputPath); err == nil {
				ingestPath = outputPath
			}
		}
	case CaptureStdout:
		// Output was captured from stdout.
		if stdoutPath != "" {
			ingestPath = stdoutPath
		}
	}

	// Log stderr for diagnostic purposes.
	if stderr.Len() > 0 {
		e.logger.Debug("tool stderr",
			"tool", def.Name,
			"stderr", truncate(stderr.String(), 500),
			"stderr_artifact", stderrPath)
	}

	// Check for execution errors (after saving artifacts).
	if execCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("tool %s timed out after %s", def.Name, e.MaxRuntime)
	}

	// Non-zero exit code is logged but not necessarily fatal.
	// Many tools return non-zero for "found things" or "partial results".
	if job.ExitCode != 0 && stdout.Len() == 0 && (outputPath == "" || !fileExists(outputPath)) {
		return fmt.Errorf("tool %s exited with code %d and produced no output",
			def.Name, job.ExitCode)
	}

	// Route output to ingestion.
	if ingestPath != "" && e.OnJobComplete != nil {
		e.OnJobComplete(job, ingestPath)
	}

	return nil
}

// buildArgs constructs the command-line arguments for a tool.
func (e *ToolExecutor) buildArgs(job *Job, def ToolDefinition) ([]string, string) {
	var args []string
	var outputPath string

	// Add default flags.
	args = append(args, def.DefaultFlags...)

	// Add job-specific arguments.
	args = append(args, job.Arguments...)

	// Handle output capture.
	switch def.CaptureMode {
	case CaptureFlag:
		// Generate output file path.
		outputPath = filepath.Join(e.artifactDir,
			fmt.Sprintf("%s_%s_%s.raw", def.Name, job.ID.String()[:8], time.Now().Format("150405")))
		args = append(args, def.OutputFlag, outputPath)
	}

	// Add target as the last argument.
	args = append(args, job.Target)

	return args, outputPath
}

// saveArtifact writes raw output to the artifact directory.
// Returns the path, a generated ID, and any error.
// NEVER discards raw output.
func (e *ToolExecutor) saveArtifact(job *Job, def ToolDefinition, stream string, data []byte) (string, uuid.UUID, error) {
	if len(data) == 0 {
		return "", uuid.Nil, nil
	}

	// Ensure artifact directory exists.
	if err := os.MkdirAll(e.artifactDir, 0755); err != nil {
		return "", uuid.Nil, fmt.Errorf("creating artifact dir: %w", err)
	}

	artifactID := uuid.New()
	filename := fmt.Sprintf("%s_%s_%s_%s.raw",
		def.Name, stream, job.ID.String()[:8], time.Now().Format("150405"))
	path := filepath.Join(e.artifactDir, filename)

	if err := os.WriteFile(path, data, 0644); err != nil {
		e.logger.Error("failed to save raw artifact",
			"path", path, "error", err,
			"data_len", len(data))
		return "", uuid.Nil, err
	}

	e.logger.Debug("artifact saved",
		"path", path,
		"stream", stream,
		"tool", def.Name,
		"size", len(data))

	return path, artifactID, nil
}

// truncate truncates a string to maxLen.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// fileExists returns true if a file exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CommandBuilder is a utility for testing — constructs the command
// that would be executed without actually running it.
func CommandBuilder(def ToolDefinition, target string, artifactDir string) (binary string, args []string, outputPath string) {
	binary = def.Binary
	job := &Job{
		ID:     uuid.New(),
		Target: target,
	}

	executor := &ToolExecutor{artifactDir: artifactDir}
	args, outputPath = executor.buildArgs(job, def)
	return binary, args, outputPath
}

// ReadOutput reads a saved output artifact.
func ReadOutput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
