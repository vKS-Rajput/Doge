package runtime

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ExecutionRequest specifies a command execution invocation.
type ExecutionRequest struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	WorkDir   string            `json:"work_dir"`
	Env       map[string]string `json:"env"`
	RunInWSL  bool              `json:"run_in_wsl"`
	WSLDistro string            `json:"wsl_distro,omitempty"`
	Timeout   time.Duration     `json:"timeout"`
}

// ExecutionResult records the completed process execution trace.
type ExecutionResult struct {
	PID         int           `json:"pid"`
	ExitCode    int           `json:"exit_code"`
	Stdout      string        `json:"stdout"`
	Stderr      string        `json:"stderr"`
	Duration    time.Duration `json:"duration"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Error       error         `json:"error,omitempty"`
}

// ActiveProcess tracks a currently running background process.
type ActiveProcess struct {
	ID        string
	PID       int
	Command   string
	StartedAt time.Time
	cancel    context.CancelFunc
}

// ProcessManager coordinates process lifecycles and real-time output streaming.
type ProcessManager struct {
	mu          sync.RWMutex
	wsl         *WSLManager
	broadcaster *EventBroadcaster
	active      map[int]*ActiveProcess
}

// NewProcessManager creates a process manager.
func NewProcessManager(wsl *WSLManager, b *EventBroadcaster) *ProcessManager {
	return &ProcessManager{
		wsl:         wsl,
		broadcaster: b,
		active:      make(map[int]*ActiveProcess),
	}
}

// Execute runs a command synchronously and returns the complete result.
func (m *ProcessManager) Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	return m.Stream(ctx, req, nil, nil)
}

// Stream executes a command and streams stdout and stderr lines in real time to handlers.
func (m *ProcessManager) Stream(
	ctx context.Context,
	req ExecutionRequest,
	onStdout func(string),
	onStderr func(string),
) (*ExecutionResult, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	start := time.Now().UTC()

	var bin string
	var args []string

	if req.RunInWSL && m.wsl.IsAvailable() {
		bin = m.wsl.binaryPath
		if req.WSLDistro != "" {
			args = append(args, "-d", req.WSLDistro)
		}
		// Convert work dir if specified
		if req.WorkDir != "" {
			wslDir := m.wsl.ConvertPathToWSL(req.WorkDir)
			args = append(args, "--cd", wslDir)
		}
		fullCmd := req.Command
		if len(req.Args) > 0 {
			fullCmd = fullCmd + " " + strings.Join(req.Args, " ")
		}
		args = append(args, "--", "sh", "-c", fullCmd)
	} else {
		bin = req.Command
		args = req.Args
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	if !req.RunInWSL && req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	if len(req.Env) > 0 {
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return &ExecutionResult{
			StartedAt:   start,
			CompletedAt: time.Now().UTC(),
			Duration:    time.Since(start),
			Error:       err,
		}, err
	}

	pid := cmd.Process.Pid
	m.registerProcess(pid, req.Command)
	defer m.unregisterProcess(pid)

	if m.broadcaster != nil {
		m.broadcaster.Broadcast(EventProcessStarted, "process", fmt.Sprintf("Started process [%d]: %s", pid, req.Command), map[string]any{
			"pid":     pid,
			"command": req.Command,
			"in_wsl":  req.RunInWSL,
		})
	}

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream stdout line by line
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(io.TeeReader(stdoutPipe, &stdoutBuf))
		for scanner.Scan() {
			line := scanner.Text()
			if onStdout != nil {
				onStdout(line)
			}
			if m.broadcaster != nil {
				m.broadcaster.Broadcast(EventProcessOutput, "stdout", line, map[string]any{
					"pid":    pid,
					"stream": "stdout",
				})
			}
		}
	}()

	// Stream stderr line by line
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(io.TeeReader(stderrPipe, &stderrBuf))
		for scanner.Scan() {
			line := scanner.Text()
			if onStderr != nil {
				onStderr(line)
			}
			if m.broadcaster != nil {
				m.broadcaster.Broadcast(EventProcessOutput, "stderr", line, map[string]any{
					"pid":    pid,
					"stream": "stderr",
				})
			}
		}
	}()

	wg.Wait()
	waitErr := cmd.Wait()
	completedAt := time.Now().UTC()
	duration := completedAt.Sub(start)

	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	if m.broadcaster != nil {
		m.broadcaster.Broadcast(EventProcessExited, "process", fmt.Sprintf("Process [%d] exited with code %d", pid, exitCode), map[string]any{
			"pid":       pid,
			"exit_code": exitCode,
			"duration":  duration.Milliseconds(),
		})
	}

	return &ExecutionResult{
		PID:         pid,
		ExitCode:    exitCode,
		Stdout:      strings.TrimSpace(stdoutBuf.String()),
		Stderr:      strings.TrimSpace(stderrBuf.String()),
		Duration:    duration,
		StartedAt:   start,
		CompletedAt: completedAt,
		Error:       waitErr,
	}, nil
}

func (m *ProcessManager) registerProcess(pid int, cmd string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[pid] = &ActiveProcess{
		PID:       pid,
		Command:   cmd,
		StartedAt: time.Now().UTC(),
	}
}

func (m *ProcessManager) unregisterProcess(pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, pid)
}

// ActiveProcesses returns a list of currently executing processes.
func (m *ProcessManager) ActiveProcesses() []*ActiveProcess {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*ActiveProcess, 0, len(m.active))
	for _, p := range m.active {
		res = append(res, p)
	}
	return res
}
