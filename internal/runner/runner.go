// Package runner executes commands and captures everything for DOGE.
//
// The runner is the bridge between "you work normally" and "DOGE
// observes everything." It wraps any shell command, tees output
// so the user sees it in real-time, and captures:
//
//   - Full command line
//   - Working directory
//   - Start/end timestamps
//   - Exit code
//   - stdout + stderr
//   - Files created or modified during execution
//
// The captured RunResult feeds into the journal + ingestion pipeline.
package runner

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RunResult captures everything about a command execution.
type RunResult struct {
	// Command is the full command line that was executed.
	Command string

	// Args are the shell arguments.
	Args []string

	// WorkingDir is where the command ran.
	WorkingDir string

	// Stdout is the captured standard output.
	Stdout string

	// Stderr is the captured standard error.
	Stderr string

	// ExitCode is the process exit code.
	ExitCode int

	// StartedAt is when execution began.
	StartedAt time.Time

	// CompletedAt is when execution finished.
	CompletedAt time.Time

	// Duration is how long it took.
	Duration time.Duration

	// NewFiles are files created during execution (relative to WorkingDir).
	NewFiles []string

	// ModifiedFiles are files modified during execution (relative to WorkingDir).
	ModifiedFiles []string

	// Error is any execution error (command not found, etc.)
	Error error
}

// fileSnapshot captures file mod times for change detection.
type fileSnapshot map[string]time.Time

// Run executes a command string through the OS shell, capturing everything.
// Output is tee'd to the provided writers (typically os.Stdout/os.Stderr)
// so the user sees normal output while DOGE captures it.
func Run(command string, workDir string, stdout, stderr io.Writer) *RunResult {
	result := &RunResult{
		Command:    command,
		WorkingDir: workDir,
		StartedAt:  time.Now(),
	}

	// Snapshot files before execution.
	before := snapshotDir(workDir)

	// Build shell command based on OS.
	var cmd *exec.Cmd
	shell, shellArg := detectShell()
	cmd = exec.Command(shell, shellArg, command)
	cmd.Dir = workDir

	result.Args = []string{shell, shellArg, command}

	// Capture stdout: tee to user's terminal + buffer.
	var stdoutBuf bytes.Buffer
	if stdout != nil {
		cmd.Stdout = io.MultiWriter(stdout, &stdoutBuf)
	} else {
		cmd.Stdout = &stdoutBuf
	}

	// Capture stderr: tee to user's terminal + buffer.
	var stderrBuf bytes.Buffer
	if stderr != nil {
		cmd.Stderr = io.MultiWriter(stderr, &stderrBuf)
	} else {
		cmd.Stderr = &stderrBuf
	}

	// IMPORTANT: Do NOT pass os.Stdin to child processes.
	// The DOGE research shell owns stdin via bufio.Reader.
	// Child processes get /dev/null as stdin.
	cmd.Stdin = nil

	// Isolate child process group (platform-specific).
	setProcAttr(cmd)

	// Execute.
	err := cmd.Run()
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()

	if err != nil {
		result.Error = err
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	} else {
		result.ExitCode = 0
	}

	// Snapshot files after execution, detect changes.
	after := snapshotDir(workDir)
	result.NewFiles, result.ModifiedFiles = diffSnapshots(before, after)

	return result
}

// DetectTool attempts to identify the security tool from the command string.
func DetectTool(command string) string {
	cmd := strings.TrimSpace(command)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "unknown"
	}

	base := filepath.Base(parts[0])

	// Known security tools.
	knownTools := map[string]string{
		"nmap":       "nmap",
		"httpx":      "httpx",
		"katana":     "katana",
		"ffuf":       "ffuf",
		"nuclei":     "nuclei",
		"subfinder":  "subfinder",
		"dnsx":       "dnsx",
		"curl":       "curl",
		"wget":       "wget",
		"nikto":      "nikto",
		"gobuster":   "gobuster",
		"dirb":       "dirb",
		"sqlmap":     "sqlmap",
		"wfuzz":      "wfuzz",
		"feroxbuster": "feroxbuster",
		"amass":      "amass",
		"masscan":    "masscan",
		"rustscan":   "rustscan",
		"whatweb":    "whatweb",
		"wappalyzer": "wappalyzer",
		"testssl.sh": "testssl",
		"sslyze":     "sslyze",
		"burp":       "burp",
	}

	if tool, ok := knownTools[base]; ok {
		return tool
	}

	// Fallback: use the command name itself.
	return base
}

// detectShell returns the shell and flag for the current OS.
func detectShell() (string, string) {
	if runtime.GOOS == "windows" {
		// Check for WSL bash first, then powershell.
		if _, err := exec.LookPath("bash"); err == nil {
			return "bash", "-c"
		}
		return "powershell", "-Command"
	}
	// Linux/macOS: use bash.
	return "bash", "-c"
}

// MaxCaptureFileSize is the largest file DOGE will auto-capture (50 MB).
const MaxCaptureFileSize = 50 * 1024 * 1024

// snapshotDir captures modification times of files in the workspace.
// Safety: skips .doge, .git, node_modules, hidden dirs, and large files.
// Only walks 3 directory levels deep to avoid scanning huge trees.
func snapshotDir(dir string) fileSnapshot {
	snap := make(fileSnapshot)
	baseDepth := strings.Count(filepath.ToSlash(dir), "/")

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip dangerous/irrelevant directories.
		if info.IsDir() {
			name := info.Name()
			if name == ".doge" || name == ".git" || name == "node_modules" ||
				name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			// Skip hidden directories (except workspace root).
			if len(name) > 1 && name[0] == '.' && path != dir {
				return filepath.SkipDir
			}
			// Limit depth to 3 levels.
			depth := strings.Count(filepath.ToSlash(path), "/") - baseDepth
			if depth > 3 {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that are too large.
		if info.Size() > MaxCaptureFileSize {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		snap[rel] = info.ModTime()
		return nil
	})
	return snap
}

// diffSnapshots identifies new and modified files between two snapshots.
func diffSnapshots(before, after fileSnapshot) (newFiles, modified []string) {
	for path, modTime := range after {
		if beforeTime, exists := before[path]; !exists {
			newFiles = append(newFiles, path)
		} else if modTime.After(beforeTime) {
			modified = append(modified, path)
		}
	}
	return
}
