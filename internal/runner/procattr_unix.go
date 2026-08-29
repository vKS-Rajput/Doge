//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// setProcAttr puts the child process in its own process group on
// Linux/macOS. This prevents the child from interfering with the
// parent's terminal state (e.g., nmap's progress bar, bash job
// control, signal propagation).
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}
