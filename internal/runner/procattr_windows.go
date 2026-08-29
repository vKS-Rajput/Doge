//go:build windows

package runner

import "os/exec"

// setProcAttr is a no-op on Windows. Windows doesn't use Unix process
// groups, so no isolation is needed for terminal state.
func setProcAttr(cmd *exec.Cmd) {
	// No-op on Windows.
}
