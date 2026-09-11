package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// DistroInfo represents an installed WSL Linux distribution.
type DistroInfo struct {
	Name      string `json:"name"`
	IsDefault bool   `json:"is_default"`
	State     string `json:"state"` // "Running", "Stopped"
	Version   int    `json:"version"`
}

// WSLStatus summarizes the host WSL2 configuration.
type WSLStatus struct {
	Available         bool         `json:"available"`
	DefaultDistro     string       `json:"default_distro"`
	DefaultVersion    int          `json:"default_version"`
	Distros           []DistroInfo `json:"distros"`
	KernelVersion     string       `json:"kernel_version,omitempty"`
	PreferredSecurity string       `json:"preferred_security_distro,omitempty"` // e.g. "kali-linux" or "doge-security"
}

// WSLManager coordinates interactions with the Windows Subsystem for Linux (WSL2).
type WSLManager struct {
	binaryPath  string
	broadcaster *EventBroadcaster
}

// NewWSLManager creates a WSL manager.
func NewWSLManager(b *EventBroadcaster) *WSLManager {
	bin := "wsl.exe"
	if runtime.GOOS != "windows" {
		bin = "wsl"
	}
	return &WSLManager{
		binaryPath:  bin,
		broadcaster: b,
	}
}

// IsAvailable checks whether wsl.exe exists and can be executed.
func (m *WSLManager) IsAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	_, err := exec.LookPath(m.binaryPath)
	return err == nil
}

// GetStatus probes WSL configuration and installed distributions.
func (m *WSLManager) GetStatus(ctx context.Context) (*WSLStatus, error) {
	status := &WSLStatus{
		Available: m.IsAvailable(),
		Distros:   make([]DistroInfo, 0),
	}

	if !status.Available {
		return status, nil
	}

	distros, err := m.ListDistros(ctx)
	if err == nil {
		status.Distros = distros
		for _, d := range distros {
			if d.IsDefault {
				status.DefaultDistro = d.Name
				status.DefaultVersion = d.Version
			}
			// Prefer Kali Linux or a dedicated doge distro for offensive lab execution
			nameLower := strings.ToLower(d.Name)
			if strings.Contains(nameLower, "kali") || strings.Contains(nameLower, "doge") {
				status.PreferredSecurity = d.Name
			}
		}
		if status.PreferredSecurity == "" && len(distros) > 0 {
			if status.DefaultDistro != "" {
				status.PreferredSecurity = status.DefaultDistro
			} else {
				status.PreferredSecurity = distros[0].Name
			}
		}
	}

	return status, nil
}

// ListDistros enumerates all installed WSL distributions.
func (m *WSLManager) ListDistros(ctx context.Context) ([]DistroInfo, error) {
	if !m.IsAvailable() {
		return nil, fmt.Errorf("WSL is not available on this system")
	}

	cmd := exec.CommandContext(ctx, m.binaryPath, "--list", "--verbose")
	outBytes, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query wsl --list: %w", err)
	}

	output := cleanWSLText(outBytes)
	lines := strings.Split(output, "\n")

	var distros []DistroInfo
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "NAME") || strings.Contains(trimmed, "STATE") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}

		isDefault := false
		nameIdx := 0
		if fields[0] == "*" {
			isDefault = true
			nameIdx = 1
		}

		if nameIdx >= len(fields) {
			continue
		}

		distroName := fields[nameIdx]
		state := "Unknown"
		version := 2

		if len(fields) > nameIdx+1 {
			state = fields[nameIdx+1]
		}
		if len(fields) > nameIdx+2 {
			if fields[nameIdx+2] == "1" {
				version = 1
			} else if fields[nameIdx+2] == "2" {
				version = 2
			}
		}

		distros = append(distros, DistroInfo{
			Name:      distroName,
			IsDefault: isDefault,
			State:     state,
			Version:   version,
		})
	}

	return distros, nil
}

// ConvertPathToWSL translates a Windows path (e.g. C:\Users\...) into a WSL path (e.g. /mnt/c/Users/...).
func (m *WSLManager) ConvertPathToWSL(winPath string) string {
	if winPath == "" {
		return ""
	}

	clean := filepath.Clean(winPath)
	// Check drive letter pattern (e.g. C:\ or c:\)
	if len(clean) >= 2 && clean[1] == ':' {
		drive := strings.ToLower(string(clean[0]))
		rest := strings.ReplaceAll(clean[2:], `\`, `/`)
		return "/mnt/" + drive + rest
	}

	return strings.ReplaceAll(clean, `\`, `/`)
}

// ConvertPathToWindows translates a WSL mount path (e.g. /mnt/c/...) into a Windows path (e.g. C:\...).
func (m *WSLManager) ConvertPathToWindows(wslPath string) string {
	if !strings.HasPrefix(wslPath, "/mnt/") || len(wslPath) < 7 {
		return wslPath
	}

	driveLetter := strings.ToUpper(string(wslPath[5]))
	remainder := wslPath[6:]
	winRemainder := strings.ReplaceAll(remainder, `/`, `\`)
	return fmt.Sprintf("%s:%s", driveLetter, winRemainder)
}

// CheckTool tests whether a security tool is installed and accessible in the target distro.
func (m *WSLManager) CheckTool(ctx context.Context, distro, toolName string) (bool, string, error) {
	if !m.IsAvailable() {
		return false, "", fmt.Errorf("WSL is not available")
	}

	args := []string{}
	if distro != "" {
		args = append(args, "-d", distro)
	}
	args = append(args, "--", "which", toolName)

	cmd := exec.CommandContext(ctx, m.binaryPath, args...)
	out, err := cmd.Output()
	if err != nil {
		return false, "", nil
	}

	path := strings.TrimSpace(string(out))
	return path != "", path, nil
}

// CheckToolsBatch tests multiple security tools in a single WSL invocation.
func (m *WSLManager) CheckToolsBatch(ctx context.Context, distro string, toolNames []string) map[string]string {
	results := make(map[string]string)
	if !m.IsAvailable() || len(toolNames) == 0 {
		return results
	}

	args := []string{}
	if distro != "" {
		args = append(args, "-d", distro)
	}
	args = append(args, "--", "which")
	args = append(args, toolNames...)

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, m.binaryPath, args...)
	out, _ := cmd.Output()
	if len(out) == 0 {
		return results
	}

	lines := strings.Split(cleanWSLText(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Match tool name from path (e.g. /usr/bin/nmap -> nmap)
		parts := strings.Split(trimmed, "/")
		base := parts[len(parts)-1]
		results[base] = trimmed
	}
	return results
}

// cleanWSLText decodes Windows console UTF-16LE output or strips null byte interleaving.
func cleanWSLText(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Check for UTF-16LE BOM: 0xFF 0xFE
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		u16 := make([]uint16, (len(data)-2)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(data[2+i*2]) | (uint16(data[3+i*2]) << 8)
		}
		return string(utf16.Decode(u16))
	}

	// Check if every second byte is 0x00 (UTF-16LE without BOM)
	nullCount := 0
	for i := 1; i < len(data); i += 2 {
		if data[i] == 0x00 {
			nullCount++
		}
	}

	if nullCount > len(data)/4 {
		// Null-interleaved UTF-16LE text
		var buf bytes.Buffer
		for i := 0; i < len(data); i += 2 {
			if data[i] != 0x00 && data[i] != '\r' {
				buf.WriteByte(data[i])
			}
		}
		return buf.String()
	}

	// Standard UTF-8 text
	str := string(data)
	str = strings.ReplaceAll(str, "\x00", "")
	str = strings.ReplaceAll(str, "\r\n", "\n")
	return str
}
