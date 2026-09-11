package runtime

import (
	"context"
	"os/exec"
	"runtime"

	"github.com/vKS-Rajput/doge/internal/report"
)

// ToolStatus captures the availability of an offensive security tool.
type ToolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	InWSL     bool   `json:"in_wsl"`
	Distro    string `json:"distro,omitempty"`
}

// Environment represents the comprehensive host and research environment state.
type Environment struct {
	OperatingSystem   string                `json:"os"`
	Architecture      string                `json:"architecture"`
	GoVersion         string                `json:"go_version"`
	EngineVersion     string                `json:"engine_version"`
	WSL               *WSLStatus            `json:"wsl"`
	Toolchain         map[string]ToolStatus `json:"toolchain"`
	WorkspaceRoot     string                `json:"workspace_root"`
	NetworkPolicy     string                `json:"network_policy"`   // "Strict", "Permissive", "Airgapped"
	ExecutionPolicy   string                `json:"execution_policy"` // "Authorized", "Supervised", "Autonomous"
}

// DefaultResearchTools lists the standard suite of offensive research tools tracked by DOGE.
var DefaultResearchTools = []string{
	"nmap",
	"httpx",
	"ffuf",
	"nuclei",
	"sqlmap",
	"amass",
	"subfinder",
	"feroxbuster",
	"katana",
	"dalfox",
	"whatweb",
}

// EnvironmentManager probes and verifies host and laboratory tooling.
type EnvironmentManager struct {
	wsl         *WSLManager
	broadcaster *EventBroadcaster
}

// NewEnvironmentManager creates an environment manager.
func NewEnvironmentManager(wsl *WSLManager, b *EventBroadcaster) *EnvironmentManager {
	return &EnvironmentManager{
		wsl:         wsl,
		broadcaster: b,
	}
}

// Detect inspects host OS, WSL2 distros, Go engine, and security tooling.
func (m *EnvironmentManager) Detect(ctx context.Context, workspaceRoot string) (*Environment, error) {
	wslStatus, _ := m.wsl.GetStatus(ctx)

	env := &Environment{
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		GoVersion:       runtime.Version(),
		EngineVersion:   report.DogeEngineVersion,
		WSL:             wslStatus,
		Toolchain:       make(map[string]ToolStatus),
		WorkspaceRoot:   workspaceRoot,
		NetworkPolicy:   "Strict",
		ExecutionPolicy: "Authorized",
	}

	// Probe standard tools: first check native PATH, then check WSL preferred distro
	distro := ""
	if wslStatus != nil && wslStatus.Available {
		distro = wslStatus.PreferredSecurity
	}

	// Check native Windows / Host PATH first
	var missingTools []string
	for _, tool := range DefaultResearchTools {
		status := ToolStatus{Name: tool}
		if p, err := exec.LookPath(tool); err == nil {
			status.Installed = true
			status.Path = p
			status.InWSL = false
			env.Toolchain[tool] = status
		} else {
			missingTools = append(missingTools, tool)
		}
	}

	// Check WSL laboratory environment in a single batch call
	if m.wsl.IsAvailable() && distro != "" && len(missingTools) > 0 {
		wslFound := m.wsl.CheckToolsBatch(ctx, distro, missingTools)
		for _, tool := range missingTools {
			status := ToolStatus{Name: tool}
			if p, ok := wslFound[tool]; ok {
				status.Installed = true
				status.Path = p
				status.InWSL = true
				status.Distro = distro
			}
			env.Toolchain[tool] = status
		}
	} else {
		for _, tool := range missingTools {
			env.Toolchain[tool] = ToolStatus{Name: tool}
		}
	}

	return env, nil
}
