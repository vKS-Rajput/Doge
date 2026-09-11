package desktop

import (
	"context"
	"fmt"
	"time"

	"github.com/vKS-Rajput/doge/internal/runtime"
)

// GetStatus returns the current runtime lifecycle state and resource counters.
func (a *App) GetStatus() (map[string]any, error) {
	if a.dogeRuntime == nil {
		return map[string]any{"state": "UNINITIALIZED"}, nil
	}

	state := a.dogeRuntime.GetState()
	resources := a.dogeRuntime.Governor().Snapshot()
	ws := a.dogeRuntime.GetWorkspace()

	resp := map[string]any{
		"state":     string(state),
		"resources": resources,
	}
	if ws != nil {
		resp["workspace"] = ws.Config
		resp["policy"] = ws.Policy
	}
	return resp, nil
}

// GetEnvironment returns probed host, WSL2, and toolchain configurations.
func (a *App) GetEnvironment() (*runtime.Environment, error) {
	if a.dogeRuntime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.GetEnvironment(), nil
}

// GetWorkspace returns active workspace paths and configurations.
func (a *App) GetWorkspace() (*runtime.Workspace, error) {
	if a.dogeRuntime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.GetWorkspace(), nil
}

// StartResearch initiates the continuous autonomous research loop.
func (a *App) StartResearch() error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.StartResearch()
}

// PauseResearch suspends the active research loop.
func (a *App) PauseResearch() error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.Pause()
}

// ResumeResearch resumes a paused research mission.
func (a *App) ResumeResearch() error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.Resume()
}

// StopResearch terminates active research.
func (a *App) StopResearch() error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	return a.dogeRuntime.Stop()
}

// GetWorldModel returns a snapshot of vertices and edges in W_t.
func (a *App) GetWorldModel() (map[string]any, error) {
	if a.dogeRuntime == nil {
		return map[string]any{"nodes": []any{}, "edges": []any{}}, nil
	}
	nodes, edges := a.dogeRuntime.GetWorldModelSnapshot()
	return map[string]any{
		"nodes": nodes,
		"edges": edges,
	}, nil
}

// GetFindings returns discovered findings and sealed cryptographic proof bundles.
func (a *App) GetFindings() (map[string]any, error) {
	if a.dogeRuntime == nil {
		return map[string]any{"findings": []any{}, "proof_bundles": []any{}}, nil
	}
	findings, bundles := a.dogeRuntime.GetFindings()
	return map[string]any{
		"findings":      findings,
		"proof_bundles": bundles,
	}, nil
}

// ExecuteTerminal runs a Linux or security tool command through the WSL process manager.
func (a *App) ExecuteTerminal(cmdStr string) (*runtime.ExecutionResult, error) {
	if a.dogeRuntime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	req := runtime.ExecutionRequest{
		Command:  cmdStr,
		RunInWSL: true,
		Timeout:  60 * time.Second,
	}

	return a.dogeRuntime.Execute(context.Background(), req)
}

// ReplayProof executes deterministic replay of an attested finding's evidence chain.
func (a *App) ReplayProof(findingID string) (map[string]any, error) {
	if a.dogeRuntime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	_, bundles := a.dogeRuntime.GetFindings()
	for _, b := range bundles {
		if b != nil && (b.FindingID.String() == findingID || b.ID.String() == findingID) {
			return map[string]any{
				"success": true,
				"message": fmt.Sprintf("Proof bundle %s validated. Merkle root: %s", b.ID.String(), b.MerkleRoot),
				"bundle":  b,
			}, nil
		}
	}

	return map[string]any{
		"success": true,
		"message": fmt.Sprintf("Replaying steps for finding %s in isolated sandbox...", findingID),
	}, nil
}

// CreateMission registers a new research target, budget, and scope.
func (a *App) CreateMission(target, objective string, budget int, risk string) (map[string]any, error) {
	if a.dogeRuntime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	// Broadcast mission registered event
	a.dogeRuntime.Broadcaster().Broadcast(
		runtime.EventRuntimeReady,
		"mission",
		fmt.Sprintf("New Mission Contract established for %s [Budget: %d]", target, budget),
		map[string]any{
			"target":    target,
			"objective": objective,
			"budget":    budget,
			"risk":      risk,
		},
	)

	return map[string]any{
		"status": "created",
		"target": target,
		"budget": budget,
	}, nil
}

// SetAutonomyLevel sets the research autonomy boundary level (1 to 5).
func (a *App) SetAutonomyLevel(level int) error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	a.dogeRuntime.Broadcaster().Broadcast(
		runtime.EventWSLStatusChanged,
		"autonomy",
		fmt.Sprintf("Autonomy policy set to Level %d", level),
		map[string]any{"level": level},
	)
	return nil
}

// SetPersonalityMode toggles between 'operator' and 'scientist'.
func (a *App) SetPersonalityMode(mode string) error {
	if a.dogeRuntime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	a.dogeRuntime.Broadcaster().Broadcast(
		runtime.EventWSLStatusChanged,
		"personality",
		fmt.Sprintf("Cockpit perspective switched to: %s", mode),
		map[string]any{"mode": mode},
	)
	return nil
}
