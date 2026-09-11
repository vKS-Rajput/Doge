package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// RuntimeConfig parameterizes the DOGE research runtime.
type RuntimeConfig struct {
	WorkspaceRoot string
	TargetURL     string
	Scope         []string
	RequestBudget int
	IPCAddress    string
}

// Runtime is the master operating system kernel for DOGE.
// It bridges the Windows desktop GUI cockpit to the WSL laboratory substrate and the Go research engine.
type Runtime struct {
	mu               sync.RWMutex
	config           RuntimeConfig
	wsl              *WSLManager
	envManager       *EnvironmentManager
	processManager   *ProcessManager
	workspaceManager *WorkspaceManager
	governor         *ResourceGovernor
	lifecycle        *LifecycleManager
	broadcaster      *EventBroadcaster
	ipcServer        *IPCServer
	pipeServer       *PipeServer

	// Active State
	workspace      *Workspace
	environment    *Environment
	worldModel     *worldmodel.UnifiedWorldModelGraph
	provenFindings []domain.ProvenFinding
	proofBundles   []*report.ProofBundle

	// Background Research Execution
	researchCancel context.CancelFunc
}

// NewRuntime creates and initializes the complete DOGE operating runtime.
func NewRuntime(cfg RuntimeConfig) *Runtime {
	broadcaster := NewEventBroadcaster(1000)
	lifecycle := NewLifecycleManager(broadcaster)
	wsl := NewWSLManager(broadcaster)
	envManager := NewEnvironmentManager(wsl, broadcaster)
	processManager := NewProcessManager(wsl, broadcaster)
	workspaceManager := NewWorkspaceManager()

	budget := cfg.RequestBudget
	if budget <= 0 {
		budget = 5000
	}
	governor := NewResourceGovernor(budget, 10, 25)

	rt := &Runtime{
		config:           cfg,
		wsl:              wsl,
		envManager:       envManager,
		processManager:   processManager,
		workspaceManager: workspaceManager,
		governor:         governor,
		lifecycle:        lifecycle,
		broadcaster:      broadcaster,
		provenFindings:   make([]domain.ProvenFinding, 0),
		proofBundles:     make([]*report.ProofBundle, 0),
	}

	rt.ipcServer = NewIPCServer(rt, broadcaster)
	rt.pipeServer = NewPipeServer(rt, broadcaster)
	return rt
}

// Start boots the DOGE runtime, probes host and WSL environments, and initializes/loads workspace.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.lifecycle.TransitionTo(StateStarting, "Booting DOGE research engine"); err != nil {
		return err
	}

	// 1. Initialize or Load Workspace
	wsRoot := r.config.WorkspaceRoot
	if wsRoot == "" {
		wsRoot = "."
	}

	ws, err := r.workspaceManager.Load(wsRoot)
	if err != nil {
		// Initialize new workspace
		target := r.config.TargetURL
		if target == "" {
			target = "authorized-target.local"
		}
		ws, err = r.workspaceManager.Initialize(wsRoot, "DOGE Research Workspace", target, r.config.Scope)
		if err != nil {
			_ = r.lifecycle.TransitionTo(StateStopped, "Workspace initialization failed: "+err.Error())
			return fmt.Errorf("failed to initialize workspace: %w", err)
		}
	}
	r.workspace = ws

	// 2. Initialize World Model Graph
	r.worldModel = worldmodel.NewUnifiedWorldModelGraph(ws.Config.Target)

	// 3. Detect and Verify Environment (Windows + WSL2)
	env, err := r.envManager.Detect(ctx, ws.RootPath)
	if err != nil {
		_ = r.lifecycle.TransitionTo(StateStopped, "Environment detection failed: "+err.Error())
		return fmt.Errorf("failed to detect environment: %w", err)
	}
	r.environment = env

	// 4. Start HTTP/SSE IPC Server if configured
	if r.config.IPCAddress != "" {
		addr, err := r.ipcServer.Start(r.config.IPCAddress)
		if err != nil {
			r.broadcaster.Broadcast(EventWSLStatusChanged, "ipc", "Failed to start HTTP IPC server: "+err.Error(), nil)
		} else {
			r.broadcaster.Broadcast(EventRuntimeReady, "ipc", "Local IPC server listening on "+addr, map[string]any{"address": addr})
		}
	}

	// 5. Start Windows Named Pipe IPC Server
	if r.pipeServer != nil {
		if err := r.pipeServer.Start(DefaultPipePath); err != nil {
			r.broadcaster.Broadcast(EventWSLStatusChanged, "ipc", "Named pipe start notice: "+err.Error(), nil)
		} else {
			r.broadcaster.Broadcast(EventRuntimeReady, "ipc", "Windows Named Pipe IPC ready on "+r.pipeServer.Path(), map[string]any{"pipe": r.pipeServer.Path()})
		}
	}

	// Transition to Ready
	if err := r.lifecycle.TransitionTo(StateReady, "DOGE laboratory environment initialized"); err != nil {
		return err
	}

	return nil
}

// Execute runs a process through the runtime process manager, tracking active processes and output.
func (r *Runtime) Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	if err := r.governor.CheckExecutionCapacity(); err != nil {
		return nil, err
	}

	r.governor.IncrementActiveProcess()
	defer r.governor.DecrementActiveProcess()

	return r.processManager.Execute(ctx, req)
}

// Stream executes a command and streams stdout and stderr in real-time.
func (r *Runtime) Stream(ctx context.Context, req ExecutionRequest, onStdout, onStderr func(string)) (*ExecutionResult, error) {
	if err := r.governor.CheckExecutionCapacity(); err != nil {
		return nil, err
	}

	r.governor.IncrementActiveProcess()
	defer r.governor.DecrementActiveProcess()

	return r.processManager.Stream(ctx, req, onStdout, onStderr)
}

// StartResearch initiates continuous autonomous research on the workspace target.
func (r *Runtime) StartResearch() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentState := r.lifecycle.GetState()
	if currentState != StateReady && currentState != StatePaused {
		return fmt.Errorf("cannot start research from state %s", currentState)
	}

	if err := r.lifecycle.TransitionTo(StateResearching, "Initiating autonomous research mission"); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.researchCancel = cancel

	targetURL := r.workspace.Config.Target

	// Run research engine in background goroutine
	go func() {
		engineCfg := coordinator.EngineConfig{
			TargetURL: targetURL,
			Budget:    r.governor.requestBudget,
		}
		engine := coordinator.NewAutonomousEngine(engineCfg)
		res, err := engine.Run(ctx)
		if err == nil && res != nil {
			r.mu.Lock()
			r.provenFindings = append(r.provenFindings, res.ProvenFindings...)
			r.proofBundles = append(r.proofBundles, res.ProofBundles...)
			r.mu.Unlock()

			r.broadcaster.Broadcast(EventFindingProven, "researcher",
				fmt.Sprintf("Autonomous research completed: %d findings proven", len(res.ProvenFindings)),
				map[string]any{"count": len(res.ProvenFindings)})
		}
		_ = r.lifecycle.TransitionTo(StateReady, "Autonomous research loop completed")
	}()

	return nil
}

// Pause suspends the active research loop.
func (r *Runtime) Pause() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.lifecycle.TransitionTo(StatePaused, "User requested pause"); err != nil {
		return err
	}
	if r.researchCancel != nil {
		r.researchCancel()
	}
	return nil
}

// Resume resumes suspended research.
func (r *Runtime) Resume() error {
	return r.StartResearch()
}

// Stop terminates all runtime processes and shuts down the IPC server.
func (r *Runtime) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.researchCancel != nil {
		r.researchCancel()
	}

	if r.ipcServer != nil {
		_ = r.ipcServer.Stop(context.Background())
	}

	if r.pipeServer != nil {
		_ = r.pipeServer.Stop()
	}

	return r.lifecycle.TransitionTo(StateStopped, "Runtime stopped")
}

// PipeServer returns the active Windows Named Pipe server.
func (r *Runtime) PipeServer() *PipeServer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pipeServer
}

// GetState returns current lifecycle state.
func (r *Runtime) GetState() LifecycleState {
	return r.lifecycle.GetState()
}

// GetEnvironment returns probed environment information.
func (r *Runtime) GetEnvironment() *Environment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.environment
}

// GetWorkspace returns active workspace details.
func (r *Runtime) GetWorkspace() *Workspace {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.workspace
}

// Governor returns the resource governor.
func (r *Runtime) Governor() *ResourceGovernor {
	return r.governor
}

// Broadcaster returns the event broadcaster.
func (r *Runtime) Broadcaster() *EventBroadcaster {
	return r.broadcaster
}

// GetWorldModelSnapshot returns the vertices and edges of W_t.
func (r *Runtime) GetWorldModelSnapshot() ([]*worldmodel.UnifiedVertex, []*worldmodel.UnifiedEdge) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.worldModel == nil {
		return nil, nil
	}
	return r.worldModel.AttackGraphView()
}

// GetFindings returns discovered findings and sealed proof bundles.
func (r *Runtime) GetFindings() ([]domain.ProvenFinding, []*report.ProofBundle) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	findings := make([]domain.ProvenFinding, len(r.provenFindings))
	copy(findings, r.provenFindings)
	bundles := make([]*report.ProofBundle, len(r.proofBundles))
	copy(bundles, r.proofBundles)
	return findings, bundles
}
