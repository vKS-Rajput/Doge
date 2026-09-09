package research

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/planner"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// CommandRunner defines the function signature for executing tools.
type CommandRunner func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult

// Config configures the autonomous research engine.
type Config struct {
	Target          string
	Environment     string
	WorkspacePath   string
	MaxIterations   int
	RateLimitPerSec int
	AllowAutoRecon  bool // true for HTB/Lab environments
}

// LoopEngine orchestrates the end-to-end autonomous research loop.
type LoopEngine struct {
	mu             sync.RWMutex
	cfg            Config
	sessionID      uuid.UUID
	state          LoopState
	iteration      int
	scopeEngine    *scope.ScopeEngine
	hypEngine      *hypothesis.Engine
	gateMgr        *gates.Manager
	planner        *planner.Planner
	learner        *learning.Learner
	learningMemory *learning.Memory
	parserRegistry *parser.Registry
	runnerFn       CommandRunner
	entities       []domain.Entity
	observations   []domain.Observation
	auditLog       []AuditEntry
	startedAt      time.Time
	lastUpdatedAt  time.Time
	activeGateID   *uuid.UUID
}

// SetRunner overrides the command runner for testing or custom execution.
func (e *LoopEngine) SetRunner(fn CommandRunner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runnerFn = fn
}

// NewLoopEngine creates a new autonomous research loop engine.
func NewLoopEngine(
	cfg Config,
	scopeEngine *scope.ScopeEngine,
	gateMgr *gates.Manager,
	parserRegistry *parser.Registry,
	learner *learning.Learner,
	learningMemory *learning.Memory,
) *LoopEngine {
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 50
	}
	if cfg.RateLimitPerSec <= 0 {
		cfg.RateLimitPerSec = 10
	}

	p := planner.NewPlanner(scopeEngine, cfg.Target, cfg.Environment)

	var initialEntities []domain.Entity
	var initialObservations []domain.Observation

	// Load existing entities and observations from workspace database if available
	if cfg.WorkspacePath != "" {
		dbPath := filepath.Join(cfg.WorkspacePath, ".doge", "workspace.db")
		if _, err := os.Stat(dbPath); err == nil {
			if dbConn, err := sql.Open("sqlite", dbPath); err == nil {
				defer dbConn.Close()
				rows, err := dbConn.Query("SELECT id, type, value FROM entities")
				if err == nil {
					for rows.Next() {
						var ent domain.Entity
						var idStr, entType, entVal string
						if err := rows.Scan(&idStr, &entType, &entVal); err == nil {
							ent.ID, _ = uuid.Parse(idStr)
							ent.Type = domain.EntityType(entType)
							ent.Value = entVal
							initialEntities = append(initialEntities, ent)
						}
					}
					rows.Close()
				}
				obsRows, err := dbConn.Query("SELECT id, type, source_tool, raw_value FROM observations")
				if err == nil {
					for obsRows.Next() {
						var obs domain.Observation
						var idStr, obsType, srcTool, rawVal string
						if err := obsRows.Scan(&idStr, &obsType, &srcTool, &rawVal); err == nil {
							obs.ID, _ = uuid.Parse(idStr)
							obs.Type = domain.ObservationType(obsType)
							obs.SourceTool = srcTool
							obs.RawValue = rawVal
							initialObservations = append(initialObservations, obs)
						}
					}
					obsRows.Close()
				}
			}
		}
	}

	hypEng := hypothesis.NewEngine()

	return &LoopEngine{
		cfg:            cfg,
		sessionID:      uuid.New(),
		state:          StateIdle,
		scopeEngine:    scopeEngine,
		hypEngine:      hypEng,
		gateMgr:        gateMgr,
		planner:        p,
		learner:        learner,
		learningMemory: learningMemory,
		parserRegistry: parserRegistry,
		entities:       initialEntities,
		observations:   initialObservations,
		auditLog:       make([]AuditEntry, 0),
		startedAt:      time.Now().UTC(),
		lastUpdatedAt:  time.Now().UTC(),
	}
}

// Step advances the autonomous research loop by one iteration.
func (e *LoopEngine) Step(ctx context.Context) (*StepResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	res := &StepResult{
		PreviousState: e.state,
	}

	if e.state == StateCompleted || e.state == StatePaused {
		res.CurrentState = e.state
		res.Message = fmt.Sprintf("Engine in terminal or paused state: %s", e.state)
		return res, nil
	}

	// 1. Check if currently blocked by a human Gate
	if e.activeGateID != nil {
		gate, ok := e.gateMgr.GetGate(*e.activeGateID)
		if ok && gate.Status == gates.StatusPending {
			e.state = StateGated
			res.CurrentState = StateGated
			res.PendingGate = gate
			res.Message = fmt.Sprintf("Awaiting decision on gate: %s", gate.Title)
			return res, nil
		}

		if ok && gate.Status == gates.StatusApproved {
			// Gate was approved by human; proceed to execute
			e.activeGateID = nil
			e.state = StateExecuting
		} else if ok && gate.Status == gates.StatusChosen {
			// Direction gate choice resolved
			e.activeGateID = nil
			e.state = StatePlanning
		} else {
			// Gate was rejected or expired; clear and replan
			e.activeGateID = nil
			e.state = StatePlanning
			res.CurrentState = StatePlanning
			res.Message = "Gate rejected by researcher, replanning..."
			return res, nil
		}
	}

	// 2. Check iteration budget
	if e.iteration >= e.cfg.MaxIterations {
		e.state = StateCompleted
		res.CurrentState = StateCompleted
		res.Message = fmt.Sprintf("Reached max iteration limit (%d)", e.cfg.MaxIterations)
		e.recordAudit(StateCompleted, "Max iterations reached", "", "", "OK", nil)
		_ = e.saveSessionLocked()
		return res, nil
	}

	e.iteration++

	// 3. Epistemic Hypothesis Analysis from current evidence
	newHyps := e.hypEngine.AnalyzeEvidence(ctx, e.entities, nil, e.observations)
	res.NewHypotheses = len(newHyps)
	res.NewObservations = len(e.observations)

	// 4. Adapt Research Plan based on current Knowledge Graph & Hypotheses
	hyps := e.hypEngine.ListHypotheses()
	_ = e.planner.AdaptPlan(e.entities, hyps)

	currentPlan := e.planner.GetPlan()
	if len(currentPlan.PlannedActions) == 0 {
		e.state = StateCompleted
		res.CurrentState = StateCompleted
		res.Message = "All planned actions executed. Research plan completed."
		_ = e.saveSessionLocked()
		return res, nil
	}

	// Pick next action to evaluate
	action := currentPlan.PlannedActions[0]

	// 5. Hard Scope Validation (Machine-Enforced Fail-Closed)
	cls, scopeReason := e.scopeEngine.ClassifyAsset(action.Target)
	if cls == scope.AssetOutOfScope || cls == scope.AssetUnknown {
		e.planner.MarkActionCompleted(action.ID, "skipped_out_of_scope")
		e.recordAudit(StatePlanning, "Action skipped out of scope", action.Target, action.Tool, string(cls), map[string]any{
			"reason": scopeReason,
		})
		res.CurrentState = e.state
		res.Message = fmt.Sprintf("Target %s is %s: %s (skipped)", action.Target, cls, scopeReason)
		return res, nil
	}

	// 6. Gate Check (Approval vs Auto-Execution)
	if action.RequiresApproval && !e.cfg.AllowAutoRecon {
		hypTitle := ""
		hypTier := ""
		hypConf := 0.0
		if action.HypothesisID != nil {
			if h, ok := e.hypEngine.GetHypothesis(*action.HypothesisID); ok {
				hypTitle = h.Title
				hypTier = string(h.Tier)
				hypConf = h.Confidence
			}
		}

		gateCtx := gates.GateContext{
			Target:              action.Target,
			Tool:                action.Tool,
			Command:             fmt.Sprintf("%s %s", action.Tool, strings.Join(action.CommandArgs, " ")),
			RiskLevel:           string(action.Risk),
			ScopeClassification: cls,
			ScopeReason:         scopeReason,
			HypothesisID:        fmt.Sprintf("%v", action.HypothesisID),
			HypothesisTitle:     hypTitle,
			EpistemicTier:       hypTier,
			Confidence:          hypConf,
			Reason:              action.Reason,
		}

		g := e.gateMgr.CreateApprovalGate(
			fmt.Sprintf("Authorize %s on %s", action.Tool, action.Target),
			action.Reason,
			gateCtx,
		)
		e.activeGateID = &g.ID
		e.state = StateGated
		res.CurrentState = StateGated
		res.PendingGate = g
		res.Message = fmt.Sprintf("Created approval gate for %s: %s", action.Tool, action.Reason)
		_ = e.saveSessionLocked()
		return res, nil
	}

	// 7. Execution & Evidence Observation
	e.state = StateExecuting
	res.ActionExecuted = action

	cmdStr := fmt.Sprintf("%s %s", action.Tool, strings.Join(action.CommandArgs, " "))
	e.recordAudit(StateExecuting, "Executing tool", action.Target, action.Tool, string(cls), map[string]any{
		"args": action.CommandArgs,
	})

	// Execute via runner
	var runRes *runner.RunResult
	if e.runnerFn != nil {
		runRes = e.runnerFn(cmdStr, e.cfg.WorkspacePath, nil, nil)
	} else {
		runRes = runner.Run(cmdStr, e.cfg.WorkspacePath, nil, nil)
	}
	e.planner.MarkActionCompleted(action.ID, "completed")

	// 8. Parsing & Knowledge Graph Materialization
	if runRes != nil && len(strings.TrimSpace(runRes.Stdout)) > 0 && e.parserRegistry != nil {
		artifact := domain.Artifact{
			ID:       uuid.New(),
			FileName: "stdout.txt",
			MIMEType: "text/plain",
		}
		header := []byte(runRes.Stdout)
		if len(header) > 512 {
			header = header[:512]
		}
		p := e.parserRegistry.FindParser(artifact, header)
		if p != nil {
			rawObs, err := p.Parse(ctx, artifact, strings.NewReader(runRes.Stdout))
			if err == nil && len(rawObs) > 0 {
				var canonicalObs []domain.Observation
				for _, ro := range rawObs {
					canonical := domain.Observation{
						ID:         uuid.New(),
						Type:       ro.Type,
						SourceTool: ro.SourceTool,
						Data:       ro.Data,
						RawValue:   ro.RawValue,
						ObservedAt: ro.ObservedAt,
					}
					if canonical.SourceTool == "" {
						canonical.SourceTool = action.Tool
					}
					canonicalObs = append(canonicalObs, canonical)
				}

				e.observations = append(e.observations, canonicalObs...)
				res.NewObservations = len(canonicalObs)

				// Materialize entities
				for _, o := range canonicalObs {
					ent := domain.Entity{
						ID:    uuid.New(),
						Type:  extractEntityType(o),
						Value: extractEntityValue(o),
					}
					if ent.Value != "" {
						e.entities = append(e.entities, ent)
					}
				}

				// Feed learning engine
				if e.learner != nil {
					_ = e.learner.LearnFromObservations(canonicalObs)
				}
			}
		}
	}

	// 9. Evaluate targeted hypotheses against criteria
	if action.HypothesisID != nil {
		if h, ok := e.hypEngine.GetHypothesis(*action.HypothesisID); ok {
			// Check if evidence confirmed or contradicted
			if runRes != nil && runRes.ExitCode == 0 && strings.Contains(runRes.Stdout, "200") {
				_ = e.hypEngine.UpdateHypothesisStatus(h.ID, hypothesis.StatusSupported, "Observed supporting HTTP 200 response")
			}
		}
	}

	e.state = StatePlanning
	res.CurrentState = StatePlanning
	res.Message = fmt.Sprintf("Action %s on %s executed successfully. Discovered %d observations, %d hypotheses.", action.Tool, action.Target, res.NewObservations, res.NewHypotheses)

	_ = e.saveSessionLocked()
	return res, nil
}

// GetSnapshot returns the current full state of the research session.
func (e *LoopEngine) GetSnapshot() *SessionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	plan := e.planner.GetPlan()
	pendingGates := e.gateMgr.ListPending()

	return &SessionSnapshot{
		SessionID:        e.sessionID,
		Target:           e.cfg.Target,
		Environment:      e.cfg.Environment,
		CurrentState:     e.state,
		CurrentPhase:     plan.CurrentPhase,
		Iteration:        e.iteration,
		EntityCount:      len(e.entities),
		ObservationCount: len(e.observations),
		Hypotheses:       e.hypEngine.ListHypotheses(),
		PendingGates:     pendingGates,
		CompletedActions: len(plan.CompletedActions),
		PlannedActions:   len(plan.PlannedActions),
		StartedAt:        e.startedAt,
		LastUpdatedAt:    time.Now().UTC(),
	}
}

// Pause pauses the autonomous research loop.
func (e *LoopEngine) Pause() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = StatePaused
	_ = e.saveSessionLocked()
}

// Resume resumes the autonomous research loop.
func (e *LoopEngine) Resume() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == StatePaused {
		e.state = StatePlanning
	}
	_ = e.saveSessionLocked()
}

func (e *LoopEngine) recordAudit(state LoopState, action, target, tool, scopeCheck string, details map[string]any) {
	e.auditLog = append(e.auditLog, AuditEntry{
		ID:         uuid.New(),
		Timestamp:  time.Now().UTC(),
		State:      state,
		Action:     action,
		Target:     target,
		Tool:       tool,
		Reason:     action,
		ScopeCheck: scopeCheck,
		Details:    details,
	})
}

func (e *LoopEngine) saveSessionLocked() error {
	if e.cfg.WorkspacePath == "" {
		return nil
	}
	dogeDir := filepath.Join(e.cfg.WorkspacePath, ".doge")
	if err := os.MkdirAll(dogeDir, 0755); err != nil {
		return err
	}

	snap := SessionSnapshot{
		SessionID:        e.sessionID,
		Target:           e.cfg.Target,
		Environment:      e.cfg.Environment,
		CurrentState:     e.state,
		Iteration:        e.iteration,
		EntityCount:      len(e.entities),
		ObservationCount: len(e.observations),
		Hypotheses:       e.hypEngine.ListHypotheses(),
		PendingGates:     e.gateMgr.ListPending(),
		StartedAt:        e.startedAt,
		LastUpdatedAt:    time.Now().UTC(),
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dogeDir, "research_session.json"), data, 0644)
}

func extractEntityType(obs domain.Observation) domain.EntityType {
	switch obs.Type {
	case domain.ObservationDNSLookup, domain.ObservationSubdomainDiscovery:
		return domain.EntitySubdomain
	case domain.ObservationPortScan:
		return domain.EntityService
	case domain.ObservationEndpointDiscovery:
		return domain.EntityEndpoint
	case domain.ObservationHTTPProbe:
		return domain.EntityURL
	case domain.ObservationTechnologyDetect:
		return domain.EntityTechnology
	default:
		return domain.EntityEndpoint
	}
}

func extractEntityValue(obs domain.Observation) string {
	if val, ok := obs.Data["host"].(string); ok && val != "" {
		return val
	}
	if val, ok := obs.Data["url"].(string); ok && val != "" {
		return val
	}
	if val, ok := obs.Data["path"].(string); ok && val != "" {
		return val
	}
	return obs.RawValue
}
