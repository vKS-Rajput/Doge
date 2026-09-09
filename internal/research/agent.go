package research

import (
	"context"
	"database/sql"
	"fmt"
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

// IterationReport provides structured visibility into a single cognitive iteration of the research agent.
type IterationReport struct {
	IterationNumber     int                               `json:"iteration_number"`
	State               LoopState                         `json:"state"`
	ObservedEntities    int                               `json:"observed_entities"`
	ObservedTotal       int                               `json:"observed_total"`
	ActiveHypotheses    []*hypothesis.ResearchHypothesis  `json:"active_hypotheses"`
	SelectedAction      *planner.ResearchAction           `json:"selected_action,omitempty"`
	EvaluationResult    *hypothesis.EvaluationResult      `json:"evaluation_result,omitempty"`
	PendingGate         *gates.Gate                       `json:"pending_gate,omitempty"`
	Message             string                            `json:"message"`
	ExecutionOutput     string                            `json:"execution_output,omitempty"`
	CompletedAt         time.Time                         `json:"completed_at"`
}

// ResearchAgent is the unified autonomous controller coordinating all intelligence, policy, and execution subsystems.
type ResearchAgent struct {
	mu             sync.RWMutex
	cfg            Config
	sessionID      uuid.UUID
	state          LoopState
	iteration      int
	scopeEngine    *scope.ScopeEngine
	runtimePolicy  *scope.RuntimePolicy
	hypEngine      *hypothesis.Engine
	gateMgr        *gates.Manager
	planner        *planner.Planner
	learner        *learning.Learner
	feedback       *learning.FeedbackEngine
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

// NewResearchAgent creates a new unified research agent.
func NewResearchAgent(
	cfg Config,
	scopeEngine *scope.ScopeEngine,
	gateMgr *gates.Manager,
	parserRegistry *parser.Registry,
	learner *learning.Learner,
	learningMemory *learning.Memory,
) *ResearchAgent {
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 50
	}
	if cfg.RateLimitPerSec <= 0 {
		cfg.RateLimitPerSec = 10
	}

	p := planner.NewPlanner(scopeEngine, cfg.Target, cfg.Environment)
	fb := learning.NewFeedbackEngine(learningMemory)
	p.SetFeedbackProvider(fb)

	policy := scope.NewRuntimePolicy(scopeEngine)
	hypEng := hypothesis.NewEngine()

	var initialEntities []domain.Entity
	var initialObservations []domain.Observation

	// Bootstrap existing entities and observations from workspace database if available
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

	return &ResearchAgent{
		cfg:            cfg,
		sessionID:      uuid.New(),
		state:          StateIdle,
		scopeEngine:    scopeEngine,
		runtimePolicy:  policy,
		hypEngine:      hypEng,
		gateMgr:        gateMgr,
		planner:        p,
		learner:        learner,
		feedback:       fb,
		learningMemory: learningMemory,
		parserRegistry: parserRegistry,
		entities:       initialEntities,
		observations:   initialObservations,
		auditLog:       make([]AuditEntry, 0),
		startedAt:      time.Now().UTC(),
		lastUpdatedAt:  time.Now().UTC(),
	}
}

// SetRunner overrides the command runner for mocking or custom execution backends.
func (a *ResearchAgent) SetRunner(fn CommandRunner) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.runnerFn = fn
}

// RunIteration executes one complete closed-loop cognitive cycle.
func (a *ResearchAgent) RunIteration(ctx context.Context) (*IterationReport, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	report := &IterationReport{
		IterationNumber:  a.iteration + 1,
		State:            a.state,
		ObservedEntities: len(a.entities),
		ObservedTotal:    len(a.observations),
		CompletedAt:      now,
	}

	if a.state == StateCompleted || a.state == StatePaused {
		report.Message = fmt.Sprintf("Agent is in terminal or paused state: %s", a.state)
		return report, nil
	}

	// 1. Check if currently blocked by a Human Gate
	if a.activeGateID != nil {
		gate, ok := a.gateMgr.GetGate(*a.activeGateID)
		if ok && gate.Status == gates.StatusPending {
			a.state = StateGated
			report.State = StateGated
			report.PendingGate = gate
			report.Message = fmt.Sprintf("Awaiting human decision on gate: %s", gate.Title)
			return report, nil
		}

		if ok && gate.Status == gates.StatusApproved {
			a.activeGateID = nil
			a.state = StateExecuting
		} else if ok && gate.Status == gates.StatusChosen {
			a.activeGateID = nil
			a.state = StatePlanning
		} else {
			a.activeGateID = nil
			a.state = StatePlanning
			report.State = StatePlanning
			report.Message = "Gate was rejected by researcher. Replanning next action..."
			return report, nil
		}
	}

	// 2. Check iteration budget
	if a.iteration >= a.cfg.MaxIterations {
		a.state = StateCompleted
		report.State = StateCompleted
		report.Message = fmt.Sprintf("Reached max iteration limit (%d)", a.cfg.MaxIterations)
		return report, nil
	}

	a.iteration++

	// 3. Epistemic Hypothesis Analysis
	_ = a.hypEngine.AnalyzeEvidence(ctx, a.entities, nil, a.observations)
	hyps := a.hypEngine.ListHypotheses()
	report.ActiveHypotheses = hyps

	// 4. Adapt & Score Research Plan with Information Gain
	_ = a.planner.AdaptPlan(a.entities, hyps)
	currentPlan := a.planner.GetPlan()

	if len(currentPlan.PlannedActions) == 0 {
		a.state = StateCompleted
		report.State = StateCompleted
		report.Message = "All planned actions executed. Investigation plan complete."
		return report, nil
	}

	// Pick top action ranked by Information Gain
	action := currentPlan.PlannedActions[0]
	report.SelectedAction = action

	// 5. Hard Scope & Runtime Policy Validation
	ticket, err := a.runtimePolicy.Acquire(ctx, action.Target, action.Tool, string(action.Phase))
	if err != nil {
		a.planner.MarkActionCompleted(action.ID, "skipped_policy_rejected")
		report.Message = fmt.Sprintf("Action skipped: %v", err)
		return report, nil
	}
	defer ticket.Release()

	// 6. Gate Check (Approval vs Auto-Execution)
	if action.RequiresApproval && !a.cfg.AllowAutoRecon {
		hypTitle := ""
		hypTier := ""
		hypConf := 0.0
		if action.HypothesisID != nil {
			if h, ok := a.hypEngine.GetHypothesis(*action.HypothesisID); ok {
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
			ScopeClassification: action.ScopeClassification,
			HypothesisID:        fmt.Sprintf("%v", action.HypothesisID),
			HypothesisTitle:     hypTitle,
			EpistemicTier:       hypTier,
			Confidence:          hypConf,
			Reason:              action.Reason,
		}

		g := a.gateMgr.CreateApprovalGate(
			fmt.Sprintf("Authorize %s on %s", action.Tool, action.Target),
			action.Reason,
			gateCtx,
		)
		a.activeGateID = &g.ID
		a.state = StateGated
		report.State = StateGated
		report.PendingGate = g
		report.Message = fmt.Sprintf("Approval required: %s", action.Reason)
		return report, nil
	}

	// 7. Execution
	a.state = StateExecuting
	cmdStr := fmt.Sprintf("%s %s", action.Tool, strings.Join(action.CommandArgs, " "))

	var runRes *runner.RunResult
	if a.runnerFn != nil {
		runRes = a.runnerFn(cmdStr, a.cfg.WorkspacePath, nil, nil)
	} else {
		runRes = runner.Run(cmdStr, a.cfg.WorkspacePath, nil, nil)
	}
	a.planner.MarkActionCompleted(action.ID, "completed")

	stdout := ""
	stderr := ""
	exitCode := 0
	if runRes != nil {
		stdout = runRes.Stdout
		stderr = runRes.Stderr
		exitCode = runRes.ExitCode
		report.ExecutionOutput = stdout
	}

	// 8. Parsing & Knowledge Graph Materialization
	if runRes != nil && len(strings.TrimSpace(stdout)) > 0 && a.parserRegistry != nil {
		artifact := domain.Artifact{
			ID:       uuid.New(),
			FileName: "stdout.txt",
			MIMEType: "text/plain",
		}
		header := []byte(stdout)
		if len(header) > 512 {
			header = header[:512]
		}
		p := a.parserRegistry.FindParser(artifact, header)
		if p != nil {
			rawObs, err := p.Parse(ctx, artifact, strings.NewReader(stdout))
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
				a.observations = append(a.observations, canonicalObs...)
				for _, o := range canonicalObs {
					ent := domain.Entity{
						ID:    uuid.New(),
						Type:  extractEntityType(o),
						Value: extractEntityValue(o),
					}
					if ent.Value != "" {
						a.entities = append(a.entities, ent)
					}
				}
				if a.learner != nil {
					_ = a.learner.LearnFromObservations(canonicalObs)
				}
			}
		}
	}

	// 9. Semantic Falsification & Evidence Evaluation
	var evalRes *hypothesis.EvaluationResult
	if action.HypothesisID != nil {
		if h, ok := a.hypEngine.GetHypothesis(*action.HypothesisID); ok {
			res := hypothesis.EvaluateExecution(h, stdout, stderr, exitCode)
			evalRes = &res
			report.EvaluationResult = evalRes

			// 10. Bidirectional Learning Feedback
			patName := string(h.Category)
			if evalRes.IsConfirmed || evalRes.NewStatus == hypothesis.StatusSupported {
				_ = a.feedback.RecordOutcome(a.sessionID, action.Tool, patName, true, 1, evalRes.Reason)
			} else if evalRes.IsFalsified || evalRes.NewStatus == hypothesis.StatusRejected {
				_ = a.feedback.RecordOutcome(a.sessionID, action.Tool, patName, false, 0, evalRes.Reason)
			}
		}
	}

	a.state = StatePlanning
	report.State = StatePlanning
	report.ObservedEntities = len(a.entities)
	report.ObservedTotal = len(a.observations)
	report.ActiveHypotheses = a.hypEngine.ListHypotheses()
	report.Message = fmt.Sprintf("Action %s on %s executed. Status: %s", action.Tool, action.Target, a.state)

	return report, nil
}

// IngestEvidence injects raw observations and entities into the agent's knowledge graph.
func (a *ResearchAgent) IngestEvidence(entities []domain.Entity, observations []domain.Observation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entities = append(a.entities, entities...)
	a.observations = append(a.observations, observations...)
}

// GetHypothesisEngine returns the hypothesis engine instance.
func (a *ResearchAgent) GetHypothesisEngine() *hypothesis.Engine {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.hypEngine
}

// GetPlanner returns the planner instance.
func (a *ResearchAgent) GetPlanner() *planner.Planner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.planner
}

// GetFeedbackEngine returns the feedback engine instance.
func (a *ResearchAgent) GetFeedbackEngine() *learning.FeedbackEngine {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.feedback
}
