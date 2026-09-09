package benchmark

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/research"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/internal/session"
)

// Runner orchestrates execution of adversarial benchmark suites.
type Runner struct{}

// NewRunner instantiates a benchmark runner.
func NewRunner() *Runner {
	return &Runner{}
}

// RunScenario executes a single adversarial benchmark scenario against the research agent.
func (r *Runner) RunScenario(ctx context.Context, scenario *BenchmarkScenario) (*ScenarioResult, error) {
	if scenario == nil {
		return nil, fmt.Errorf("cannot run nil scenario")
	}

	start := time.Now()

	// 1. Setup Scope
	scopeCfg := scope.Config{
		Target:      scenario.Target,
		Environment: "lab",
		InScope:     []string{scenario.Target, "*." + scenario.Target},
		Rules:       scope.DefaultProgramRules(),
	}
	scopeEng, err := scope.NewEngine(scopeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to init scope: %w", err)
	}

	gateMgr := gates.NewManager("")
	parserReg := parser.NewRegistry(nil)
	learner := learning.NewLearner(nil)

	maxIter := scenario.MaxAllowedIter
	if maxIter <= 0 {
		maxIter = 10
	}

	agentCfg := research.Config{
		Target:          scenario.Target,
		Environment:     "lab",
		MaxIterations:   maxIter,
		RateLimitPerSec: 100,
		AllowAutoRecon:  true,
	}

	agent := research.NewResearchAgent(
		agentCfg,
		scopeEng,
		gateMgr,
		parserReg,
		learner,
		nil,
	)

	// 2. Ingest Initial Synthetic Evidence
	agent.IngestEvidence(scenario.InitialEntities, scenario.InitialObservations)

	// 3. Configure Deterministic Simulated Execution Backend
	agent.SetRunner(func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult {
		res := &runner.RunResult{
			Command:   cmd,
			StartedAt: time.Now(),
		}

		matched := false
		for pattern, simResp := range scenario.SimulatedResponses {
			if strings.Contains(cmd, pattern) {
				res.ExitCode = simResp.ExitCode
				res.Stdout = simResp.Stdout
				res.Stderr = simResp.Stderr
				matched = true
				break
			}
		}

		if !matched {
			res.ExitCode = 0
			res.Stdout = "HTTP/1.1 200 OK\n\nDefault benchmark probe response"
		}

		return res
	})

	// 4. Run Iteration Loop
	recorder := session.NewTraceRecorder(uuid.New(), scenario.Target, session.ProfileStandard)
	groundTruthConfirmed := false
	distractorsFalsified := 0

	for i := 0; i < maxIter; i++ {
		rep, err := agent.RunIteration(ctx)
		if err != nil {
			break
		}

		if rep.State == research.StateCompleted {
			break
		}

		if rep.SelectedAction != nil {
			var deltas []session.HypothesisDelta
			if rep.EvaluationResult != nil && rep.SelectedAction.HypothesisID != nil {
				if h, ok := agent.GetHypothesisEngine().GetHypothesis(*rep.SelectedAction.HypothesisID); ok {
					deltas = append(deltas, session.HypothesisDelta{
						HypothesisID:    h.ID,
						HypothesisTitle: h.Title,
						OldStatus:       rep.EvaluationResult.PreviousStatus,
						NewStatus:       rep.EvaluationResult.NewStatus,
						OldConfidence:   rep.EvaluationResult.ConfidenceOld,
						NewConfidence:   rep.EvaluationResult.ConfidenceNew,
						Reason:          rep.EvaluationResult.Reason,
					})

					if rep.EvaluationResult.IsConfirmed || h.Status == hypothesis.StatusConfirmed {
						if h.Category == scenario.GroundTruth.Category {
							groundTruthConfirmed = true
						}
					}
					if rep.EvaluationResult.IsFalsified || h.Status == hypothesis.StatusRejected {
						distractorsFalsified++
					}
				}
			}

			recorder.RecordIteration(&session.IterationTraceEntry{
				IterationNumber:      rep.IterationNumber,
				ActionTitle:          rep.SelectedAction.Reason,
				Tool:                 rep.SelectedAction.Tool,
				TargetEndpoint:       rep.SelectedAction.Target,
				InformationGainScore: rep.SelectedAction.PriorityScore,
				PriorityReason:       rep.SelectedAction.Reason,
				ExecutionStdout:      rep.ExecutionOutput,
				HypothesisDeltas:     deltas,
				RecordedAt:           time.Now().UTC(),
			})
		}
	}

	trace := recorder.Finalize(1, "Scenario execution completed")
	duration := time.Since(start)

	passed := groundTruthConfirmed
	if len(scenario.Distractors) > 0 && distractorsFalsified == 0 && !groundTruthConfirmed {
		passed = false
	}

	return &ScenarioResult{
		ScenarioID:           scenario.ID,
		Title:                scenario.Title,
		Passed:               passed,
		GroundTruthFound:     groundTruthConfirmed,
		DistractorsFalsified: distractorsFalsified,
		TotalDistractors:     len(scenario.Distractors),
		IterationsUsed:       len(trace.Iterations),
		MaxAllowedIter:       maxIter,
		Duration:             duration,
		Trace:                trace,
		Notes:                fmt.Sprintf("Ground truth found: %v, Distractors refuted: %d/%d", groundTruthConfirmed, distractorsFalsified, len(scenario.Distractors)),
	}, nil
}

// RunSuite executes all scenarios in a benchmark suite and computes aggregate scorecard metrics.
func (r *Runner) RunSuite(ctx context.Context, suite []*BenchmarkScenario) (*BenchmarkScorecard, error) {
	if len(suite) == 0 {
		return nil, fmt.Errorf("cannot run empty benchmark suite")
	}

	scorecard := &BenchmarkScorecard{
		SuiteID:         uuid.New(),
		TotalScenarios:  len(suite),
		ScenarioResults: make([]*ScenarioResult, 0, len(suite)),
		EvaluatedAt:     time.Now().UTC(),
	}

	totalIter := 0
	for _, sc := range suite {
		res, err := r.RunScenario(ctx, sc)
		if err != nil {
			return nil, fmt.Errorf("failed executing scenario %s: %w", sc.ID, err)
		}

		scorecard.ScenarioResults = append(scorecard.ScenarioResults, res)
		scorecard.TotalDistractors += res.TotalDistractors
		scorecard.FalsifiedDistractors += res.DistractorsFalsified
		totalIter += res.IterationsUsed

		if res.Passed {
			scorecard.PassedScenarios++
		} else {
			scorecard.FailedScenarios++
		}
	}

	scorecard.PassRatePercent = (float64(scorecard.PassedScenarios) / float64(scorecard.TotalScenarios)) * 100.0
	if scorecard.TotalDistractors > 0 {
		scorecard.FalsificationRate = (float64(scorecard.FalsifiedDistractors) / float64(scorecard.TotalDistractors)) * 100.0
	} else {
		scorecard.FalsificationRate = 100.0
	}
	scorecard.AverageIterations = float64(totalIter) / float64(scorecard.TotalScenarios)

	return scorecard, nil
}
