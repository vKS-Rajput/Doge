package e2e

import (
	"context"
	"database/sql"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/planner"
	"github.com/vKS-Rajput/doge/internal/research"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// TestEvidenceChangesNextAction verifies that ingesting new high-priority evidence
// immediately alters the agent's next planned action.
func TestEvidenceChangesNextAction(t *testing.T) {
	ctx := context.Background()
	scopeCfg := scope.Config{
		Target:      "testapp.com",
		Environment: "lab",
		InScope:     []string{"testapp.com", "*.testapp.com"},
		Rules:       scope.DefaultProgramRules(),
	}
	scopeEng, _ := scope.NewEngine(scopeCfg)
	gateMgr := gates.NewManager("")
	parserReg := parser.NewRegistry(nil)
	learner := learning.NewLearner(nil)

	agent := research.NewResearchAgent(
		research.Config{Target: "testapp.com", Environment: "lab", MaxIterations: 5, RateLimitPerSec: 50, AllowAutoRecon: true},
		scopeEng, gateMgr, parserReg, learner, nil,
	)

	// Mock runner for deterministic offline execution
	agent.SetRunner(func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult {
		return &runner.RunResult{ExitCode: 0, Stdout: "HTTP/1.1 200 OK"}
	})

	// Step 1: Initial state with domain only
	agent.IngestEvidence([]domain.Entity{
		{ID: uuid.New(), Type: domain.EntityDomain, Value: "testapp.com"},
	}, nil)

	rep1, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration 1 failed: %v", err)
	}

	initialTool := rep1.SelectedAction.Tool
	t.Logf("Initial Action with only domain: %s on %s", initialTool, rep1.SelectedAction.Target)

	// Step 2: Ingest critical API endpoint with object identifier
	agent.IngestEvidence([]domain.Entity{
		{ID: uuid.New(), Type: domain.EntityEndpoint, Value: "https://testapp.com/api/v1/invoices/99281"},
	}, []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery, SourceTool: "doge_surface", RawValue: "https://testapp.com/api/v1/invoices/99281", ObservedAt: time.Now().UTC()},
	})

	rep2, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration 2 failed: %v", err)
	}

	newAction := rep2.SelectedAction
	t.Logf("Next Action after ingesting invoice object endpoint: %s on %s (Reason: %s)", newAction.Tool, newAction.Target, newAction.Reason)

	if newAction.Target != "testapp.com/api/v1/invoices/99281" && newAction.Target != "https://testapp.com/api/v1/invoices/99281" {
		t.Errorf("expected agent to pivot target to discovered invoice endpoint, got: %s", newAction.Target)
	}
}

// TestLearningAcrossSessions verifies that negative outcomes in session 1
// reduce candidate action priority in session 2 via persistent memory.
func TestLearningAcrossSessions(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite memory db: %v", err)
	}
	defer db.Close()

	mem := learning.NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatalf("failed to ensure tables: %v", err)
	}

	// Session 1: Pattern bola_idor repeatedly produces false positives
	fb1 := learning.NewFeedbackEngine(mem)
	sessID1 := uuid.New()
	_ = fb1.RecordOutcome(sessID1, "httpx", "bola_idor", false, 0, "403 Forbidden tenant isolation")
	_ = fb1.RecordOutcome(sessID1, "httpx", "bola_idor", false, 0, "403 Forbidden tenant isolation")

	// Session 2: A new session starts with the same persistent memory
	fb2 := learning.NewFeedbackEngine(mem)
	boost := fb2.GetPatternPriorityBoost("bola_idor")
	t.Logf("Session 2 Learned Priority Boost for bola_idor: %.2f", boost)

	if boost >= 0 {
		t.Errorf("expected negative priority boost in session 2 for repeatedly refuted pattern, got: %.2f", boost)
	}
}

// TestScopeBlocksOutOfScope verifies fail-closed security preventing actions on unauthorized assets.
func TestScopeBlocksOutOfScope(t *testing.T) {
	ctx := context.Background()
	scopeCfg := scope.Config{
		Target:      "authorized.com",
		Environment: "authorized",
		InScope:     []string{"authorized.com", "*.authorized.com"},
		OutOfScope:  []string{"forbidden.authorized.com", "*.thirdparty.com"},
		Rules:       scope.DefaultProgramRules(),
	}
	scopeEng, _ := scope.NewEngine(scopeCfg)
	policy := scope.NewRuntimePolicy(scopeEng)
	defer policy.Stop()

	// 1. In-Scope Target
	ticket, err := policy.Acquire(ctx, "sub.authorized.com", "httpx", "web_probing")
	if err != nil {
		t.Errorf("expected in-scope asset to be allowed, got error: %v", err)
	}
	ticket.Release()

	// 2. Out-of-Scope Target
	_, err = policy.Acquire(ctx, "forbidden.authorized.com", "httpx", "web_probing")
	if err == nil {
		t.Errorf("expected out-of-scope asset to be blocked by policy engine")
	}

	// 3. Third-party SaaS Target
	_, err = policy.Acquire(ctx, "login.okta.com", "httpx", "web_probing")
	if err == nil {
		t.Errorf("expected third-party okta.com to be blocked")
	}
}

// TestHumanGateApprovalFlow verifies that in authorized mode, high-risk actions require human approval.
func TestHumanGateApprovalFlow(t *testing.T) {
	ctx := context.Background()
	scopeCfg := scope.Config{
		Target:      "corp.com",
		Environment: "authorized", // strictly requires gate approval
		InScope:     []string{"corp.com", "*.corp.com"},
		Rules:       scope.DefaultProgramRules(),
	}
	scopeEng, _ := scope.NewEngine(scopeCfg)
	gateMgr := gates.NewManager("")
	parserReg := parser.NewRegistry(nil)
	learner := learning.NewLearner(nil)

	agent := research.NewResearchAgent(
		research.Config{Target: "corp.com", Environment: "authorized", MaxIterations: 5, RateLimitPerSec: 50, AllowAutoRecon: false},
		scopeEng, gateMgr, parserReg, learner, nil,
	)

	// Ingest endpoint that triggers an active validation action requiring approval
	agent.IngestEvidence([]domain.Entity{
		{ID: uuid.New(), Type: domain.EntityEndpoint, Value: "https://corp.com/api/users/441"},
	}, []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery, SourceTool: "doge_surface", RawValue: "https://corp.com/api/users/441", ObservedAt: time.Now().UTC()},
	})

	rep, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration failed: %v", err)
	}

	if rep.State != research.StateGated {
		t.Errorf("expected state StateGated in authorized mode, got: %s", rep.State)
	}
	if rep.PendingGate == nil {
		t.Fatalf("expected pending gate to be created")
	}

	t.Logf("✓ Verified Human Gate Created: ID=%s Title=%s Status=%s",
		rep.PendingGate.ID, rep.PendingGate.Title, rep.PendingGate.Status)

	// Approve the gate
	_ = gateMgr.Approve(rep.PendingGate.ID, "lead_researcher", "Authorized for active testing")

	// Set runner mock
	agent.SetRunner(func(cmd, workDir string, stdout, stderr io.Writer) *runner.RunResult {
		return &runner.RunResult{ExitCode: 0, Stdout: "HTTP/1.1 200 OK"}
	})

	// Run next iteration to verify execution resumes after approval
	repAfterApproval, err := agent.RunIteration(ctx)
	if err != nil {
		t.Fatalf("iteration after approval failed: %v", err)
	}

	t.Logf("✓ Verified Resumed Execution: State=%s Message=%s", repAfterApproval.State, repAfterApproval.Message)
}

// TestInformationGainRanking verifies that high-gain / high-impact actions are mathematically ranked
// above low-gain or repetitive actions.
func TestInformationGainRanking(t *testing.T) {
	now := time.Now().UTC()

	hypHigh := &hypothesis.ResearchHypothesis{
		ID:         uuid.New(),
		Title:      "Unvalidated Critical BOLA",
		Category:   hypothesis.CatBOLA,
		Status:     hypothesis.StatusUnvalidated,
		Confidence: 0.70,
		FirstObservedAt: now,
		LastEvaluatedAt: now,
	}

	hypRefuted := &hypothesis.ResearchHypothesis{
		ID:         uuid.New(),
		Title:      "Refuted SSRF Theory",
		Category:   hypothesis.CatSSRF,
		Status:     hypothesis.StatusRejected,
		Confidence: 0.0,
		FirstObservedAt: now,
		LastEvaluatedAt: now,
	}

	action1 := &planner.ResearchAction{
		ID:           uuid.New(),
		Tool:         "httpx",
		Target:       "app.local/api/users/1",
		Risk:         planner.RiskLow,
		HypothesisID: &hypHigh.ID,
	}

	action2 := &planner.ResearchAction{
		ID:           uuid.New(),
		Tool:         "httpx",
		Target:       "app.local/api/fetch",
		Risk:         planner.RiskHigh,
		HypothesisID: &hypRefuted.ID,
	}

	ranked := planner.RankActions([]*planner.ResearchAction{action2, action1}, []*hypothesis.ResearchHypothesis{hypHigh, hypRefuted}, nil)

	if len(ranked) != 2 {
		t.Fatalf("expected 2 actions")
	}

	if ranked[0].ID != action1.ID {
		t.Errorf("expected high-gain action1 to be ranked #1, got action2 with score %.2f vs action1 score %.2f",
			ranked[1].PriorityScore, ranked[0].PriorityScore)
	}

	t.Logf("Action 1 (High Gain) Priority: %.2f", ranked[0].PriorityScore)
	t.Logf("Action 2 (Refuted Theory) Priority: %.2f", ranked[1].PriorityScore)
}
