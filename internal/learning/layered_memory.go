package learning

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// WorkingMemory contains the immediate, single-iteration cognitive state of the research agent.
type WorkingMemory struct {
	IterationIndex       int                            `json:"iteration_index"`
	ActiveHypothesis     *hypothesis.ResearchHypothesis `json:"active_hypothesis,omitempty"`
	ActiveActionID       uuid.UUID                      `json:"active_action_id,omitempty"`
	ActiveActionTitle    string                         `json:"active_action_title,omitempty"`
	ActiveTargetEndpoint string                         `json:"active_target_endpoint,omitempty"`
	LastExecutionStdout  string                         `json:"last_execution_stdout,omitempty"`
	LastExecutionStderr  string                         `json:"last_execution_stderr,omitempty"`
	LastExitCode         int                            `json:"last_exit_code"`
	PendingGaps          []*worldmodel.ResearchGap      `json:"pending_gaps,omitempty"`
	UpdatedAt            time.Time                      `json:"updated_at"`
}

// EpisodicMemoryEntry records a single completed step in the research trajectory.
type EpisodicMemoryEntry struct {
	ID               uuid.UUID                   `json:"id"`
	IterationIndex   int                         `json:"iteration_index"`
	ActionTitle      string                      `json:"action_title"`
	ActionType       string                      `json:"action_type"`
	TargetEndpoint   string                      `json:"target_endpoint"`
	HypothesisID     *uuid.UUID                  `json:"hypothesis_id,omitempty"`
	HypothesisTitle  string                      `json:"hypothesis_title,omitempty"`
	Productive       bool                        `json:"productive"`
	StatusTransition *hypothesis.EpistemicStatus `json:"status_transition,omitempty"`
	ConfidenceDelta  float64                     `json:"confidence_delta"`
	OutcomeReason    string                      `json:"outcome_reason"`
	RecordedAt       time.Time                   `json:"recorded_at"`
}

// SemanticMemory encapsulates the persistent grounded knowledge graph and verified facts.
type SemanticMemory struct {
	WorldModel       *worldmodel.WorldModel `json:"-"`
	VerifiedFindings []domain.Finding       `json:"verified_findings"`
	DiscoveredHosts  map[string]bool        `json:"discovered_hosts"`
	DiscoveredRoutes map[string]bool        `json:"discovered_routes"`
}

// ProceduralMemory retains learned tactical templates, tool heuristics, and failure signatures.
type ProceduralMemory struct {
	ToolEffectiveness map[string]float64           `json:"tool_effectiveness"`
	PatternWeights    map[string]float64           `json:"pattern_weights"`
	FailureSignatures map[string]*FailureSignature `json:"failure_signatures"`
}

// LayeredMemoryHierarchy coordinates all four cognitive memory tiers.
type LayeredMemoryHierarchy struct {
	mu         sync.RWMutex
	Working    *WorkingMemory
	Episodic   []*EpisodicMemoryEntry
	Semantic   *SemanticMemory
	Procedural *ProceduralMemory
	MemoryDB   *Memory
}

// NewLayeredMemoryHierarchy creates a clean 4-tier cognitive memory structure.
func NewLayeredMemoryHierarchy(wm *worldmodel.WorldModel, memDB *Memory) *LayeredMemoryHierarchy {
	return &LayeredMemoryHierarchy{
		Working: &WorkingMemory{
			UpdatedAt: time.Now().UTC(),
		},
		Episodic: make([]*EpisodicMemoryEntry, 0),
		Semantic: &SemanticMemory{
			WorldModel:       wm,
			VerifiedFindings: make([]domain.Finding, 0),
			DiscoveredHosts:  make(map[string]bool),
			DiscoveredRoutes: make(map[string]bool),
		},
		Procedural: &ProceduralMemory{
			ToolEffectiveness: make(map[string]float64),
			PatternWeights:    make(map[string]float64),
			FailureSignatures: make(map[string]*FailureSignature),
		},
		MemoryDB: memDB,
	}
}

// UpdateWorkingMemory updates the current iteration cognitive focus.
func (lm *LayeredMemoryHierarchy) UpdateWorkingMemory(
	iteration int,
	hyp *hypothesis.ResearchHypothesis,
	actionID uuid.UUID,
	actionTitle string,
	targetEndpoint string,
	gaps []*worldmodel.ResearchGap,
) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lm.Working.IterationIndex = iteration
	lm.Working.ActiveHypothesis = hyp
	lm.Working.ActiveActionID = actionID
	lm.Working.ActiveActionTitle = actionTitle
	lm.Working.ActiveTargetEndpoint = targetEndpoint
	lm.Working.PendingGaps = gaps
	lm.Working.UpdatedAt = time.Now().UTC()
}

// RecordStepExecution logs an execution step into Episodic memory and updates Procedural weights.
func (lm *LayeredMemoryHierarchy) RecordStepExecution(
	iteration int,
	actionTitle string,
	actionType string,
	targetEndpoint string,
	hyp *hypothesis.ResearchHypothesis,
	productive bool,
	statusTrans *hypothesis.EpistemicStatus,
	confDelta float64,
	outcomeReason string,
	stdout string,
	stderr string,
	exitCode int,
) *EpisodicMemoryEntry {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now().UTC()
	lm.Working.LastExecutionStdout = stdout
	lm.Working.LastExecutionStderr = stderr
	lm.Working.LastExitCode = exitCode
	lm.Working.UpdatedAt = now

	var hypID *uuid.UUID
	var hypTitle string
	if hyp != nil {
		id := hyp.ID
		hypID = &id
		hypTitle = hyp.Title
	}

	entry := &EpisodicMemoryEntry{
		ID:               uuid.New(),
		IterationIndex:   iteration,
		ActionTitle:      actionTitle,
		ActionType:       actionType,
		TargetEndpoint:   targetEndpoint,
		HypothesisID:     hypID,
		HypothesisTitle:  hypTitle,
		Productive:       productive,
		StatusTransition: statusTrans,
		ConfidenceDelta:  confDelta,
		OutcomeReason:    outcomeReason,
		RecordedAt:       now,
	}

	lm.Episodic = append(lm.Episodic, entry)

	// Update Procedural Weights
	normType := strings.ToLower(strings.TrimSpace(actionType))
	if productive {
		lm.Procedural.ToolEffectiveness[normType] += 0.3
		if lm.Procedural.ToolEffectiveness[normType] > 3.0 {
			lm.Procedural.ToolEffectiveness[normType] = 3.0
		}
	} else {
		lm.Procedural.ToolEffectiveness[normType] -= 0.4
		if lm.Procedural.ToolEffectiveness[normType] < -4.0 {
			lm.Procedural.ToolEffectiveness[normType] = -4.0
		}
	}

	return entry
}

// HasFailedActionSignature checks whether an equivalent action has previously failed on this surface.
func (lm *LayeredMemoryHierarchy) HasFailedActionSignature(actionType, targetEndpoint string) (*FailureSignature, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	sigKey := fmt.Sprintf("%s:%s", strings.ToLower(actionType), strings.ToLower(targetEndpoint))
	sig, exists := lm.Procedural.FailureSignatures[sigKey]
	return sig, exists
}

// RecordFailureSignature registers a failure pattern so the planner avoids repeating futile actions.
func (lm *LayeredMemoryHierarchy) RecordFailureSignature(sig *FailureSignature) {
	if sig == nil {
		return
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()

	sigKey := fmt.Sprintf("%s:%s", strings.ToLower(sig.ActionType), strings.ToLower(sig.TargetEndpoint))
	lm.Procedural.FailureSignatures[sigKey] = sig
}

// GetRecentEpisodicEntries returns the last N episodic memory steps.
func (lm *LayeredMemoryHierarchy) GetRecentEpisodicEntries(limit int) []*EpisodicMemoryEntry {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if len(lm.Episodic) <= limit {
		res := make([]*EpisodicMemoryEntry, len(lm.Episodic))
		copy(res, lm.Episodic)
		return res
	}

	start := len(lm.Episodic) - limit
	res := make([]*EpisodicMemoryEntry, limit)
	copy(res, lm.Episodic[start:])
	return res
}
