package learning

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/vKS-Rajput/doge/internal/strategy"
)

// StrategyEvaluation captures empirical performance metrics of an executed strategy.
type StrategyEvaluation struct {
	StrategyID          string    `json:"strategy_id"`
	Target              string    `json:"target"`
	FindingsCount       int       `json:"findings_count"`
	TotalRequestsIssued int       `json:"total_requests_issued"`
	ExecutionDurationMs int64     `json:"execution_duration_ms"`
	NoveltyYield        float64   `json:"novelty_yield"`
	CompletedAt         time.Time `json:"completed_at"`
}

// MetaLearner manages the meta-learning loop and Quality-Diversity (MAP-Elites) strategy archive.
type MetaLearner struct {
	mu           sync.RWMutex
	elites       map[string]*strategy.StrategyProgram // key: behavioral dimension
	actionCredit map[strategy.StepActionType]float64
	history      []StrategyEvaluation
}

// NewMetaLearner creates a new meta-learning engine.
func NewMetaLearner() *MetaLearner {
	return &MetaLearner{
		elites: make(map[string]*strategy.StrategyProgram),
		actionCredit: map[strategy.StepActionType]float64{
			strategy.ActionRecon:                  0.5,
			strategy.ActionProbeProperty:          0.6,
			strategy.ActionCausalIntervention:     0.8,
			strategy.ActionDifferentialComparison: 0.7,
			strategy.ActionIndependentValidation:  0.9,
			strategy.ActionImpactDemonstration:    0.95,
		},
		history: make([]StrategyEvaluation, 0),
	}
}

// RecordOutcome updates strategy statistics, credits successful actions, and updates the elite archive.
func (m *MetaLearner) RecordOutcome(prog *strategy.StrategyProgram, eval StrategyEvaluation) {
	if prog == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	prog.ExecutionCount++
	m.history = append(m.history, eval)

	if eval.FindingsCount > 0 {
		prog.SuccessCount += eval.FindingsCount

		// Temporal Difference Credit Assignment:
		// Steps in successful strategies receive reinforcement boost
		reward := float64(eval.FindingsCount) * 0.1
		for _, step := range prog.Steps {
			m.actionCredit[step.ActionType] += reward
		}

		// Update MAP-Elites Archive:
		// If this strategy outperforms the current incumbent for this target domain/dimension, retain it
		cellKey := prog.TargetDomain
		if len(prog.Steps) > 1 && prog.Steps[1].Parameters != nil {
			if dim, ok := prog.Steps[1].Parameters["dimension"].(string); ok {
				cellKey = dim
			}
		}

		incumbent, exists := m.elites[cellKey]
		if !exists || (float64(prog.SuccessCount)/float64(prog.ExecutionCount+1) >
			float64(incumbent.SuccessCount)/float64(incumbent.ExecutionCount+1)) {
			m.elites[cellKey] = prog
		}
	}
}

// GetActionCredit returns the learned credit weight for a given step primitive.
func (m *MetaLearner) GetActionCredit(action strategy.StepActionType) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.actionCredit[action]
}

// GetElite returns the highest-performing strategy for a given dimension cell.
func (m *MetaLearner) GetElite(dimension string) (*strategy.StrategyProgram, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	elite, ok := m.elites[dimension]
	return elite, ok
}

// RecombineStrategies combines high-performing components of two parent strategies into an offspring strategy.
func (m *MetaLearner) RecombineStrategies(parentA, parentB *strategy.StrategyProgram, targetURL string) *strategy.StrategyProgram {
	if parentA == nil || parentB == nil {
		if parentA != nil {
			return parentA
		}
		return parentB
	}

	m.mu.RLock()
	creditA := m.actionCredit
	m.mu.RUnlock()

	hasher := sha256.New()
	hasher.Write([]byte(parentA.ID + ":" + parentB.ID + ":" + targetURL))
	idHash := hex.EncodeToString(hasher.Sum(nil))[:8]

	mergedSteps := make([]strategy.StrategyStep, 0)
	stepMap := make(map[strategy.StepActionType]strategy.StrategyStep)

	// Collect steps from Parent A and Parent B, selecting higher-credit configurations
	allSteps := append(parentA.Steps, parentB.Steps...)
	for _, s := range allSteps {
		existing, ok := stepMap[s.ActionType]
		if !ok || creditA[s.ActionType] > creditA[existing.ActionType] {
			stepCopy := s
			stepCopy.Target = targetURL
			stepMap[s.ActionType] = stepCopy
		}
	}

	// Order steps canonically: Recon -> Probe -> Intervention -> Differential -> Validation -> Impact
	canonicalOrder := []strategy.StepActionType{
		strategy.ActionRecon,
		strategy.ActionProbeProperty,
		strategy.ActionCausalIntervention,
		strategy.ActionDifferentialComparison,
		strategy.ActionIndependentValidation,
		strategy.ActionImpactDemonstration,
	}

	idx := 0
	for _, act := range canonicalOrder {
		if step, ok := stepMap[act]; ok {
			step.Index = idx
			mergedSteps = append(mergedSteps, step)
			idx++
		}
	}

	offspring := &strategy.StrategyProgram{
		ID:                fmt.Sprintf("OFFSPRING_%s", idHash),
		Name:              fmt.Sprintf("Evolved Strategy (Recombination of %s & %s)", parentA.ID, parentB.ID),
		Description:       "Meta-learned composite research algorithm",
		TargetDomain:      targetURL,
		Steps:             mergedSteps,
		Preconditions:     parentA.Preconditions,
		Postconditions:    parentA.Postconditions,
		EstimatedCost:     (parentA.EstimatedCost + parentB.EstimatedCost) / 2.0,
		RiskScore:         (parentA.RiskScore + parentB.RiskScore) / 2.0,
		EstimatedInfoGain: (parentA.EstimatedInfoGain + parentB.EstimatedInfoGain) * 0.52, // slight synergy gain
		NoveltyScore:      (parentA.NoveltyScore + parentB.NoveltyScore) * 0.52,
		CreatedAt:         time.Now().UTC(),
	}

	return offspring
}
