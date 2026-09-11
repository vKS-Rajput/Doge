package transfer

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vKS-Rajput/doge/internal/strategy"
)

// AbstractExperience represents generalized, target-agnostic security research knowledge.
type AbstractExperience struct {
	ConceptID     string                   `json:"concept_id"`
	DimensionName string                   `json:"dimension_name"`
	AbstractGraph *AbstractRelationalGraph `json:"abstract_graph"`
	BaseStrategy  *strategy.StrategyProgram `json:"base_strategy"`
	SuccessCount  int                      `json:"success_count"`
	Confidence    float64                  `json:"confidence"`
	LearnedAt     time.Time                `json:"learned_at"`
}

// TransferEngine orchestrates cross-target strategy transfer and ensures sound independent validation.
type TransferEngine struct {
	mu          sync.RWMutex
	experiences map[string]*AbstractExperience
}

// NewTransferEngine creates a new cross-target transfer engine.
func NewTransferEngine() *TransferEngine {
	return &TransferEngine{
		experiences: make(map[string]*AbstractExperience),
	}
}

// StoreExperience saves an abstract experience learned from a successfully validated finding.
func (e *TransferEngine) StoreExperience(conceptID, dimension string, graph *AbstractRelationalGraph, prog *strategy.StrategyProgram) {
	if graph == nil || prog == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.experiences[conceptID] = &AbstractExperience{
		ConceptID:     conceptID,
		DimensionName: dimension,
		AbstractGraph: graph,
		BaseStrategy:  prog,
		SuccessCount:  1,
		Confidence:    0.90,
		LearnedAt:     time.Now().UTC(),
	}
}

// FindMatchingExperience searches for past experiences whose abstract graph is isomorphic to targetGraph.
func (e *TransferEngine) FindMatchingExperience(targetGraph *AbstractRelationalGraph, threshold float64) (*AbstractExperience, float64) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var bestExp *AbstractExperience
	bestScore := 0.0

	for _, exp := range e.experiences {
		score := IsomorphismScore(exp.AbstractGraph, targetGraph)
		if score >= threshold && score > bestScore {
			bestScore = score
			bestExp = exp
		}
	}
	return bestExp, bestScore
}

// TransferStrategy transposes a strategy program to Target B without transferring any target A URLs.
func (e *TransferEngine) TransferStrategy(
	exp *AbstractExperience,
	targetGraph *AbstractRelationalGraph,
	concreteEndpointMap map[string]string,
	targetBaseURL string,
) (*strategy.StrategyProgram, error) {
	if exp == nil || exp.BaseStrategy == nil {
		return nil, fmt.Errorf("transfer error: nil experience or base strategy")
	}

	binding := ExtractRoleBinding(exp.AbstractGraph, targetGraph)
	if len(binding) == 0 && len(concreteEndpointMap) == 0 {
		return nil, fmt.Errorf("transfer error: no valid structural binding between source and target graphs")
	}

	// Determine new primary target endpoint for target B
	newTarget := targetBaseURL
	for _, ep := range concreteEndpointMap {
		newTarget = ep
		break
	}

	transferredSteps := make([]strategy.StrategyStep, 0, len(exp.BaseStrategy.Steps))
	for _, step := range exp.BaseStrategy.Steps {
		stepCopy := step
		stepCopy.Target = newTarget

		// Clean parameters to ensure zero target-specific leakage
		paramsCopy := make(map[string]any)
		for k, v := range step.Parameters {
			// Do not copy any URL or host strings from source
			if strVal, ok := v.(string); ok && (strings.Contains(strVal, "http://") || strings.Contains(strVal, "https://")) {
				continue
			}
			paramsCopy[k] = v
		}
		paramsCopy["transferred_from_concept"] = exp.ConceptID
		stepCopy.Parameters = paramsCopy

		transferredSteps = append(transferredSteps, stepCopy)
	}

	transferredProg := &strategy.StrategyProgram{
		ID:                fmt.Sprintf("TRANSFER_%s_TO_%s", exp.DimensionName, targetGraph.TargetID),
		Name:              fmt.Sprintf("Transferred Research Strategy: %s", exp.DimensionName),
		Description:       fmt.Sprintf("Cross-target strategy transferred via G_A =~= G_B structural isomorphism from %s", exp.ConceptID),
		TargetDomain:      newTarget,
		Steps:             transferredSteps,
		Preconditions:     exp.BaseStrategy.Preconditions,
		Postconditions:    exp.BaseStrategy.Postconditions,
		EstimatedCost:     exp.BaseStrategy.EstimatedCost,
		RiskScore:         exp.BaseStrategy.RiskScore,
		EstimatedInfoGain: exp.BaseStrategy.EstimatedInfoGain * 0.95, // slight entropy discount
		NoveltyScore:      exp.BaseStrategy.NoveltyScore * 0.95,
		CreatedAt:         time.Now().UTC(),
	}

	return transferredProg, nil
}
