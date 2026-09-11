package strategy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// StrategySynthesizer generates and selects research strategies using multi-objective Pareto optimization.
type StrategySynthesizer struct {
	archive []*StrategyProgram
}

// NewStrategySynthesizer creates a new strategy synthesizer instance.
func NewStrategySynthesizer() *StrategySynthesizer {
	return &StrategySynthesizer{
		archive: make([]*StrategyProgram, 0),
	}
}

// RegisterInArchive adds a known or synthesized strategy into the archive.
func (s *StrategySynthesizer) RegisterInArchive(prog *StrategyProgram) {
	if prog != nil {
		s.archive = append(s.archive, prog)
	}
}

// SynthesizeStrategy creates a targeted research program for a target endpoint and behavioral dimension.
func (s *StrategySynthesizer) SynthesizeStrategy(targetURL, dimension string, isExploratory bool) *StrategyProgram {
	hasher := sha256.New()
	hasher.Write([]byte(targetURL + ":" + dimension))
	idHash := hex.EncodeToString(hasher.Sum(nil))[:8]

	id := "STRAT_" + dimension + "_" + idHash
	name := "Autonomous Research Procedure: " + dimension

	steps := make([]StrategyStep, 0)

	// Step 1: Recon & Surface Mapping
	steps = append(steps, StrategyStep{
		Index:       0,
		ActionType:  ActionRecon,
		Target:      targetURL,
		MaxRequests: 10,
		TimeoutMs:   5000,
	})

	// Step 2: Property / Metamorphic Probing
	steps = append(steps, StrategyStep{
		Index:       1,
		ActionType:  ActionProbeProperty,
		Target:      targetURL,
		Parameters:  map[string]any{"dimension": dimension},
		MaxRequests: 15,
		TimeoutMs:   10000,
	})

	// Step 3: Causal Intervention do(X)
	steps = append(steps, StrategyStep{
		Index:       2,
		ActionType:  ActionCausalIntervention,
		Target:      targetURL,
		Parameters:  map[string]any{"operator": "do(X)", "dimension": dimension},
		MaxRequests: 20,
		TimeoutMs:   15000,
	})

	// Step 4: Differential Negative Control
	steps = append(steps, StrategyStep{
		Index:       3,
		ActionType:  ActionDifferentialComparison,
		Target:      targetURL,
		Parameters:  map[string]any{"differential": true},
		MaxRequests: 10,
		TimeoutMs:   5000,
	})

	// Step 5: Independent Deterministic Validation
	steps = append(steps, StrategyStep{
		Index:       4,
		ActionType:  ActionIndependentValidation,
		Target:      targetURL,
		Parameters:  map[string]any{"independent_control": true},
		MaxRequests: 10,
		TimeoutMs:   10000,
	})

	// Step 6: Bounded Impact Demonstration
	steps = append(steps, StrategyStep{
		Index:       5,
		ActionType:  ActionImpactDemonstration,
		Target:      targetURL,
		Parameters:  map[string]any{"safe_demonstration": true},
		MaxRequests: 5,
		TimeoutMs:   5000,
	})

	infoGain := 0.85
	novelty := 0.90
	risk := 0.25
	if isExploratory {
		novelty = 0.95
		infoGain = 0.80
		risk = 0.20
	}

	prog := &StrategyProgram{
		ID:                id,
		Name:              name,
		Description:       "Grammar-composed research strategy targeting " + dimension,
		TargetDomain:      targetURL,
		Steps:             steps,
		Preconditions:     []string{"EndpointReachable", "PrincipalAuthenticated"},
		Postconditions:    []string{"ProvenFinding", "ConceptMinted"},
		EstimatedCost:     70, // 70 total requests
		RiskScore:         risk,
		EstimatedInfoGain: infoGain,
		NoveltyScore:      novelty,
		CreatedAt:         time.Now().UTC(),
	}

	s.archive = append(s.archive, prog)
	return prog
}

// ComputeParetoFrontier extracts the non-dominated set of strategies optimizing:
// Objectives: Maximize InfoGain, Maximize Novelty
// Costs: Minimize Cost, Minimize Risk
func (s *StrategySynthesizer) ComputeParetoFrontier() []*StrategyProgram {
	var frontier []*StrategyProgram

	for i, candidate := range s.archive {
		dominated := false
		for j, other := range s.archive {
			if i == j {
				continue
			}
			// other dominates candidate if:
			// other is >= in all gain metrics and <= in all cost metrics, and strictly better in at least one
			betterOrEqual := other.EstimatedInfoGain >= candidate.EstimatedInfoGain &&
				other.NoveltyScore >= candidate.NoveltyScore &&
				other.EstimatedCost <= candidate.EstimatedCost &&
				other.RiskScore <= candidate.RiskScore

			strictlyBetter := other.EstimatedInfoGain > candidate.EstimatedInfoGain ||
				other.NoveltyScore > candidate.NoveltyScore ||
				other.EstimatedCost < candidate.EstimatedCost ||
				other.RiskScore < candidate.RiskScore

			if betterOrEqual && strictlyBetter {
				dominated = true
				break
			}
		}
		if !dominated {
			frontier = append(frontier, candidate)
		}
	}

	// Deterministic sort: highest (InfoGain * Novelty) / (Risk * Cost) first
	sort.Slice(frontier, func(i, j int) bool {
		scoreI := (frontier[i].EstimatedInfoGain * frontier[i].NoveltyScore) /
			(frontier[i].RiskScore*frontier[i].EstimatedCost + 1e-5)
		scoreJ := (frontier[j].EstimatedInfoGain * frontier[j].NoveltyScore) /
			(frontier[j].RiskScore*frontier[j].EstimatedCost + 1e-5)
		return scoreI > scoreJ
	})

	return frontier
}

// SelectBestFromFrontier deterministic policy: selects the highest scoring program on the Pareto frontier.
func (s *StrategySynthesizer) SelectBestFromFrontier() *StrategyProgram {
	frontier := s.ComputeParetoFrontier()
	if len(frontier) == 0 {
		return nil
	}
	return frontier[0]
}
