package strategy

import (
	"fmt"
	"time"
)

// StepActionType defines the typed primitives available in the Research Strategy DSL.
type StepActionType string

const (
	ActionRecon                  StepActionType = "RECON_SURFACE"
	ActionProbeProperty          StepActionType = "PROBE_SECURITY_PROPERTY"
	ActionCausalIntervention     StepActionType = "CAUSAL_INTERVENTION_DO"
	ActionDifferentialComparison StepActionType = "DIFFERENTIAL_COMPARISON"
	ActionIndependentValidation  StepActionType = "INDEPENDENT_VALIDATION"
	ActionImpactDemonstration    StepActionType = "IMPACT_DEMONSTRATION"
)

// StrategyStep represents a single typed primitive operation within a research strategy.
type StrategyStep struct {
	Index       int            `json:"index"`
	ActionType  StepActionType `json:"action_type"`
	Target      string         `json:"target"`
	Parameters  map[string]any `json:"parameters"`
	Condition   string         `json:"condition"`
	MaxRequests int            `json:"max_requests"`
	TimeoutMs   int            `json:"timeout_ms"`
}

// StrategyProgram represents an entire research procedure as executable, auditable data.
type StrategyProgram struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	TargetDomain      string         `json:"target_domain"`
	Steps             []StrategyStep `json:"steps"`
	Preconditions     []string       `json:"preconditions"`
	Postconditions    []string       `json:"postconditions"`
	EstimatedCost     float64        `json:"estimated_cost"`      // in request count
	RiskScore         float64        `json:"risk_score"`          // 0.0 (safe) to 1.0 (destructive)
	EstimatedInfoGain float64        `json:"estimated_info_gain"`  // 0.0 to 1.0
	NoveltyScore      float64        `json:"novelty_score"`       // 0.0 to 1.0
	SuccessCount      int            `json:"success_count"`
	ExecutionCount    int            `json:"execution_count"`
	CreatedAt         time.Time      `json:"created_at"`
}

// TotalRequests returns the maximum upper bound of requests this strategy can issue.
func (p *StrategyProgram) TotalRequests() int {
	total := 0
	for _, s := range p.Steps {
		if s.MaxRequests > 0 {
			total += s.MaxRequests
		} else {
			total += 10
		}
	}
	return total
}

// FormatDSL produces a clean human-readable DSL representation of the research program.
func (p *StrategyProgram) FormatDSL() string {
	res := fmt.Sprintf("STRATEGY %s {\n", p.ID)
	res += fmt.Sprintf("  NAME: %q\n", p.Name)
	res += fmt.Sprintf("  TARGET: %s\n", p.TargetDomain)
	res += fmt.Sprintf("  METRICS: [Gain=%.2f, Novelty=%.2f, Risk=%.2f, Cost=%.0f]\n",
		p.EstimatedInfoGain, p.NoveltyScore, p.RiskScore, p.EstimatedCost)
	res += "  STEPS:\n"
	for _, step := range p.Steps {
		res += fmt.Sprintf("    %d: %s -> %s (max_req=%d, timeout=%dms)\n",
			step.Index, step.ActionType, step.Target, step.MaxRequests, step.TimeoutMs)
	}
	res += "}\n"
	return res
}
