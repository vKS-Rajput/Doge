package strategy

import (
	"fmt"
	"net/url"
	"strings"
)

// ScopePolicy defines authorized execution limits for research strategies.
type ScopePolicy struct {
	AllowedHosts []string `json:"allowed_hosts"`
	MaxCost      float64  `json:"max_cost"` // max requests
	MaxRisk      float64  `json:"max_risk"` // 0.0 to 1.0
}

// TypeCheck verifies that a StrategyProgram complies with scope and safety constraints.
// Strategies that violate scope or exceed safety thresholds are rejected structurally.
func TypeCheck(prog *StrategyProgram, policy ScopePolicy) error {
	if prog == nil {
		return fmt.Errorf("typecheck error: nil strategy program")
	}

	if len(prog.Steps) == 0 {
		return fmt.Errorf("typecheck error: strategy %s has 0 steps", prog.ID)
	}

	// 1. Verify Risk Ceiling
	if prog.RiskScore > policy.MaxRisk {
		return fmt.Errorf("typecheck error: strategy risk %.2f exceeds maximum authorized risk ceiling %.2f",
			prog.RiskScore, policy.MaxRisk)
	}

	// 2. Verify Cost Ceiling
	totalCost := float64(prog.TotalRequests())
	if policy.MaxCost > 0 && totalCost > policy.MaxCost {
		return fmt.Errorf("typecheck error: strategy request cost %.0f exceeds budget %.0f",
			totalCost, policy.MaxCost)
	}

	// 3. Verify Step Ordering: Validation/Impact cannot occur without prior observation/probe
	hasObsOrProbe := false
	hasValidation := false

	for i, step := range prog.Steps {
		// Verify step target is within authorized scope
		if step.Target != "" {
			if err := verifyTargetScope(step.Target, policy.AllowedHosts); err != nil {
				return fmt.Errorf("typecheck error in step %d: %w", i, err)
			}
		}

		switch step.ActionType {
		case ActionRecon, ActionProbeProperty, ActionCausalIntervention:
			hasObsOrProbe = true
		case ActionIndependentValidation:
			if !hasObsOrProbe {
				return fmt.Errorf("typecheck error in step %d: validation cannot be executed without prior observation or causal probe", i)
			}
			hasValidation = true
		case ActionImpactDemonstration:
			if !hasValidation {
				return fmt.Errorf("typecheck error in step %d: impact demonstration forbidden without prior independent validation", i)
			}
		}
	}

	return nil
}

func verifyTargetScope(target string, allowedHosts []string) error {
	if len(allowedHosts) == 0 {
		return nil // open scope (e.g. test environment)
	}

	// Extract hostname
	host := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host = u.Host
		}
	}

	// Strip port for host comparison
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	matched := false
	for _, allowed := range allowedHosts {
		allowedClean := allowed
		if idx := strings.Index(allowedClean, ":"); idx != -1 {
			allowedClean = allowedClean[:idx]
		}
		if strings.EqualFold(host, allowedClean) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(allowedClean)) {
			matched = true
			break
		}
	}

	if !matched {
		return fmt.Errorf("target host %q is out of authorized scope %v", host, allowedHosts)
	}

	return nil
}
