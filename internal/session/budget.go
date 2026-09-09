package session

import (
	"fmt"
	"sync"
	"time"
)

// OperatingProfile classifies autonomous execution behavior, aggressiveness, and guardrails.
type OperatingProfile string

const (
	ProfileStealth  OperatingProfile = "stealth"
	ProfileStandard OperatingProfile = "standard"
	ProfileThorough OperatingProfile = "thorough"
)

// ResourceBudget defines upper bounds on research execution to prevent runaway resource consumption.
type ResourceBudget struct {
	MaxIterations     int           `json:"max_iterations"`
	MaxDuration       time.Duration `json:"max_duration"`
	MaxRequests       int           `json:"max_requests"`
	MaxCostUSD        float64       `json:"max_cost_usd"`
	MaxParallelProbes int           `json:"max_parallel_probes"`
	RateLimitPerSec   int           `json:"rate_limit_per_sec"`
}

// DefaultBudgetForProfile generates a tuned resource budget for a given operating profile.
func DefaultBudgetForProfile(profile OperatingProfile) ResourceBudget {
	switch profile {
	case ProfileStealth:
		return ResourceBudget{
			MaxIterations:     20,
			MaxDuration:       30 * time.Minute,
			MaxRequests:       100,
			MaxCostUSD:        5.0,
			MaxParallelProbes: 1,
			RateLimitPerSec:   2,
		}
	case ProfileThorough:
		return ResourceBudget{
			MaxIterations:     150,
			MaxDuration:       4 * time.Hour,
			MaxRequests:       5000,
			MaxCostUSD:        50.0,
			MaxParallelProbes: 8,
			RateLimitPerSec:   25,
		}
	case ProfileStandard:
		fallthrough
	default:
		return ResourceBudget{
			MaxIterations:     50,
			MaxDuration:       1 * time.Hour,
			MaxRequests:       1000,
			MaxCostUSD:        15.0,
			MaxParallelProbes: 4,
			RateLimitPerSec:   10,
		}
	}
}

// BudgetTracker monitors resource utilization in real-time during an active session.
type BudgetTracker struct {
	mu               sync.RWMutex
	Profile          OperatingProfile `json:"profile"`
	Budget           ResourceBudget   `json:"budget"`
	UsedIterations   int              `json:"used_iterations"`
	UsedRequests     int              `json:"used_requests"`
	UsedCostUSD      float64          `json:"used_cost_usd"`
	StartedAt        time.Time        `json:"started_at"`
	IsExhausted      bool             `json:"is_exhausted"`
	ExhaustionReason string           `json:"exhaustion_reason,omitempty"`
}

// NewBudgetTracker instantiates a real-time budget monitor.
func NewBudgetTracker(profile OperatingProfile, customBudget *ResourceBudget) *BudgetTracker {
	b := DefaultBudgetForProfile(profile)
	if customBudget != nil {
		b = *customBudget
	}

	return &BudgetTracker{
		Profile:   profile,
		Budget:    b,
		StartedAt: time.Now().UTC(),
	}
}

// ConsumeIteration increments iteration counter and checks against budget bounds.
func (bt *BudgetTracker) ConsumeIteration() error {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if bt.IsExhausted {
		return fmt.Errorf("budget exhausted: %s", bt.ExhaustionReason)
	}

	bt.UsedIterations++

	// Check iteration limit
	if bt.Budget.MaxIterations > 0 && bt.UsedIterations >= bt.Budget.MaxIterations {
		bt.IsExhausted = true
		bt.ExhaustionReason = fmt.Sprintf("Reached max iteration limit (%d/%d)", bt.UsedIterations, bt.Budget.MaxIterations)
		return fmt.Errorf("budget exhausted: %s", bt.ExhaustionReason)
	}

	// Check duration limit
	if bt.Budget.MaxDuration > 0 && time.Since(bt.StartedAt) >= bt.Budget.MaxDuration {
		bt.IsExhausted = true
		bt.ExhaustionReason = fmt.Sprintf("Reached max execution duration (%v)", bt.Budget.MaxDuration)
		return fmt.Errorf("budget exhausted: %s", bt.ExhaustionReason)
	}

	return nil
}

// RecordRequests increments HTTP/network request count and evaluates budget.
func (bt *BudgetTracker) RecordRequests(count int) error {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	bt.UsedRequests += count

	if bt.Budget.MaxRequests > 0 && bt.UsedRequests >= bt.Budget.MaxRequests {
		bt.IsExhausted = true
		bt.ExhaustionReason = fmt.Sprintf("Reached max request quota (%d/%d)", bt.UsedRequests, bt.Budget.MaxRequests)
		return fmt.Errorf("budget exhausted: %s", bt.ExhaustionReason)
	}

	return nil
}

// RecordCost adds cloud/LLM cost and evaluates financial budget.
func (bt *BudgetTracker) RecordCost(costUSD float64) error {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	bt.UsedCostUSD += costUSD

	if bt.Budget.MaxCostUSD > 0 && bt.UsedCostUSD >= bt.Budget.MaxCostUSD {
		bt.IsExhausted = true
		bt.ExhaustionReason = fmt.Sprintf("Reached max cost budget ($%.2f/$%.2f)", bt.UsedCostUSD, bt.Budget.MaxCostUSD)
		return fmt.Errorf("budget exhausted: %s", bt.ExhaustionReason)
	}

	return nil
}

// UtilizationPercent returns the maximum percentage consumed across all constrained dimensions (0.0 to 100.0).
func (bt *BudgetTracker) UtilizationPercent() float64 {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	var maxPct float64

	if bt.Budget.MaxIterations > 0 {
		pct := (float64(bt.UsedIterations) / float64(bt.Budget.MaxIterations)) * 100.0
		if pct > maxPct {
			maxPct = pct
		}
	}
	if bt.Budget.MaxDuration > 0 {
		pct := (float64(time.Since(bt.StartedAt)) / float64(bt.Budget.MaxDuration)) * 100.0
		if pct > maxPct {
			maxPct = pct
		}
	}
	if bt.Budget.MaxRequests > 0 {
		pct := (float64(bt.UsedRequests) / float64(bt.Budget.MaxRequests)) * 100.0
		if pct > maxPct {
			maxPct = pct
		}
	}
	if bt.Budget.MaxCostUSD > 0 {
		pct := (bt.UsedCostUSD / bt.Budget.MaxCostUSD) * 100.0
		if pct > maxPct {
			maxPct = pct
		}
	}

	return maxPct
}
