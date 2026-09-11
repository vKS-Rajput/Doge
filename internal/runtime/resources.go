package runtime

import (
	"fmt"
	"sync"
	"time"
)

// ResourceUsage captures instantaneous runtime resource utilization.
type ResourceUsage struct {
	RequestsMade    int       `json:"requests_made"`
	RequestBudget   int       `json:"request_budget"`
	ActiveProcesses int       `json:"active_processes"`
	MaxProcesses    int       `json:"max_processes"`
	RateLimitPerSec int       `json:"rate_limit_per_sec"`
	LastRecordedAt  time.Time `json:"last_recorded_at"`
}

// ResourceGovernor enforces safety boundaries, request limits, and concurrency caps.
type ResourceGovernor struct {
	mu              sync.RWMutex
	requestBudget   int
	requestsMade    int
	maxProcesses    int
	activeProcesses int
	rateLimitPerSec int
	lastRequestTime time.Time
}

// NewResourceGovernor creates a resource governor.
func NewResourceGovernor(requestBudget, maxProcesses, ratePerSec int) *ResourceGovernor {
	if requestBudget <= 0 {
		requestBudget = 5000
	}
	if maxProcesses <= 0 {
		maxProcesses = 10
	}
	if ratePerSec <= 0 {
		ratePerSec = 20
	}
	return &ResourceGovernor{
		requestBudget:   requestBudget,
		maxProcesses:    maxProcesses,
		rateLimitPerSec: ratePerSec,
		lastRequestTime: time.Now().UTC(),
	}
}

// CheckExecutionCapacity verifies that starting a new process or mission does not exceed safety caps.
func (g *ResourceGovernor) CheckExecutionCapacity() error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.requestBudget > 0 && g.requestsMade >= g.requestBudget {
		return fmt.Errorf("request budget exhausted: %d/%d requests made", g.requestsMade, g.requestBudget)
	}

	if g.activeProcesses >= g.maxProcesses {
		return fmt.Errorf("maximum concurrent process limit reached: %d/%d active", g.activeProcesses, g.maxProcesses)
	}

	return nil
}

// RecordRequests increments the request counter and enforces the budget ceiling.
func (g *ResourceGovernor) RecordRequests(count int) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if count <= 0 {
		count = 1
	}

	if g.requestBudget > 0 && g.requestsMade+count > g.requestBudget {
		return fmt.Errorf("cannot issue %d requests: would exceed remaining budget of %d (used %d/%d)",
			count, g.requestBudget-g.requestsMade, g.requestsMade, g.requestBudget)
	}

	g.requestsMade += count
	g.lastRequestTime = time.Now().UTC()
	return nil
}

// IncrementActiveProcess tracks process creation.
func (g *ResourceGovernor) IncrementActiveProcess() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.activeProcesses++
}

// DecrementActiveProcess tracks process completion.
func (g *ResourceGovernor) DecrementActiveProcess() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.activeProcesses > 0 {
		g.activeProcesses--
	}
}

// Snapshot returns current resource metrics.
func (g *ResourceGovernor) Snapshot() ResourceUsage {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return ResourceUsage{
		RequestsMade:    g.requestsMade,
		RequestBudget:   g.requestBudget,
		ActiveProcesses: g.activeProcesses,
		MaxProcesses:    g.maxProcesses,
		RateLimitPerSec: g.rateLimitPerSec,
		LastRecordedAt:  g.lastRequestTime,
	}
}
