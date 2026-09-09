// Package director implements the Dual-Policy Research Director for DOGE Phase 2.
//
// In autonomous security research under partial observability, a system cannot
// rely solely on greedy exploitation of known hypotheses. The Director arbitrates
// between two distinct search policies:
//
// 1. Exploitation Policy (π_exploit):
//    "Given what I currently know, what promising path should I investigate next?"
//    Focuses on hypothesis testing, attack-graph path extension, independent
//    validation, and impact demonstration.
//
// 2. Discovery Policy (π_discover):
//    "What important thing could exist that my current world model doesn't even represent?"
//    Focuses on unknown-space exploration, metamorphic relation probing, dynamic
//    invariant induction, and behavioral novelty search.
package director

import (
	"sync"
)

// PolicyType identifies which search policy is active.
type PolicyType string

const (
	PolicyExploit  PolicyType = "exploit"
	PolicyDiscover PolicyType = "discover"
)

// PolicyStats tracks the yield and performance of each search policy.
type PolicyStats struct {
	Invocations   int `json:"invocations"`
	Novelties     int `json:"novelties"`
	FindingsFound int `json:"findings_found"`
}

// Director arbitrates research budget between exploitation and discovery.
type Director struct {
	mu           sync.RWMutex
	exploitRatio float64 // e.g. 0.65 = 65% exploit, 35% discover
	exploitStats PolicyStats
	discoverStats PolicyStats
	history      []PolicyType
}

// NewDirector creates a new research director with the given baseline exploitation ratio.
func NewDirector(exploitRatio float64) *Director {
	if exploitRatio <= 0.0 || exploitRatio >= 1.0 {
		exploitRatio = 0.65
	}
	return &Director{
		exploitRatio: exploitRatio,
		history:      make([]PolicyType, 0),
	}
}

// SelectPolicy chooses the next policy to drive mission generation.
// It balances the configured ratio while adapting if discovery yields new invariants.
func (d *Director) SelectPolicy() PolicyType {
	d.mu.Lock()
	defer d.mu.Unlock()

	total := len(d.history)
	if total == 0 {
		d.history = append(d.history, PolicyDiscover)
		d.discoverStats.Invocations++
		return PolicyDiscover
	}

	exploitCount := 0
	for _, p := range d.history {
		if p == PolicyExploit {
			exploitCount++
		}
	}

	currentRatio := float64(exploitCount) / float64(total)
	var chosen PolicyType

	if currentRatio < d.exploitRatio {
		chosen = PolicyExploit
		d.exploitStats.Invocations++
	} else {
		chosen = PolicyDiscover
		d.discoverStats.Invocations++
	}

	d.history = append(d.history, chosen)
	return chosen
}

// RecordOutcome updates policy performance statistics.
func (d *Director) RecordOutcome(policy PolicyType, foundNovelty, foundFinding bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch policy {
	case PolicyExploit:
		if foundNovelty {
			d.exploitStats.Novelties++
		}
		if foundFinding {
			d.exploitStats.FindingsFound++
		}
	case PolicyDiscover:
		if foundNovelty {
			d.discoverStats.Novelties++
			// When discovery is productive, temporarily give it more room
			d.exploitRatio = maxFloat(0.40, d.exploitRatio-0.05)
		}
		if foundFinding {
			d.discoverStats.FindingsFound++
		}
	}
}

// GetStats returns current performance stats.
func (d *Director) GetStats() (exploitStats, discoverStats PolicyStats, currentRatio float64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.exploitStats, d.discoverStats, d.exploitRatio
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
