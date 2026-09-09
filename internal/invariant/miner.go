package invariant

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/property"
)

// Miner inspects execution traces and automatically synthesizes candidate invariants.
type Miner struct {
	mu         sync.RWMutex
	traces     []ExecutionTrace
	invariants map[string]*Invariant // keyed by signature: Type + Subject
}

// NewMiner creates a new invariant miner.
func NewMiner() *Miner {
	return &Miner{
		traces:     make([]ExecutionTrace, 0),
		invariants: make(map[string]*Invariant),
	}
}

// AddTrace adds an observed execution trace and updates invariant hypotheses.
func (m *Miner) AddTrace(trace ExecutionTrace) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if trace.ID == uuid.Nil {
		trace.ID = uuid.New()
	}
	if trace.Timestamp.IsZero() {
		trace.Timestamp = time.Now().UTC()
	}
	m.traces = append(m.traces, trace)
}

// MineInvariants analyzes all collected traces and induces new candidate invariants.
func (m *Miner) MineInvariants() []*Invariant {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()

	// 1. Detect Batch / Pipelined Endpoints
	for _, trace := range m.traces {
		lowEndpoint := strings.ToLower(trace.Endpoint)
		hasBatchKeywords := strings.Contains(lowEndpoint, "batch") ||
			strings.Contains(lowEndpoint, "bulk") ||
			strings.Contains(lowEndpoint, "pipeline") ||
			len(trace.SubOperations) > 0

		if hasBatchKeywords {
			sigContext := fmt.Sprintf("%s:%s", InvariantContextIsolation, trace.Endpoint)
			if _, exists := m.invariants[sigContext]; !exists {
				m.invariants[sigContext] = &Invariant{
					ID:                   uuid.New(),
					Type:                 InvariantContextIsolation,
					Statement:            fmt.Sprintf("Sub-operations within %s execute strictly in their own identity context without session/pipeline bleed", trace.Endpoint),
					Subject:              trace.Endpoint,
					Precondition:         "Multiple sub-operations processed in a single batch frame",
					ObservedSupportCount: 1,
					Confidence:           0.70,
					State:                property.StateUntested,
					DiscoveredAt:         now,
					UpdatedAt:            now,
				}
			} else {
				m.invariants[sigContext].ObservedSupportCount++
				m.invariants[sigContext].Confidence = minFloat(0.95, m.invariants[sigContext].Confidence+0.05)
				m.invariants[sigContext].UpdatedAt = now
			}

			sigOrder := fmt.Sprintf("%s:%s", InvariantOrderCommutativity, trace.Endpoint)
			if _, exists := m.invariants[sigOrder]; !exists {
				m.invariants[sigOrder] = &Invariant{
					ID:                   uuid.New(),
					Type:                 InvariantOrderCommutativity,
					Statement:            fmt.Sprintf("Privilege of sub-operations in %s is independent of the execution order of preceding operations", trace.Endpoint),
					Subject:              trace.Endpoint,
					Precondition:         "Preceding operation executes with higher privilege than subsequent operation",
					ObservedSupportCount: 1,
					Confidence:           0.70,
					State:                property.StateUntested,
					DiscoveredAt:         now,
					UpdatedAt:            now,
				}
			}
		}

		// 2. Detect Identity Boundaries
		if trace.Principal != "" {
			sigIdent := fmt.Sprintf("%s:%s", InvariantIdentityBinding, trace.Endpoint)
			if _, exists := m.invariants[sigIdent]; !exists {
				m.invariants[sigIdent] = &Invariant{
					ID:                   uuid.New(),
					Type:                 InvariantIdentityBinding,
					Statement:            fmt.Sprintf("Requests to %s cannot access resources outside of %s's scope", trace.Endpoint, trace.Principal),
					Subject:              trace.Endpoint,
					Precondition:         fmt.Sprintf("Principal is %s", trace.Principal),
					ObservedSupportCount: 1,
					Confidence:           0.75,
					State:                property.StateUntested,
					DiscoveredAt:         now,
					UpdatedAt:            now,
				}
			}
		}
	}

	result := make([]*Invariant, 0, len(m.invariants))
	for _, inv := range m.invariants {
		result = append(result, inv)
	}
	return result
}

// GetInvariants returns all currently tracked invariants.
func (m *Miner) GetInvariants() []*Invariant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Invariant, 0, len(m.invariants))
	for _, inv := range m.invariants {
		result = append(result, inv)
	}
	return result
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
