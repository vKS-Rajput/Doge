package property

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Evaluator manages, evaluates, and prioritizes security properties.
// It is the bridge between the world model and the hypothesis engine.
type Evaluator struct {
	mu         sync.RWMutex
	properties map[uuid.UUID]*SecurityProperty
	bySubject  map[string][]*SecurityProperty
	byClass    map[PropertyClass][]*SecurityProperty
}

// NewEvaluator creates a new property evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		properties: make(map[uuid.UUID]*SecurityProperty),
		bySubject:  make(map[string][]*SecurityProperty),
		byClass:    make(map[PropertyClass][]*SecurityProperty),
	}
}

// Register adds a security property to the evaluator.
func (e *Evaluator) Register(p *SecurityProperty) {
	if p == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.State == "" {
		p.State = StateUnknown
	}

	e.properties[p.ID] = p
	e.bySubject[p.Subject] = append(e.bySubject[p.Subject], p)
	e.byClass[p.Class] = append(e.byClass[p.Class], p)
}

// Get returns a property by ID.
func (e *Evaluator) Get(id uuid.UUID) (*SecurityProperty, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.properties[id]
	return p, ok
}

// GetBySubject returns all properties for a given subject.
func (e *Evaluator) GetBySubject(subject string) []*SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bySubject[subject]
}

// GetByClass returns all properties of a given class.
func (e *Evaluator) GetByClass(class PropertyClass) []*SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.byClass[class]
}

// ListAll returns all registered properties.
func (e *Evaluator) ListAll() []*SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*SecurityProperty, 0, len(e.properties))
	for _, p := range e.properties {
		result = append(result, p)
	}
	return result
}

// ApplyResult applies a test result to the corresponding property.
func (e *Evaluator) ApplyResult(result PropertyTestResult) {
	e.mu.Lock()
	defer e.mu.Unlock()

	p, ok := e.properties[result.PropertyID]
	if !ok {
		return
	}
	p.ApplyTestResult(result)
}

// HighestGainUntested returns the untested/unknown property with
// the highest expected information gain. This drives mission generation.
func (e *Evaluator) HighestGainUntested() *SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var best *SecurityProperty
	bestGain := -1.0

	for _, p := range e.properties {
		if !p.IsTestable() {
			continue
		}
		gain := p.InformationGain()
		if gain > bestGain {
			bestGain = gain
			best = p
		}
	}
	return best
}

// RankedUntested returns all testable properties ranked by information gain (highest first).
func (e *Evaluator) RankedUntested() []*SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var testable []*SecurityProperty
	for _, p := range e.properties {
		if p.IsTestable() {
			testable = append(testable, p)
		}
	}

	// Sort by information gain (descending) — using insertion sort for simplicity
	for i := 1; i < len(testable); i++ {
		for j := i; j > 0 && testable[j].InformationGain() > testable[j-1].InformationGain(); j-- {
			testable[j], testable[j-1] = testable[j-1], testable[j]
		}
	}

	return testable
}

// Violated returns all properties that have been confirmed as violated.
func (e *Evaluator) Violated() []*SecurityProperty {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var violated []*SecurityProperty
	for _, p := range e.properties {
		if p.State == StateViolated || (p.State == StateContradicted && p.Confidence >= 0.8) {
			violated = append(violated, p)
		}
	}
	return violated
}

// CoverageReport generates a coverage summary across all property classes.
type CoverageReport struct {
	TotalProperties int                        `json:"total_properties"`
	TestedCount     int                        `json:"tested_count"`
	UntestedCount   int                        `json:"untested_count"`
	ViolatedCount   int                        `json:"violated_count"`
	CoveragePercent float64                    `json:"coverage_percent"`
	ByClass         map[PropertyClass]ClassCov `json:"by_class"`
}

// ClassCov is coverage for a single property class.
type ClassCov struct {
	Total    int     `json:"total"`
	Tested   int     `json:"tested"`
	Violated int     `json:"violated"`
	Coverage float64 `json:"coverage"`
}

// Coverage computes the current coverage report.
func (e *Evaluator) Coverage() CoverageReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := CoverageReport{
		ByClass: make(map[PropertyClass]ClassCov),
	}

	for _, p := range e.properties {
		report.TotalProperties++

		isTested := p.State != StateUnknown && p.State != StateAssumed && p.State != StateUntested
		isViolated := p.State == StateViolated || (p.State == StateContradicted && p.Confidence >= 0.8)

		if isTested {
			report.TestedCount++
		} else {
			report.UntestedCount++
		}
		if isViolated {
			report.ViolatedCount++
		}

		cc := report.ByClass[p.Class]
		cc.Total++
		if isTested {
			cc.Tested++
		}
		if isViolated {
			cc.Violated++
		}
		if cc.Total > 0 {
			cc.Coverage = float64(cc.Tested) / float64(cc.Total) * 100
		}
		report.ByClass[p.Class] = cc
	}

	if report.TotalProperties > 0 {
		report.CoveragePercent = float64(report.TestedCount) / float64(report.TotalProperties) * 100
	}

	return report
}

// GenerateFromEndpoints creates standard security properties for discovered endpoints.
// This is the bridge between world model discovery and property-based testing.
func (e *Evaluator) GenerateFromEndpoints(endpoints []string, principals []string) {
	now := time.Now().UTC()

	for _, ep := range endpoints {
		// Authorization property: each endpoint should require auth
		e.Register(&SecurityProperty{
			ID:          uuid.New(),
			Class:       ClassAuthorization,
			Statement:   "Only authorized principals can access " + ep,
			Subject:     ep,
			SubjectType: "endpoint",
			State:       StateUntested,
			Priority:    0.8,
			CreatedAt:   now,
			UpdatedAt:   now,
		})

		// Isolation property: each endpoint should enforce tenant isolation
		if len(principals) >= 2 {
			e.Register(&SecurityProperty{
				ID:          uuid.New(),
				Class:       ClassIsolation,
				Statement:   "Cross-principal access is denied on " + ep,
				Subject:     ep,
				SubjectType: "endpoint",
				State:       StateUntested,
				Priority:    0.9,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
	}
}

// GenerateWorkflowProperties creates properties for discovered workflows.
func (e *Evaluator) GenerateWorkflowProperties(workflowName string, states []string) {
	now := time.Now().UTC()

	// Core workflow integrity property
	e.Register(&SecurityProperty{
		ID:          uuid.New(),
		Class:       ClassWorkflowIntegrity,
		Statement:   "Workflow transitions in " + workflowName + " cannot be skipped",
		Subject:     workflowName,
		SubjectType: "workflow",
		State:       StateUntested,
		Priority:    1.0, // Highest priority — workflow bypass is critical
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	// Each state transition should be enforced
	for i := 0; i < len(states)-1; i++ {
		e.Register(&SecurityProperty{
			ID:          uuid.New(),
			Class:       ClassWorkflowIntegrity,
			Statement:   "State '" + states[i] + "' must be completed before '" + states[i+1] + "' in " + workflowName,
			Subject:     workflowName + ":" + states[i] + "->" + states[i+1],
			SubjectType: "state_transition",
			State:       StateUntested,
			Priority:    0.95,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	// Terminal state should not be reachable without all predecessors
	if len(states) >= 2 {
		terminal := states[len(states)-1]
		e.Register(&SecurityProperty{
			ID:          uuid.New(),
			Class:       ClassWorkflowIntegrity,
			Statement:   "Terminal state '" + terminal + "' requires all predecessor states in " + workflowName,
			Subject:     workflowName + ":" + terminal,
			SubjectType: "state_terminal",
			State:       StateUntested,
			Priority:    1.0,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}
}
