// Package contradiction implements the First-Class Contradiction Engine for DOGE.
//
// When observation A and observation B contradict each other (e.g. User A cannot access
// resource X in state S1, but accesses resource X in state S2), DOGE does not overwrite
// observation A. Instead, it creates a first-class Contradiction object and systematically
// evaluates candidate explanations: state differences, caching artifacts, authorization
// inconsistencies, race conditions, identity mismatches, or hidden conditions.
package contradiction

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ExplanationCategory classifies the theoretical mechanism explaining a contradiction.
type ExplanationCategory string

const (
	ExplainStateDifference        ExplanationCategory = "state_difference"
	ExplainCacheArtifact          ExplanationCategory = "cache_artifact"
	ExplainAuthInconsistency      ExplanationCategory = "authorization_inconsistency"
	ExplainRaceCondition          ExplanationCategory = "race_condition"
	ExplainIdentityMismatch       ExplanationCategory = "identity_mismatch"
	ExplainHiddenCondition        ExplanationCategory = "hidden_condition"
	ExplainUnknownMechanism       ExplanationCategory = "unknown_mechanism"
)

// ExplanationCandidate represents a hypothesized resolution for an observed contradiction.
type ExplanationCandidate struct {
	Category    ExplanationCategory `json:"category"`
	Hypothesis  string              `json:"hypothesis"`
	Confidence  float64             `json:"confidence"`
	TestCommand string              `json:"test_command,omitempty"`
}

// Status tracks the resolution lifecycle of a contradiction.
type Status string

const (
	StatusOpen          Status = "OPEN"
	StatusInvestigating Status = "INVESTIGATING"
	StatusResolved      Status = "RESOLVED"
	StatusFalsified     Status = "FALSIFIED"
)

// Contradiction models an unexplained conflict between two or more verified observations.
type Contradiction struct {
	ID                  uuid.UUID              `json:"id"`
	Title               string                 `json:"title"`
	Resource            string                 `json:"resource"`
	ObservationA        domain.ExperimentEvidence `json:"observation_a"`
	ObservationB        domain.ExperimentEvidence `json:"observation_b"`
	Discrepancy         string                 `json:"discrepancy"`
	CandidateExplanations []ExplanationCandidate `json:"candidate_explanations"`
	ResolvedCategory    *ExplanationCategory   `json:"resolved_category,omitempty"`
	ResolvedNotes       string                 `json:"resolved_notes,omitempty"`
	Status              Status                 `json:"status"`
	DetectedAt          time.Time              `json:"detected_at"`
	ResolvedAt          *time.Time             `json:"resolved_at,omitempty"`
}

// Engine maintains and evaluates active contradictions in the world model.
type Engine struct {
	mu             sync.RWMutex
	contradictions map[uuid.UUID]*Contradiction
	resourceIndex  map[string][]*Contradiction
}

// NewEngine creates a new contradiction detection and reasoning engine.
func NewEngine() *Engine {
	return &Engine{
		contradictions: make(map[uuid.UUID]*Contradiction),
		resourceIndex:  make(map[string][]*Contradiction),
	}
}

// IngestAndDetect evaluates a newly captured observation against historical evidence
// to identify emerging contradictions.
func (e *Engine) IngestAndDetect(newEv domain.ExperimentEvidence, history []domain.ExperimentEvidence) []*Contradiction {
	e.mu.Lock()
	defer e.mu.Unlock()

	var detected []*Contradiction

	for _, prev := range history {
		if prev.ID == newEv.ID {
			continue
		}

		// Check if they target the same endpoint/resource
		if prev.RequestURL != newEv.RequestURL || prev.RequestURL == "" {
			continue
		}

		// Pattern 1: Status Code Contradiction (e.g. 403 Forbidden vs 200 OK)
		isStatusConflict := (prev.ResponseStatus == 200 && (newEv.ResponseStatus == 401 || newEv.ResponseStatus == 403)) ||
			(newEv.ResponseStatus == 200 && (prev.ResponseStatus == 401 || prev.ResponseStatus == 403))

		// Pattern 2: Latency Divergence Contradiction (>10x divergence on identical queries)
		isLatencyConflict := false
		if prev.ResponseStatus == newEv.ResponseStatus && prev.ResponseTimeMs > 0 && newEv.ResponseTimeMs > 0 {
			ratio := float64(prev.ResponseTimeMs) / float64(newEv.ResponseTimeMs)
			if ratio > 8.0 || ratio < 0.125 {
				isLatencyConflict = true
			}
		}

		// Pattern 3: Payload Length Collapse / Bleed Contradiction
		isPayloadConflict := false
		if prev.ResponseStatus == 200 && newEv.ResponseStatus == 200 {
			lenA := len(prev.ResponseBody)
			lenB := len(newEv.ResponseBody)
			if (lenA > 1000 && lenB < 100) || (lenB > 1000 && lenA < 100) {
				isPayloadConflict = true
			}
		}

		if isStatusConflict || isLatencyConflict || isPayloadConflict {
			c := e.buildContradiction(prev, newEv, isStatusConflict, isLatencyConflict, isPayloadConflict)
			if c != nil {
				e.contradictions[c.ID] = c
				e.resourceIndex[c.Resource] = append(e.resourceIndex[c.Resource], c)
				detected = append(detected, c)
			}
		}
	}

	return detected
}

func (e *Engine) buildContradiction(evA, evB domain.ExperimentEvidence, statusConflict, latencyConflict, payloadConflict bool) *Contradiction {
	cID := uuid.New()
	resource := evA.RequestURL

	var discrepancy string
	var candidates []ExplanationCandidate

	if statusConflict {
		discrepancy = fmt.Sprintf("HTTP Status Conflict: Evidence A returned %d, while Evidence B returned %d on %s",
			evA.ResponseStatus, evB.ResponseStatus, resource)

		candidates = []ExplanationCandidate{
			{
				Category:    ExplainAuthInconsistency,
				Hypothesis:  "Authorization middleware inconsistently enforces identity binding across request parameters or routes.",
				Confidence:  0.80,
				TestCommand: fmt.Sprintf("Issue replay with alternating credentials against %s", resource),
			},
			{
				Category:    ExplainStateDifference,
				Hypothesis:  "An unmodeled intermediate state transition occurred between observations.",
				Confidence:  0.70,
			},
			{
				Category:    ExplainCacheArtifact,
				Hypothesis:  "A reverse proxy cached an earlier unauthenticated response or poisoned header.",
				Confidence:  0.65,
			},
			{
				Category:    ExplainRaceCondition,
				Hypothesis:  "Concurrent execution frame or asynchronous job modified permissions temporarily.",
				Confidence:  0.60,
			},
		}
	} else if latencyConflict {
		discrepancy = fmt.Sprintf("Latency Divergence Conflict: Evidence A took %dms, while Evidence B took %dms on %s",
			evA.ResponseTimeMs, evB.ResponseTimeMs, resource)

		candidates = []ExplanationCandidate{
			{
				Category:    ExplainHiddenCondition,
				Hypothesis:  "A backend blind timing oracle or expensive SQL execution occurred conditionally.",
				Confidence:  0.85,
			},
			{
				Category:    ExplainCacheArtifact,
				Hypothesis:  "Cache HIT versus origin backend MISS divergence.",
				Confidence:  0.75,
			},
		}
	} else if payloadConflict {
		discrepancy = fmt.Sprintf("Payload Size Conflict: Evidence A returned %d bytes, while Evidence B returned %d bytes on %s",
			len(evA.ResponseBody), len(evB.ResponseBody), resource)

		candidates = []ExplanationCandidate{
			{
				Category:    ExplainIdentityMismatch,
				Hypothesis:  "Session tenant context bled into response or leaked unredacted data.",
				Confidence:  0.80,
			},
			{
				Category:    ExplainStateDifference,
				Hypothesis:  "Resource was modified, emptied, or populated by external state transition.",
				Confidence:  0.70,
			},
		}
	}

	return &Contradiction{
		ID:                    cID,
		Title:                 fmt.Sprintf("Contradiction on %s", resource),
		Resource:              resource,
		ObservationA:          evA,
		ObservationB:          evB,
		Discrepancy:           discrepancy,
		CandidateExplanations: candidates,
		Status:                StatusOpen,
		DetectedAt:            time.Now().UTC(),
	}
}

// ConvertToHypotheses translates a detected contradiction into concrete research hypotheses
// for insertion into the research frontier.
func (e *Engine) ConvertToHypotheses(c *Contradiction) []*hypothesis.ResearchHypothesis {
	now := time.Now().UTC()
	var hypotheses []*hypothesis.ResearchHypothesis

	for _, cand := range c.CandidateExplanations {
		cat := hypothesis.CatNovelAnomaly
		if cand.Category == ExplainAuthInconsistency {
			cat = hypothesis.CatAuthBoundary
		}

		h := &hypothesis.ResearchHypothesis{
			ID:                   uuid.New(),
			Title:                fmt.Sprintf("Contradiction Resolution [%s]: %s", cand.Category, c.Resource),
			Statement:            cand.Hypothesis,
			Target:               c.Resource,
			Tier:                 hypothesis.TierHypothesis,
			Status:               hypothesis.StatusUnvalidated,
			Category:             cat,
			Confidence:           cand.Confidence,
			ConfirmationCriteria: fmt.Sprintf("Observation confirms explanation: %s", cand.Hypothesis),
			RefutationCriteria:   fmt.Sprintf("Observation refutes explanation: %s", cand.Hypothesis),
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}
		hypotheses = append(hypotheses, h)
	}

	return hypotheses
}

// Resolve marks a contradiction as resolved with a verified explanation.
func (e *Engine) Resolve(contradictionID uuid.UUID, category ExplanationCategory, notes string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	c, ok := e.contradictions[contradictionID]
	if !ok {
		return fmt.Errorf("contradiction %s not found", contradictionID)
	}

	now := time.Now().UTC()
	c.ResolvedCategory = &category
	c.ResolvedNotes = notes
	c.Status = StatusResolved
	c.ResolvedAt = &now

	return nil
}

// GetOpen returns all currently unresolved contradictions.
func (e *Engine) GetOpen() []*Contradiction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var open []*Contradiction
	for _, c := range e.contradictions {
		if c.Status == StatusOpen || c.Status == StatusInvestigating {
			open = append(open, c)
		}
	}
	return open
}

// Count returns the total number of tracked contradictions.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.contradictions)
}
