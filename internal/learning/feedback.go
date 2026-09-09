package learning

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FeedbackEngine provides bidirectional learning feedback into the research planner.
type FeedbackEngine struct {
	mu           sync.RWMutex
	memory       *Memory
	inMemoryTool map[string]float64
	inMemoryPats map[string]float64
}

// NewFeedbackEngine creates a new feedback engine backed by Learning Memory.
func NewFeedbackEngine(memory *Memory) *FeedbackEngine {
	return &FeedbackEngine{
		memory:       memory,
		inMemoryTool: make(map[string]float64),
		inMemoryPats: make(map[string]float64),
	}
}

// GetPatternPriorityBoost returns the priority adjustment for a given pattern.
// Positive values boost priority; negative values penalize unproductive patterns.
func (f *FeedbackEngine) GetPatternPriorityBoost(patternName string) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	norm := strings.ToLower(strings.TrimSpace(patternName))
	if boost, ok := f.inMemoryPats[norm]; ok {
		return boost
	}

	if f.memory == nil {
		return 0.0
	}

	pattern, err := f.memory.GetPattern(norm)
	if err != nil || pattern == nil {
		return 0.0
	}

	return pattern.PriorityBoost
}

// GetToolEffectiveness returns the historical productivity boost/penalty for a tool.
func (f *FeedbackEngine) GetToolEffectiveness(tool string) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	norm := strings.ToLower(strings.TrimSpace(tool))
	if eff, ok := f.inMemoryTool[norm]; ok {
		return eff
	}

	return 0.0
}

// RecordOutcome records the real outcome of an action/hypothesis test.
func (f *FeedbackEngine) RecordOutcome(
	investigationID uuid.UUID,
	tool string,
	patternName string,
	productive bool,
	findingsProduced int,
	notes string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	normTool := strings.ToLower(strings.TrimSpace(tool))
	normPat := strings.ToLower(strings.TrimSpace(patternName))
	now := time.Now().UTC()

	// Update tool effectiveness in-memory
	if productive {
		f.inMemoryTool[normTool] += 0.25
		if f.inMemoryTool[normTool] > 2.0 {
			f.inMemoryTool[normTool] = 2.0
		}
	} else {
		f.inMemoryTool[normTool] -= 0.35
		if f.inMemoryTool[normTool] < -3.0 {
			f.inMemoryTool[normTool] = -3.0
		}
	}

	// Update pattern boost in-memory and in persistent storage
	if normPat != "" {
		if productive {
			f.inMemoryPats[normPat] += 0.50
			if f.inMemoryPats[normPat] > 3.0 {
				f.inMemoryPats[normPat] = 3.0
			}
		} else {
			f.inMemoryPats[normPat] -= 0.60
			if f.inMemoryPats[normPat] < -4.0 {
				f.inMemoryPats[normPat] = -4.0
			}
		}

		if f.memory != nil {
			pat, err := f.memory.GetPattern(normPat)
			if err == nil && pat != nil {
				if productive {
					pat.PriorityBoost += 0.3
					pat.Confidence += 0.1
				} else {
					pat.PriorityBoost -= 0.4
					pat.Confidence -= 0.15
					if pat.Confidence < 0.0 {
						pat.Confidence = 0.0
					}
				}
				pat.LastSeen = now
				_ = f.memory.StorePattern(pat)

				_ = f.memory.RecordOutcome(&ResearchOutcome{
					ID:                  uuid.New(),
					PatternID:           pat.ID,
					InvestigationID:     investigationID,
					Productive:          productive,
					FindingsProduced:    findingsProduced,
					ObservationsProduced: 1,
					Notes:               notes,
					RecordedAt:          now,
				})
			} else {
				// Create new pattern with outcome
				newPat := &ResearchPattern{
					ID:            uuid.New(),
					Name:          normPat,
					Description:   notes,
					Category:      PatternAuthz,
					Confidence:    0.2,
					Occurrences:   1,
					PriorityBoost: -0.4,
					FirstSeen:     now,
					LastSeen:      now,
					DecayFactor:   1.0,
				}
				if productive {
					newPat.Confidence = 0.6
					newPat.PriorityBoost = 0.4
				}
				_ = f.memory.StorePattern(newPat)
			}
		}
	}

	return nil
}
