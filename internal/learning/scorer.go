package learning

import (
	"time"

	"github.com/google/uuid"
)

// Scorer adjusts research priorities based on learned patterns.
//
// The scorer NEVER creates facts. It only adjusts ranking.
// Every adjustment is traceable via PriorityExplanation.
type Scorer struct {
	memory *Memory
}

// NewScorer creates a scorer backed by the learning memory.
func NewScorer(memory *Memory) *Scorer {
	return &Scorer{memory: memory}
}

// AdjustPriority takes a base priority and adjusts it using learned patterns.
// Returns the adjusted priority and a full explanation.
func (s *Scorer) AdjustPriority(basePriority float64, target string, context map[string]string) PriorityExplanation {
	explanation := PriorityExplanation{
		BasePriority:  basePriority,
		FinalPriority: basePriority,
	}

	patterns, err := s.memory.AllPatterns()
	if err != nil || len(patterns) == 0 {
		return explanation
	}

	for _, p := range patterns {
		// Skip low-confidence or heavily decayed patterns.
		effectiveConfidence := p.Confidence * p.DecayFactor
		if effectiveConfidence < 0.1 {
			continue
		}

		// Check if this pattern is relevant to the target.
		if !s.isRelevant(p, target, context) {
			continue
		}

		// Calculate adjustment.
		delta := p.PriorityBoost * effectiveConfidence

		// Noise patterns reduce priority.
		if p.Category == PatternNoise {
			delta = -delta
		}

		if delta != 0 {
			explanation.Adjustments = append(explanation.Adjustments, PriorityAdjustment{
				Reason:    p.Description,
				Delta:     delta,
				PatternID: p.ID,
			})
			explanation.FinalPriority += delta
		}
	}

	// Clamp to [0.0, 1.0].
	if explanation.FinalPriority > 1.0 {
		explanation.FinalPriority = 1.0
	}
	if explanation.FinalPriority < 0.0 {
		explanation.FinalPriority = 0.0
	}

	return explanation
}

// isRelevant checks if a pattern applies to a given target and context.
func (s *Scorer) isRelevant(p ResearchPattern, target string, context map[string]string) bool {
	switch p.Category {
	case PatternEndpoint:
		// Endpoint patterns are relevant if the target looks like a URL path.
		if len(target) > 0 && target[0] == '/' {
			return true
		}
	case PatternParameter:
		// Parameter patterns are relevant if context mentions parameters.
		if _, ok := context["parameter"]; ok {
			return true
		}
	case PatternAuth, PatternAuthz:
		// Auth patterns are always relevant.
		return true
	case PatternTechnology:
		// Tech patterns relevant if context mentions the technology.
		if tech, ok := context["technology"]; ok {
			return tech != ""
		}
	case PatternNoise:
		// Noise patterns relevant if target matches.
		return true
	case PatternResponse, PatternWorkflow:
		return true
	}
	return false
}

// DecayPatterns reduces confidence of patterns that haven't been seen recently.
// Patterns older than the threshold get their decay factor reduced.
func (s *Scorer) DecayPatterns(threshold time.Duration) error {
	patterns, err := s.memory.AllPatterns()
	if err != nil {
		return err
	}

	now := time.Now()
	for _, p := range patterns {
		age := now.Sub(p.LastSeen)
		if age > threshold {
			// Reduce decay factor by 10% for each threshold period.
			periods := age / threshold
			newDecay := p.DecayFactor * (1.0 - 0.1*float64(periods))
			if newDecay < 0.1 {
				newDecay = 0.1 // Never fully decay.
			}
			if newDecay != p.DecayFactor {
				p.DecayFactor = newDecay
				if err := s.memory.StorePattern(&p); err != nil {
					return err
				}

				// Record the decay event.
				s.memory.RecordEvent(&LearningEvent{
					ID:              uuid.New(),
					Type:            EventDecay,
					PatternName:     p.Name,
					Context:         "pattern decayed due to staleness",
					ConfidenceDelta: -(p.Confidence * (1.0 - newDecay)),
					RecordedAt:      now,
				})
			}
		}
	}
	return nil
}
