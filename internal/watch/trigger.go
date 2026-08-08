package watch

import (
	"log/slog"
)

// TriggerPolicy determines when AI reasoning should be suggested.
//
// The trigger policy is DETERMINISTIC and EVIDENCE-DRIVEN:
//   - It may decide something deserves attention
//   - It may NEVER decide that a vulnerability exists
//   - It only suggests; it never auto-invokes the LLM
//
// When triggered, the display shows:
//
//	🧠 AI reasoning recommended
//	Run: doge ask "What changed?"
//
// The researcher decides whether to actually invoke AI.
type TriggerPolicy struct {
	logger *slog.Logger
}

// NewTriggerPolicy creates a new AI trigger policy.
func NewTriggerPolicy(logger *slog.Logger) *TriggerPolicy {
	return &TriggerPolicy{logger: logger}
}

// TriggerResult contains the trigger decision.
type TriggerResult struct {
	ShouldSuggest bool
	Reason        string
}

// Evaluate checks whether a change summary warrants AI reasoning.
func (p *TriggerPolicy) Evaluate(summary ChangeSummary) TriggerResult {
	// Rule 1: High/critical severity items.
	for _, item := range summary.Items {
		if item.Priority == "high" || item.Priority == "critical" {
			return TriggerResult{
				ShouldSuggest: true,
				Reason:        "high-severity change detected: " + item.Value,
			}
		}
	}

	// Rule 2: Large structural change (many new observations).
	if summary.Observations >= 50 {
		return TriggerResult{
			ShouldSuggest: true,
			Reason:        "large structural change detected",
		}
	}

	// Rule 3: Multiple files in one window suggests a significant event.
	if summary.Files >= 5 {
		return TriggerResult{
			ShouldSuggest: true,
			Reason:        "multiple scan outputs detected simultaneously",
		}
	}

	return TriggerResult{ShouldSuggest: false}
}
