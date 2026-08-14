package validation

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

// TranslateValidationPlan converts an approved ValidationPlan into
// typed Actions that the executor can run.
//
// This is the boundary between AI reasoning and real-world effects.
// The AI produces structured ValidationPlan.Steps (descriptions).
// The translator produces typed Actions (structured HTTP metadata).
// The executor constructs the actual HTTP requests.
//
// The AI NEVER constructs raw HTTP requests.
func TranslateValidationPlan(
	plan ai.ValidationPlan,
	planID uuid.UUID,
	hypothesisID uuid.UUID,
	target string,
	defaultTimeout time.Duration,
) ([]Action, error) {
	if len(plan.Steps) == 0 {
		return nil, fmt.Errorf("validation plan has no steps")
	}

	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if defaultTimeout <= 0 {
		defaultTimeout = 10 * time.Second
	}

	var actions []Action
	for _, step := range plan.Steps {
		action, err := translateStep(step, planID, hypothesisID, target, defaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", step.Order, err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}

// translateStep converts a single ValidationStep into an Action.
func translateStep(
	step ai.ValidationStep,
	planID uuid.UUID,
	hypothesisID uuid.UUID,
	target string,
	timeout time.Duration,
) (Action, error) {
	// Determine action type from step description.
	actionType := classifyStep(step)

	// Default to GET — the safest transport method.
	method := "GET"

	// Extract path from step description or default to root.
	path := extractPath(step.Description)

	return Action{
		ID:             uuid.New(),
		PlanID:         planID,
		HypothesisID:   hypothesisID,
		Type:           actionType,
		Target:         target,
		Method:         method,
		Path:           path,
		ExpectedResult: step.Purpose,
		SafetyClass:    SafetyReadOnly,
		Timeout:        timeout,
	}, nil
}

// classifyStep determines the action type from a step description.
func classifyStep(step ai.ValidationStep) ActionType {
	desc := step.Description

	// Simple keyword classification.
	// In v0.9.5, all steps become http_request or endpoint_probe.
	if containsAny(desc, []string{"compare", "comparison", "versus", "vs"}) {
		return ActionHTTPCompare
	}
	if containsAny(desc, []string{"header", "CSP", "CORS", "Content-Type"}) {
		return ActionHeaderCheck
	}
	if containsAny(desc, []string{"check if", "exists", "responds", "probe", "alive"}) {
		return ActionEndpointProbe
	}
	if containsAny(desc, []string{"role", "authenticated", "unauthenticated", "admin", "user"}) {
		return ActionRoleCompare
	}
	return ActionHTTPRequest
}

// extractPath extracts a URL path from a step description.
// Returns "/" if no path is found.
func extractPath(description string) string {
	// Look for paths starting with "/".
	words := splitWords(description)
	for _, w := range words {
		if len(w) > 1 && w[0] == '/' {
			// Basic sanitization: remove trailing punctuation.
			w = trimTrailingPunct(w)
			return w
		}
	}
	return "/"
}

func containsAny(s string, keywords []string) bool {
	lower := toLower(s)
	for _, kw := range keywords {
		if contains(lower, toLower(kw)) {
			return true
		}
	}
	return false
}

func splitWords(s string) []string {
	var words []string
	word := ""
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == ',' || c == ';' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
		} else {
			word += string(c)
		}
	}
	if word != "" {
		words = append(words, word)
	}
	return words
}

func trimTrailingPunct(s string) string {
	for len(s) > 0 {
		last := s[len(s)-1]
		if last == '.' || last == ',' || last == ';' || last == ')' || last == '"' || last == '\'' {
			s = s[:len(s)-1]
		} else {
			break
		}
	}
	return s
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
