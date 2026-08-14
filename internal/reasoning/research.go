package reasoning

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/opportunity"
	"github.com/vKS-Rajput/doge/internal/retriever"
	"github.com/vKS-Rajput/doge/internal/surface"
	"github.com/vKS-Rajput/doge/pkg/ai"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResearchContext is the structured input to the research reasoning engine.
//
// The AI receives ONLY this structured context. Never raw HTML,
// never raw tool stdout, never unstructured data as top-level input.
//
// Observations within the evidence bundle are wrapped in
// OBSERVED_UNTRUSTED_CONTENT markers by the context builder.
type ResearchContext struct {
	// Opportunity is the research opportunity being investigated.
	Opportunity *opportunity.Opportunity

	// AttackSurfacePath is the chain from entry point to target surface.
	AttackSurfacePath *surface.ResearchPath

	// Correlations are cross-tool evidence links relevant to this target.
	Correlations []domain.Correlation

	// Evidence is the retrieved evidence bundle (with trust boundaries).
	Evidence *retriever.Bundle

	// InvestigationState captures previous research on this target.
	InvestigationState *InvestigationSnapshot

	// Constraints limit what the AI can produce.
	Constraints ResearchConstraints

	// ProjectID is the owning project.
	ProjectID uuid.UUID
}

// InvestigationSnapshot captures previous research state.
type InvestigationSnapshot struct {
	PreviousHypotheses  []domain.Hypothesis
	TestedSurfaces      []domain.TestedSurface
	PreviousConclusions []domain.Conclusion
}

// ResearchConstraints limit AI output.
type ResearchConstraints struct {
	MaxHypotheses   int      // Cap hypothesis count (default: 5).
	MaxQuestions    int      // Cap additional questions (default: 3).
	ForbiddenClaims []string // e.g., "confirmed vulnerability", "exploitable".
}

// ResearchResponseSchema is the JSON schema for research reasoning output.
const ResearchResponseSchema = `{
  "type": "object",
  "properties": {
    "hypotheses": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "statement": { "type": "string" },
          "supporting_evidence": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "id": { "type": "string" },
                "type": { "type": "string" },
                "summary": { "type": "string" }
              },
              "required": ["id", "type", "summary"]
            }
          },
          "confirmation_criteria": { "type": "array", "items": { "type": "string" } },
          "refutation_criteria": { "type": "array", "items": { "type": "string" } },
          "missing_evidence": { "type": "array", "items": { "type": "string" } },
          "status": { "type": "string", "enum": ["supported", "plausible", "uncertain", "contradicted", "insufficient"] },
          "confidence": { "type": "number" }
        },
        "required": ["statement", "supporting_evidence", "confirmation_criteria", "refutation_criteria", "status", "confidence"]
      }
    },
    "additional_questions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "question": { "type": "string" },
          "why": { "type": "string" },
          "expected_evidence": { "type": "string" },
          "sourced_from": { "type": "string" }
        },
        "required": ["question", "why", "expected_evidence", "sourced_from"]
      }
    },
    "validation_plans": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "question": { "type": "string" },
          "steps": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "order": { "type": "integer" },
                "description": { "type": "string" },
                "purpose": { "type": "string" }
              },
              "required": ["order", "description", "purpose"]
            }
          },
          "expected_confirmation": { "type": "string" },
          "expected_refutation": { "type": "string" }
        },
        "required": ["question", "steps", "expected_confirmation", "expected_refutation"]
      }
    },
    "limitations": { "type": "array", "items": { "type": "string" } },
    "uncertainties": { "type": "array", "items": { "type": "string" } }
  },
  "required": ["hypotheses", "limitations", "uncertainties"]
}`

// Reason processes a research context and produces hypotheses,
// questions, and validation plans.
//
// This is the research-specific entry point, alongside the
// existing Ask() method for general questions.
func (e *Engine) Reason(ctx context.Context, rctx *ResearchContext) (*ai.ResearchResponse, error) {
	// Step 1: Format sections as strings for the context builder.
	oppSection := formatOpportunitySection(rctx.Opportunity)
	pathSection := formatPathSection(rctx.AttackSurfacePath)
	corrSection := formatCorrelationSection(rctx.Correlations)
	invSection := formatInvestigationSection(rctx.InvestigationState)

	// Step 2: Build research prompt.
	prompt := e.builder.BuildResearchPrompt(oppSection, pathSection, corrSection, rctx.Evidence, invSection)

	e.logger.Info("research reasoning",
		"target", rctx.Opportunity.Target,
		"surface", rctx.Opportunity.SurfaceType,
		"evidence_count", prompt.EvidenceCount,
		"token_estimate", prompt.TokenEstimate,
	)

	// Step 2: Invoke Ollama with research response schema.
	result, err := e.ollama.Generate(ctx, prompt.SystemMessage, prompt.UserMessage, ResearchResponseSchema)
	if err != nil {
		return nil, &ai.ReasoningError{
			Stage:   "generation",
			Message: fmt.Sprintf("Ollama invocation failed: %v", err),
		}
	}

	// Step 3: Parse structured JSON response.
	var response ai.ResearchResponse
	if err := json.Unmarshal([]byte(result.Content), &response); err != nil {
		e.logger.Warn("invalid research JSON from model", "error", err)
		return nil, &ai.ReasoningError{
			Stage:   "parsing",
			Message: "Model returned invalid JSON for research response.",
		}
	}

	// Step 4: Build valid evidence ID set from the context.
	validIDs := buildValidEvidenceIDs(rctx.Evidence)

	// Step 5: Validate and filter hypotheses.
	var validHypotheses []ai.ResearchHypothesis
	for _, h := range response.Hypotheses {
		if err := ValidateHypothesis(&h, validIDs); err != nil {
			e.logger.Warn("hypothesis rejected",
				"statement", truncate(h.Statement, 80),
				"reason", err.Error(),
			)
			response.Limitations = append(response.Limitations,
				fmt.Sprintf("Rejected hypothesis: %s", err.Error()))
			continue
		}
		validHypotheses = append(validHypotheses, h)
	}
	response.Hypotheses = validHypotheses

	// Step 6: Enforce constraints.
	response = enforceConstraints(response, rctx.Constraints)

	// Step 7: Enforce safety on all validation plans.
	for i := range response.ValidationPlans {
		ValidateValidationPlan(&response.ValidationPlans[i])
	}

	e.logger.Info("research reasoning complete",
		"hypotheses", len(response.Hypotheses),
		"questions", len(response.AdditionalQuestions),
		"plans", len(response.ValidationPlans),
	)

	return &response, nil
}

// buildValidEvidenceIDs creates a lookup set of all evidence IDs
// available in the research context.
func buildValidEvidenceIDs(bundle *retriever.Bundle) map[string]bool {
	ids := make(map[string]bool)
	if bundle == nil {
		return ids
	}
	for _, e := range bundle.Evidence {
		ids[e.ID] = true
		// Also allow short IDs (first 8 chars).
		if len(e.ID) >= 8 {
			ids[e.ID[:8]] = true
		}
	}
	return ids
}

// enforceConstraints applies limits to the research response.
func enforceConstraints(r ai.ResearchResponse, c ResearchConstraints) ai.ResearchResponse {
	maxH := c.MaxHypotheses
	if maxH <= 0 {
		maxH = 5
	}
	if len(r.Hypotheses) > maxH {
		r.Hypotheses = r.Hypotheses[:maxH]
	}

	maxQ := c.MaxQuestions
	if maxQ <= 0 {
		maxQ = 3
	}
	if len(r.AdditionalQuestions) > maxQ {
		r.AdditionalQuestions = r.AdditionalQuestions[:maxQ]
	}

	// Filter forbidden claims from any hypothesis that slipped through.
	for _, forbidden := range c.ForbiddenClaims {
		lower := strings.ToLower(forbidden)
		var filtered []ai.ResearchHypothesis
		for _, h := range r.Hypotheses {
			if !strings.Contains(strings.ToLower(h.Statement), lower) {
				filtered = append(filtered, h)
			}
		}
		r.Hypotheses = filtered
	}

	return r
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// --- Section formatters ---
// These convert typed structs into prompt-ready strings to avoid
// circular imports between reasoning and context packages.

func formatOpportunitySection(opp *opportunity.Opportunity) string {
	if opp == nil {
		return ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("**Target:** %s", opp.Target))
	lines = append(lines, fmt.Sprintf("**Surface Type:** %s", opp.SurfaceType))
	lines = append(lines, fmt.Sprintf("**Title:** %s", opp.Title))
	if opp.Description != "" {
		lines = append(lines, fmt.Sprintf("**Description:** %s", opp.Description))
	}
	if len(opp.Questions) > 0 {
		lines = append(lines, "\n**Research Questions:**")
		for i, q := range opp.Questions {
			lines = append(lines, fmt.Sprintf("%d. %s", i+1, q.Question))
			lines = append(lines, fmt.Sprintf("   Why: %s", q.Why))
			lines = append(lines, fmt.Sprintf("   Expected evidence: %s", q.ExpectedEvidence))
		}
	}
	return strings.Join(lines, "\n")
}

func formatPathSection(path *surface.ResearchPath) string {
	if path == nil {
		return ""
	}
	var lines []string
	if len(path.Nodes) > 0 {
		lines = append(lines, fmt.Sprintf("**Entry Point:** %s", path.Nodes[0].Entity.Value))
		lines = append(lines, fmt.Sprintf("**Target Surface:** %s", path.Nodes[len(path.Nodes)-1].Entity.Value))
	}
	lines = append(lines, fmt.Sprintf("**Depth:** %d", path.Depth))
	if len(path.SurfaceCategories) > 0 {
		cats := make([]string, len(path.SurfaceCategories))
		for i, c := range path.SurfaceCategories {
			cats[i] = string(c)
		}
		lines = append(lines, fmt.Sprintf("**Categories:** %s", strings.Join(cats, " → ")))
	}
	if path.Description != "" {
		lines = append(lines, fmt.Sprintf("**Description:** %s", path.Description))
	}
	return strings.Join(lines, "\n")
}

func formatCorrelationSection(corrs []domain.Correlation) string {
	if len(corrs) == 0 {
		return ""
	}
	var lines []string
	for _, c := range corrs {
		lines = append(lines, fmt.Sprintf("- **%s** (confidence: %.0f%%, observations: %d)",
			c.RuleName, c.Confidence*100, len(c.ObservationIDs)))
	}
	return strings.Join(lines, "\n")
}

func formatInvestigationSection(state *InvestigationSnapshot) string {
	if state == nil {
		return ""
	}
	var lines []string
	if len(state.PreviousHypotheses) > 0 {
		lines = append(lines, fmt.Sprintf("**Previous hypotheses:** %d", len(state.PreviousHypotheses)))
		for _, h := range state.PreviousHypotheses {
			lines = append(lines, fmt.Sprintf("- [%s] %s (confidence: %.0f%%)",
				h.Status, h.Title, h.Confidence*100))
		}
	}
	if len(state.TestedSurfaces) > 0 {
		lines = append(lines, fmt.Sprintf("\n**Tested surfaces:** %d", len(state.TestedSurfaces)))
		for _, s := range state.TestedSurfaces {
			lines = append(lines, fmt.Sprintf("- %s: %s", s.Category, s.Status))
		}
	}
	if len(state.PreviousConclusions) > 0 {
		lines = append(lines, fmt.Sprintf("\n**Previous conclusions:** %d", len(state.PreviousConclusions)))
		for _, c := range state.PreviousConclusions {
			lines = append(lines, fmt.Sprintf("- [%s] %s", c.Status, c.Text))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

