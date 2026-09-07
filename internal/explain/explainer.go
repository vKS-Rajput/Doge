package explain

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Explanation provides structured epistemic and operational provenance for any hypothesis or recommendation.
type Explanation struct {
	Target             string                    `json:"target"`
	HypothesisID       uuid.UUID                 `json:"hypothesis_id"`
	Title              string                    `json:"title"`
	Statement          string                    `json:"statement"`
	EpistemicTier      hypothesis.EpistemicTier  `json:"epistemic_tier"`
	Status             hypothesis.EpistemicStatus `json:"status"`
	Confidence         float64                   `json:"confidence"`
	ScopeValidation    string                    `json:"scope_validation"`
	SupportingEvidence []hypothesis.EvidenceRef  `json:"supporting_evidence"`
	ValidationSteps    []hypothesis.ValidationRequirement `json:"validation_steps"`
	RefutationCriteria string                    `json:"refutation_criteria"`
	ConfirmationCriteria string                  `json:"confirmation_criteria"`
	LearnedPatterns    []string                  `json:"learned_patterns,omitempty"`
	SummaryMarkdown    string                    `json:"summary_markdown"`
}

// Explainer generates traceable justification chains for human review.
type Explainer struct {
	scopeEngine *scope.ScopeEngine
	hypEngine   *hypothesis.Engine
	learningMem *learning.Memory
}

// New creates a new Explainer.
func New(scopeEngine *scope.ScopeEngine, hypEngine *hypothesis.Engine, learningMem *learning.Memory) *Explainer {
	return &Explainer{
		scopeEngine: scopeEngine,
		hypEngine:   hypEngine,
		learningMem: learningMem,
	}
}

// ExplainHypothesis constructs a comprehensive explanation chain for a hypothesis.
func (e *Explainer) ExplainHypothesis(id uuid.UUID) (*Explanation, error) {
	h, ok := e.hypEngine.GetHypothesis(id)
	if !ok {
		return nil, fmt.Errorf("hypothesis %s not found", id)
	}

	cls, reason := e.scopeEngine.ClassifyAsset(h.Target)
	scopeVal := fmt.Sprintf("[%s] %s", cls, reason)

	expl := &Explanation{
		Target:               h.Target,
		HypothesisID:         h.ID,
		Title:                h.Title,
		Statement:            h.Statement,
		EpistemicTier:        h.Tier,
		Status:               h.Status,
		Confidence:           h.Confidence,
		ScopeValidation:      scopeVal,
		SupportingEvidence:   h.SupportingEvidence,
		ValidationSteps:      h.ValidationSteps,
		RefutationCriteria:   h.RefutationCriteria,
		ConfirmationCriteria: h.ConfirmationCriteria,
	}

	// Fetch relevant learning patterns if available
	if e.learningMem != nil {
		patterns, err := e.learningMem.AllPatterns()
		if err == nil {
			for _, p := range patterns {
				if strings.Contains(strings.ToLower(h.Title), strings.ToLower(p.Name)) ||
					strings.Contains(strings.ToLower(h.Statement), strings.ToLower(p.Name)) {
					expl.LearnedPatterns = append(expl.LearnedPatterns, fmt.Sprintf("%s (confidence: %.2f)", p.Description, p.Confidence))
				}
			}
		}
	}

	// Build markdown representation
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 🐕 DOGE Epistemic Explanation: %s\n\n", h.Title))
	sb.WriteString(fmt.Sprintf("- **Target:** `%s`\n", h.Target))
	sb.WriteString(fmt.Sprintf("- **Epistemic Tier:** `%s`\n", h.Tier))
	sb.WriteString(fmt.Sprintf("- **Status:** `%s`\n", h.Status))
	sb.WriteString(fmt.Sprintf("- **Confidence Score:** `%.2f / 1.00`\n", h.Confidence))
	sb.WriteString(fmt.Sprintf("- **Scope Validation:** %s\n\n", scopeVal))
	sb.WriteString(fmt.Sprintf("**Epistemic Statement:**\n> %s\n\n", h.Statement))

	if len(h.SupportingEvidence) > 0 {
		sb.WriteString("**Supporting Grounded Evidence:**\n")
		for i, ev := range h.SupportingEvidence {
			sb.WriteString(fmt.Sprintf("%d. **[%s]** %s (`%s`)\n", i+1, ev.SourceTool, ev.Description, ev.RawValue))
		}
		sb.WriteString("\n")
	}

	if len(h.ValidationSteps) > 0 {
		sb.WriteString("**Falsifiable Validation Steps:**\n")
		for _, step := range h.ValidationSteps {
			gateStr := "Auto"
			if step.RequiresHumanGate {
				gateStr = "Human Gate Required"
			}
			sb.WriteString(fmt.Sprintf("- **Step %d (%s):** %s\n  - *Expected Proof:* %s\n  - *Refutation Proof:* %s\n",
				step.StepNumber, gateStr, step.ActionDescription, step.ExpectedProof, step.RefutationProof))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("- **Refutation Criteria:** %s\n", h.RefutationCriteria))
	sb.WriteString(fmt.Sprintf("- **Confirmation Criteria:** %s\n", h.ConfirmationCriteria))

	expl.SummaryMarkdown = sb.String()
	return expl, nil
}

// ExplainEntity constructs provenance summary for an entity.
func (e *Explainer) ExplainEntity(ent domain.Entity, obsCount int) string {
	cls, reason := e.scopeEngine.ClassifyAsset(ent.Value)
	return fmt.Sprintf("Entity [%s] `%s` | Scope: %s (%s) | Observed %d times",
		ent.Type, ent.Value, cls, reason, obsCount)
}
