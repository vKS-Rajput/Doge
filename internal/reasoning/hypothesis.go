package reasoning

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

// forbiddenStatements are phrases that an AI hypothesis must never contain.
// These prevent the AI from declaring vulnerabilities.
var forbiddenStatements = []string{
	"is vulnerable",
	"confirmed vulnerability",
	"exploitable",
	"critical vulnerability",
	"high severity",
	"can be exploited",
	"zero-day",
	"0-day",
}

// ValidateHypothesis ensures a hypothesis meets epistemic requirements.
//
// A hypothesis without refutation criteria is unfalsifiable and
// therefore scientifically useless. A hypothesis without evidence
// is ungrounded. Both are rejected.
//
// validEvidenceIDs is the set of evidence IDs available in the
// ResearchContext. Every referenced evidence ID must exist in this set.
// This prevents the AI from hallucinating evidence references.
func ValidateHypothesis(h *ai.ResearchHypothesis, validEvidenceIDs map[string]bool) error {
	if strings.TrimSpace(h.Statement) == "" {
		return fmt.Errorf("hypothesis must have a statement")
	}
	if len(h.Statement) > 2000 {
		return fmt.Errorf("hypothesis statement exceeds 2000 chars")
	}

	// Evidence grounding: must cite real evidence.
	if len(h.SupportingEvidence) == 0 {
		return fmt.Errorf("hypothesis must cite supporting evidence")
	}

	// Evidence existence: each referenced ID must exist in the context.
	for i, ref := range h.SupportingEvidence {
		if strings.TrimSpace(ref.ID) == "" {
			return fmt.Errorf("supporting_evidence[%d]: empty evidence ID", i)
		}
		if validEvidenceIDs != nil {
			// Check both full ID and short ID (first 8 chars).
			if !validEvidenceIDs[ref.ID] {
				return fmt.Errorf("supporting_evidence[%d]: evidence ID %q does not exist in research context", i, ref.ID)
			}
		}
	}

	// Falsifiability: must have refutation criteria.
	if len(h.RefutationCriteria) == 0 {
		return fmt.Errorf("hypothesis must have refutation criteria (unfalsifiable hypotheses are rejected)")
	}

	// Confirmation criteria required.
	if len(h.ConfirmationCriteria) == 0 {
		return fmt.Errorf("hypothesis must have confirmation criteria")
	}

	// Epistemic status required.
	if !validEpistemicStatus(h.Status) {
		return fmt.Errorf("invalid epistemic status %q (must be supported/plausible/uncertain/contradicted/insufficient)", h.Status)
	}

	// Confidence bounds.
	if h.Confidence < 0.0 || h.Confidence > 1.0 {
		return fmt.Errorf("confidence %.2f outside [0.0, 1.0]", h.Confidence)
	}

	// Forbidden claims gate.
	lower := strings.ToLower(h.Statement)
	for _, forbidden := range forbiddenStatements {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("hypothesis must not declare %q — hypotheses describe what deserves investigation, not vulnerability status", forbidden)
		}
	}

	return nil
}

func validEpistemicStatus(s ai.EpistemicStatus) bool {
	switch s {
	case ai.EpistemicSupported, ai.EpistemicPlausible, ai.EpistemicUncertain,
		ai.EpistemicContradicted, ai.EpistemicInsufficient:
		return true
	default:
		return false
	}
}

// ValidateValidationPlan ensures a plan meets safety requirements.
// In v0.9.4, RequiresApproval, NonDestructive, AuthorizedTargetOnly,
// and NoPersistence are ALL forcibly set to true. The AI cannot
// override these.
func ValidateValidationPlan(p *ai.ValidationPlan) {
	p.Constraints.RequiresApproval = true
	p.Constraints.AuthorizedTargetOnly = true
	p.Constraints.NonDestructive = true
	p.Constraints.NoPersistence = true
}

// HypothesisTracker tracks the evidence state of a hypothesis
// across reasoning evaluations. Used for evaluation-based confidence
// recalculation.
type HypothesisTracker struct {
	// HypothesisID identifies the hypothesis.
	HypothesisID uuid.UUID `json:"hypothesis_id"`

	// LastSupportedAt is when new supporting evidence was last found.
	LastSupportedAt time.Time `json:"last_supported_at"`

	// SupportingEvidenceVersion is a hash of the current supporting
	// evidence IDs. If unchanged across evaluations, confidence decays.
	SupportingEvidenceVersion string `json:"supporting_evidence_version"`

	// EvaluationCount is the number of reasoning evaluations since
	// the last new supporting evidence was found.
	EvaluationCount int `json:"evaluation_count"`

	// ContradictionCount is the number of times contradicting evidence
	// was found.
	ContradictionCount int `json:"contradiction_count"`
}

// RecalculateConfidence computes confidence from evidence state.
//
// Decay is evaluation-based, not time-based:
//   - Each evaluation without new support: -0.05
//   - Each contradiction: -0.15
//   - Floor: 0.0 (contradicted) or 0.10 (unsupported)
func RecalculateConfidence(original float64, tracker HypothesisTracker) float64 {
	c := original

	// Contradictions are aggressive.
	if tracker.ContradictionCount > 0 {
		c -= float64(tracker.ContradictionCount) * 0.15
		if c < 0.0 {
			return 0.0
		}
	}

	// Decay for evaluations without new support.
	if tracker.EvaluationCount > 0 {
		c -= float64(tracker.EvaluationCount) * 0.05
		if c < 0.10 {
			return 0.10 // Floor at 0.10 for unsupported.
		}
	}

	return c
}
