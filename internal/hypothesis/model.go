// Package hypothesis implements DOGE's Epistemic Hypothesis and Anomaly Reasoning Engine.
//
// DOGE maintains strict epistemic boundaries:
//   OBSERVATION → FACT → INFERENCE → HYPOTHESIS → CANDIDATE FINDING → VALIDATED FINDING
//
// It discovers both known vulnerability patterns and novel behavioral anomalies,
// but never flags an unvalidated observation as a confirmed vulnerability.
package hypothesis

import (
	"time"

	"github.com/google/uuid"
)

// EpistemicTier classifies the level of certainty and validation.
type EpistemicTier string

const (
	TierObservation      EpistemicTier = "OBSERVATION"       // Raw data from a tool
	TierFact             EpistemicTier = "FACT"              // Verified grounded state (e.g. "port 443 open")
	TierInference        EpistemicTier = "INFERENCE"         // Logical deduction (e.g. "uses microservices")
	TierHypothesis       EpistemicTier = "HYPOTHESIS"        // Unvalidated theory with falsifiability criteria
	TierCandidateFinding EpistemicTier = "CANDIDATE_FINDING" // Partially confirmed with supporting indicators
	TierValidatedFinding EpistemicTier = "VALIDATED_FINDING" // Decisively validated with proof and reproducibility
)

// EpistemicStatus tracks the state of a hypothesis.
type EpistemicStatus string

const (
	StatusUnvalidated   EpistemicStatus = "UNVALIDATED"
	StatusPlausible     EpistemicStatus = "PLAUSIBLE"
	StatusSupported     EpistemicStatus = "SUPPORTED"
	StatusContradicted  EpistemicStatus = "CONTRADICTED"
	StatusConfirmed     EpistemicStatus = "CONFIRMED"
	StatusRejected      EpistemicStatus = "REJECTED"
	StatusInconclusive  EpistemicStatus = "INCONCLUSIVE"
)

// Category classifies the research hypothesis domain.
type Category string

const (
	CatBOLA              Category = "bola_idor"
	CatAuthBoundary      Category = "authentication_boundary"
	CatPrivilegeEsc      Category = "privilege_escalation"
	CatSSRF              Category = "ssrf"
	CatCORS              Category = "cors_misconfiguration"
	CatMassAssignment    Category = "mass_assignment"
	CatInformationLeak   Category = "information_disclosure"
	CatRateLimitAnomaly  Category = "rate_limit_anomaly"
	CatNovelAnomaly      Category = "novel_behavioral_anomaly"
	CatInjection         Category = "injection_surface"
)

// EvidenceRef records provenance for supporting data.
type EvidenceRef struct {
	ObservationID string `json:"observation_id,omitempty"`
	SourceTool    string `json:"source_tool"`
	ArtifactName  string `json:"artifact_name,omitempty"`
	Description   string `json:"description"`
	RawValue      string `json:"raw_value,omitempty"`
}

// ValidationRequirement defines what evidence is required to confirm or refute a hypothesis.
type ValidationRequirement struct {
	StepNumber          int    `json:"step_number"`
	ActionDescription   string `json:"action_description"`
	ExpectedProof       string `json:"expected_proof"`
	RefutationProof     string `json:"refutation_proof"`
	RequiresScopeCheck  bool   `json:"requires_scope_check"`
	RequiresHumanGate   bool   `json:"requires_human_gate"`
}

// ResearchHypothesis is a grounded, falsifiable security research hypothesis.
type ResearchHypothesis struct {
	ID                  uuid.UUID               `json:"id"`
	Title               string                  `json:"title"`
	Statement           string                  `json:"statement"`
	Target              string                  `json:"target"`
	Tier                EpistemicTier           `json:"tier"`
	Status              EpistemicStatus         `json:"status"`
	Category            Category                `json:"category"`
	Confidence          float64                 `json:"confidence"` // 0.0 to 1.0
	SupportingEvidence  []EvidenceRef           `json:"supporting_evidence"`
	ValidationSteps     []ValidationRequirement `json:"validation_steps"`
	RefutationCriteria  string                  `json:"refutation_criteria"`
	ConfirmationCriteria string                 `json:"confirmation_criteria"`
	FirstObservedAt     time.Time               `json:"first_observed_at"`
	LastEvaluatedAt     time.Time               `json:"last_evaluated_at"`
	EvaluationCount     int                     `json:"evaluation_count"`
	ContradictionCount  int                     `json:"contradiction_count"`
	ConfirmedAt         *time.Time              `json:"confirmed_at,omitempty"`
	RejectedAt          *time.Time              `json:"rejected_at,omitempty"`
	Notes               string                  `json:"notes,omitempty"`
}

// RecalculateConfidence updates confidence based on evaluation history and evidence changes.
func (h *ResearchHypothesis) RecalculateConfidence(hasNewSupportingEvidence bool) {
	h.EvaluationCount++
	h.LastEvaluatedAt = time.Now().UTC()

	if h.ContradictionCount > 0 {
		h.Confidence -= float64(h.ContradictionCount) * 0.20
		if h.Confidence <= 0.0 {
			h.Confidence = 0.0
			h.Status = StatusContradicted
			return
		}
	}

	if hasNewSupportingEvidence {
		h.Confidence += 0.10
		if h.Confidence > 0.95 {
			h.Confidence = 0.95 // Never 1.0 until explicitly confirmed
		}
		if h.Status == StatusUnvalidated {
			h.Status = StatusPlausible
		}
	} else {
		// Evaluation-based decay when no new supporting evidence is observed
		h.Confidence -= 0.04
		if h.Confidence < 0.10 {
			h.Confidence = 0.10 // Minimum baseline for open hypothesis
		}
	}
}
