package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Severity classifies the impact level of a finding, insight, or
// similar security-relevant object.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingCategory classifies what type of security issue was found.
type FindingCategory string

const (
	FindingCatAuthorization    FindingCategory = "authorization"
	FindingCatAuthentication   FindingCategory = "authentication"
	FindingCatInjection        FindingCategory = "injection"
	FindingCatInfoDisclosure   FindingCategory = "information_disclosure"
	FindingCatMisconfiguration FindingCategory = "misconfiguration"
	FindingCatCryptographic    FindingCategory = "cryptographic"
	FindingCatBusinessLogic    FindingCategory = "business_logic"
	FindingCatInputValidation  FindingCategory = "input_validation"
	FindingCatSessionMgmt      FindingCategory = "session_management"
	FindingCatFileUpload       FindingCategory = "file_upload"
)

// FindingStatus tracks the lifecycle of a finding.
type FindingStatus string

const (
	// FindingDraft is the initial state before human confirmation.
	FindingDraft FindingStatus = "draft"

	// FindingConfirmed means a human has verified this is real.
	FindingConfirmed FindingStatus = "confirmed"

	// FindingReported means this has been included in a report.
	FindingReported FindingStatus = "reported"

	// FindingResolved means the issue has been addressed.
	FindingResolved FindingStatus = "resolved"

	// FindingFalsePositive means the researcher determined this isn't real.
	FindingFalsePositive FindingStatus = "false_positive"

	// FindingDisputed means the researcher disagrees with the finding.
	FindingDisputed FindingStatus = "disputed"

	// FindingDuplicate means this is a duplicate of another finding.
	FindingDuplicate FindingStatus = "duplicate"
)

// Finding is the ONLY structure in DOGE that says "this is real."
//
// Every structure before this in the epistemic ladder is cautious:
//
//	Observation    → "I saw this"
//	Correlation    → "These are connected"
//	Novelty        → "This is unusual"
//	Opportunity    → "This deserves investigation"
//	Hypothesis     → "This might be true"
//	Validation     → "Here's what happened when we tested"
//	Candidate      → "This looks confirmable"
//
// A Finding says:
//
//	"A human has confirmed this based on evidence."
//
// Only a human can create a confirmed Finding.
// The AI may suggest severity and category, but only a human
// can set FindingConfirmed status.
type Finding struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// Title is a short, descriptive name.
	Title string `json:"title"`

	// Description provides detailed explanation.
	Description string `json:"description"`

	// Severity classifies impact. Suggested by AI, confirmed by human.
	Severity Severity `json:"severity"`

	// Category classifies the type of issue.
	Category FindingCategory `json:"category"`

	// Status tracks the finding lifecycle.
	Status FindingStatus `json:"status"`

	// EvidenceChain is the complete provenance from artifacts to finding.
	EvidenceChain EvidenceChain `json:"evidence_chain"`

	// CandidateID links to the FindingCandidate that originated this.
	CandidateID *uuid.UUID `json:"candidate_id,omitempty"`

	// HypothesisID links to the hypothesis that was validated.
	HypothesisID *uuid.UUID `json:"hypothesis_id,omitempty"`

	// EntityIDs lists the entities involved in this finding.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// EvidenceIDs lists the evidence supporting this finding.
	// Retained for backward compatibility with v0.5.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// ReproductionSteps are structured, not freeform.
	ReproductionSteps []ReproductionStep `json:"reproduction_steps"`

	// Impact is the assessed impact.
	Impact ImpactAssessment `json:"impact"`

	// Remediation guidance.
	Remediation string `json:"remediation"`

	// ConfirmedBy identifies the human who confirmed this.
	// NEVER "ai" or "system" — only a human identifier.
	ConfirmedBy string `json:"confirmed_by"`

	// InvestigationID links to the parent investigation.
	InvestigationID *uuid.UUID `json:"investigation_id,omitempty"`

	// DuplicateOfID links to the original if this is a duplicate.
	DuplicateOfID *uuid.UUID `json:"duplicate_of_id,omitempty"`

	// Notes holds the researcher's freeform notes.
	Notes string `json:"notes"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this finding was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this finding was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// ConfirmedAt is when the researcher confirmed this finding.
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

// ValidateFinding ensures a finding has evidence and provenance.
//
// Findings are researcher-confirmed facts, not AI opinions.
// A finding without evidence is invalid — this prevents the
// memory hallucination cascade where AI-generated hypotheses
// become "findings" and then get treated as established facts.
//
//	AI can propose → Hypothesis
//	AI can suggest → Finding Candidate
//	Evidence + researcher → Finding ✓
//	AI alone → Finding ✗
func ValidateFinding(f Finding) error {
	if f.Title == "" {
		return fmt.Errorf("finding title is empty")
	}
	if len(f.EvidenceIDs) == 0 && len(f.EvidenceChain.ObservationIDs) == 0 {
		return fmt.Errorf("finding must have evidence: either EvidenceIDs or EvidenceChain.ObservationIDs")
	}
	if f.Status == FindingConfirmed && f.ConfirmedBy == "" {
		return fmt.Errorf("confirmed finding must have a human confirmer (ConfirmedBy)")
	}
	if f.Status == FindingConfirmed && f.ConfirmedAt == nil {
		return fmt.Errorf("confirmed finding must have a confirmation timestamp")
	}
	if len(f.ReproductionSteps) == 0 && f.Status == FindingConfirmed {
		return fmt.Errorf("confirmed finding must have reproduction steps")
	}
	return nil
}

// --- Evidence Chain ---

// EvidenceChain is the complete provenance from raw artifacts
// to the confirmed finding. Every link is traceable.
//
// Example:
//
//	Finding: Unauthorized file upload
//	  ├── Hypothesis: "Upload may not enforce authorization"
//	  ├── Validation: GET /admin/upload as anonymous → 200
//	  ├── Correlations: same_target_multiple_tools
//	  ├── Observations: subfinder, httpx, nmap, nuclei
//	  └── Artifacts: subfinder-admin.json, httpx-admin.json
type EvidenceChain struct {
	// ObservationIDs lists the observations that form the evidence base.
	ObservationIDs []uuid.UUID `json:"observation_ids"`

	// CorrelationIDs lists correlations that connected the evidence.
	CorrelationIDs []uuid.UUID `json:"correlation_ids,omitempty"`

	// ValidationResultIDs lists the validation execution results.
	ValidationResultIDs []uuid.UUID `json:"validation_result_ids,omitempty"`

	// ArtifactIDs lists the original tool output files.
	ArtifactIDs []uuid.UUID `json:"artifact_ids,omitempty"`

	// HypothesisID links to the hypothesis that was tested.
	HypothesisID *uuid.UUID `json:"hypothesis_id,omitempty"`

	// Summary is a human-readable description of the evidence path.
	Summary string `json:"summary"`
}

// --- Finding Candidate ---

// CandidateStatus tracks the review state of a finding candidate.
type CandidateStatus string

const (
	// CandidatePending is awaiting human review.
	CandidatePending CandidateStatus = "pending"

	// CandidateAccepted means the human confirmed it as a finding.
	CandidateAccepted CandidateStatus = "accepted"

	// CandidateRejected means the human decided this is not a finding.
	CandidateRejected CandidateStatus = "rejected"

	// CandidateNeedsMore means the human wants additional evidence.
	CandidateNeedsMore CandidateStatus = "needs_more_evidence"
)

// FindingCandidate is the intermediate object between a supported
// hypothesis and a confirmed finding.
//
// The epistemic ladder:
//
//	Supported Hypothesis
//	      ↓
//	Finding Candidate        ← this
//	      ↓
//	👤 HUMAN CONFIRMATION
//	      ↓
//	CONFIRMED FINDING
//
// A supported hypothesis might still be:
//   - insufficiently reproduced
//   - incorrectly categorized
//   - missing impact evidence
//   - disputed by the researcher
//   - not severe enough to report
//   - a duplicate
type FindingCandidate struct {
	// ID uniquely identifies this candidate.
	ID uuid.UUID `json:"id"`

	// HypothesisID links to the supported hypothesis.
	HypothesisID uuid.UUID `json:"hypothesis_id"`

	// EvidenceChain is the accumulated evidence.
	EvidenceChain EvidenceChain `json:"evidence_chain"`

	// SuggestedTitle is the AI-proposed title.
	SuggestedTitle string `json:"suggested_title"`

	// SuggestedCategory is the AI-proposed category.
	SuggestedCategory FindingCategory `json:"suggested_category"`

	// SuggestedSeverity is the AI-proposed severity.
	SuggestedSeverity Severity `json:"suggested_severity"`

	// Rationale explains why this candidate was created.
	Rationale string `json:"rationale"`

	// Status tracks the human review state.
	Status CandidateStatus `json:"status"`

	// ReviewNotes are human notes about the review decision.
	ReviewNotes string `json:"review_notes,omitempty"`

	// ReviewedBy identifies who reviewed this candidate.
	ReviewedBy string `json:"reviewed_by,omitempty"`

	// ReviewedAt is when the review happened.
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`

	// ProjectID scopes to a project.
	ProjectID uuid.UUID `json:"project_id"`

	// InvestigationID links to the parent investigation.
	InvestigationID uuid.UUID `json:"investigation_id"`

	// CreatedAt is when this candidate was generated.
	CreatedAt time.Time `json:"created_at"`
}

// --- Reproduction Steps ---

// ReproductionStep is a structured step for reproducing the finding.
type ReproductionStep struct {
	// Order is the step number.
	Order int `json:"order"`

	// Description explains what to do.
	Description string `json:"description"`

	// ExpectedResult describes what should happen.
	ExpectedResult string `json:"expected_result"`

	// ObservedResult describes what actually happened.
	ObservedResult string `json:"observed_result"`

	// EvidenceID optionally links to supporting evidence.
	EvidenceID *uuid.UUID `json:"evidence_id,omitempty"`
}

// --- Impact Assessment ---

// ImpactAssessment describes the security impact.
type ImpactAssessment struct {
	// Confidentiality impact (none/low/high).
	Confidentiality string `json:"confidentiality"`

	// Integrity impact (none/low/high).
	Integrity string `json:"integrity"`

	// Availability impact (none/low/high).
	Availability string `json:"availability"`

	// Scope describes the blast radius.
	Scope string `json:"scope"`

	// Description is a human-readable impact summary.
	Description string `json:"description"`
}

// --- Finding Template ---

// FindingTemplate is a schema-driven template for common
// vulnerability classes. Templates define WHAT EVIDENCE is needed,
// not what the vulnerability IS.
//
// A template never says "This is an SSRF."
// It says: "A finding classified as SSRF requires these evidence fields."
type FindingTemplate struct {
	// Category identifies which finding category this template is for.
	Category FindingCategory `json:"category"`

	// RequiredEvidence lists evidence types that MUST be present.
	RequiredEvidence []EvidenceRequirement `json:"required_evidence"`

	// OptionalEvidence lists evidence types that add strength.
	OptionalEvidence []EvidenceRequirement `json:"optional_evidence"`

	// ReproductionSchema describes what reproduction steps need.
	ReproductionSchema []string `json:"reproduction_schema"`

	// ImpactFields describes what impact assessment needs.
	ImpactFields []string `json:"impact_fields"`

	// RemediationGuidance provides default remediation text.
	RemediationGuidance string `json:"remediation_guidance"`
}

// EvidenceRequirement describes a required piece of evidence.
type EvidenceRequirement struct {
	// Name identifies this evidence requirement.
	Name string `json:"name"`

	// Description explains what evidence is needed.
	Description string `json:"description"`

	// EvidenceType is the observation type expected.
	EvidenceType string `json:"evidence_type"`
}

// --- Filters ---

// FindingFilter specifies listing criteria.
type FindingFilter struct {
	ProjectID       *uuid.UUID       `json:"project_id,omitempty"`
	InvestigationID *uuid.UUID       `json:"investigation_id,omitempty"`
	Status          *FindingStatus   `json:"status,omitempty"`
	Severity        *Severity        `json:"severity,omitempty"`
	Category        *FindingCategory `json:"category,omitempty"`
	Limit           int              `json:"limit,omitempty"`
}

// CandidateFilter specifies listing criteria.
type CandidateFilter struct {
	ProjectID       *uuid.UUID       `json:"project_id,omitempty"`
	InvestigationID *uuid.UUID       `json:"investigation_id,omitempty"`
	Status          *CandidateStatus `json:"status,omitempty"`
	Limit           int              `json:"limit,omitempty"`
}
