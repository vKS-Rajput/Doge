// Package ai provides shared types for the AI reasoning pipeline.
//
// These types are used by both the reasoning engine and the
// verification engine, so they live in a shared package to
// avoid import cycles.
//
// Architectural principle:
//
//	The LLM can propose claims. It cannot establish facts.
//	Only workspace evidence and deterministic system logic
//	can establish facts.
package ai

import "time"

// Response is the structured output from the LLM.
// The model MUST return valid JSON matching this schema.
type Response struct {
	Answer      string   `json:"answer"`
	Claims      []Claim  `json:"claims"`
	Limitations []string `json:"limitations"`
}

// ClaimCategory classifies how a claim was derived.
type ClaimCategory string

const (
	// ClaimObserved: restates something directly present in evidence.
	ClaimObserved ClaimCategory = "observed"

	// ClaimInferred: logical inference from multiple evidence items.
	ClaimInferred ClaimCategory = "inferred"

	// ClaimHypothetical: speculative, requires further investigation.
	ClaimHypothetical ClaimCategory = "hypothetical"
)

// Claim is a single factual assertion made by the LLM.
type Claim struct {
	Text        string        `json:"text"`
	EvidenceIDs []string      `json:"evidence_ids"`
	Confidence  float64       `json:"confidence"`
	Category    ClaimCategory `json:"category"`
}

// VerificationStatus describes how well a claim is supported by evidence.
type VerificationStatus string

const (
	StatusSupported          VerificationStatus = "supported"
	StatusPartiallySupported VerificationStatus = "partially_supported"
	StatusUnsupported        VerificationStatus = "unsupported"
	StatusContradicted       VerificationStatus = "contradicted"
	StatusUnverifiable       VerificationStatus = "unverifiable"
)

// VerificationResult is the outcome of verifying a single claim.
type VerificationResult struct {
	ClaimIndex  int                `json:"claim_index"`
	ClaimText   string             `json:"claim_text"`
	Status      VerificationStatus `json:"status"`
	EvidenceIDs []string           `json:"evidence_ids"`
	Reason      string             `json:"reason"`
}

// VerifiedResponse is the final output after claim verification.
type VerifiedResponse struct {
	Answer          string               `json:"answer"`
	SupportedClaims []VerifiedClaim      `json:"supported_claims"`
	RejectedClaims  []VerifiedClaim      `json:"rejected_claims"`
	Limitations     []string             `json:"limitations"`
	Verification    []VerificationResult `json:"verification"`
	ModelUsed       string               `json:"model_used"`
	TotalTokens     int                  `json:"total_tokens"`
	DurationMs      int64                `json:"duration_ms"`
	ThinkingEnabled bool                 `json:"thinking_enabled"`
}

// VerifiedClaim is a claim with its verification result attached.
type VerifiedClaim struct {
	Claim
	VerificationStatus VerificationStatus `json:"verification_status"`
	VerificationReason string             `json:"verification_reason"`
}

// ReasoningError represents a failure in the reasoning pipeline.
type ReasoningError struct {
	Stage   string `json:"stage"`   // "generation", "parsing", "validation", "verification"
	Message string `json:"message"`
	Retried bool   `json:"retried"`
}

func (e *ReasoningError) Error() string {
	return e.Stage + ": " + e.Message
}

// ModelMetrics captures performance data from a reasoning invocation.
type ModelMetrics struct {
	Model           string        `json:"model"`
	PromptTokens    int           `json:"prompt_tokens"`
	ResponseTokens  int           `json:"response_tokens"`
	TotalTokens     int           `json:"total_tokens"`
	Duration        time.Duration `json:"duration"`
	TokensPerSecond float64       `json:"tokens_per_second"`
}

// --- Research Reasoning Types (v0.9.4) ---

// EpistemicStatus classifies how well evidence supports a hypothesis.
//
// This is the AI's honest assessment of evidence quality.
// It is NOT a vulnerability probability.
type EpistemicStatus string

const (
	// EpistemicSupported: Evidence consistently supports the hypothesis.
	EpistemicSupported EpistemicStatus = "supported"

	// EpistemicPlausible: Compatible evidence, but insufficient to confirm.
	EpistemicPlausible EpistemicStatus = "plausible"

	// EpistemicUncertain: Evidence is ambiguous or mixed signals.
	EpistemicUncertain EpistemicStatus = "uncertain"

	// EpistemicContradicted: Evidence actively refutes the hypothesis.
	EpistemicContradicted EpistemicStatus = "contradicted"

	// EpistemicInsufficient: Not enough evidence to evaluate.
	EpistemicInsufficient EpistemicStatus = "insufficient"
)

// ResearchHypothesis is an AI-generated hypothesis about a security
// configuration that may warrant investigation.
//
// CRITICAL INVARIANT: A hypothesis is NOT a finding.
// It is: "The evidence suggests X may be worth investigating."
// It is NOT: "X is vulnerable."
//
// Every hypothesis must answer four questions:
//  1. What do we think? (Statement)
//  2. Why do we think it? (SupportingEvidence)
//  3. What would prove us right? (ConfirmationCriteria)
//  4. What would prove us wrong? (RefutationCriteria)
type ResearchHypothesis struct {
	// Statement is the hypothesis itself.
	Statement string `json:"statement"`

	// SupportingEvidence references specific evidence items.
	// Each ID must exist in the ResearchContext's evidence bundle.
	SupportingEvidence []EvidenceRef `json:"supporting_evidence"`

	// ConfirmationCriteria describe what would confirm this hypothesis.
	ConfirmationCriteria []string `json:"confirmation_criteria"`

	// RefutationCriteria describe what would refute this hypothesis.
	// A hypothesis without refutation criteria is unfalsifiable
	// and therefore scientifically useless.
	RefutationCriteria []string `json:"refutation_criteria"`

	// MissingEvidence describes what evidence is needed but absent.
	MissingEvidence []string `json:"missing_evidence"`

	// Status is the epistemic assessment.
	Status EpistemicStatus `json:"status"`

	// Confidence measures evidence quality, NOT vulnerability probability.
	// 0.85 = "85% confident the evidence supports this hypothesis."
	// NOT: "85% chance this is a vulnerability."
	Confidence float64 `json:"confidence"`
}

// EvidenceRef is a reference to a specific piece of evidence.
type EvidenceRef struct {
	// ID is the evidence identifier (first 8 chars for display).
	ID string `json:"id"`

	// Type classifies the evidence source.
	Type string `json:"type"` // "observation", "correlation", "novelty", "entity", etc.

	// Summary is a one-line description.
	Summary string `json:"summary"`
}

// ResearchQuestion is a research question, either from the opportunity
// generator or proposed by the AI.
type ResearchQuestion struct {
	// Question is the research question.
	Question string `json:"question"`

	// Why explains why this question matters.
	Why string `json:"why"`

	// ExpectedEvidence describes what evidence would answer this.
	ExpectedEvidence string `json:"expected_evidence"`

	// SourcedFrom identifies whether this came from the opportunity
	// generator or was proposed by the AI.
	SourcedFrom string `json:"sourced_from"` // "opportunity" or "ai_proposed"
}

// ValidationStep is a single step in a validation plan.
// Description only — no executable command representation in v0.9.4.
type ValidationStep struct {
	// Order is the step number (1-indexed).
	Order int `json:"order"`

	// Description is what to do (human-readable, not executable).
	Description string `json:"description"`

	// Purpose explains why this step matters.
	Purpose string `json:"purpose"`
}

// ValidationPlan describes how to test a hypothesis.
// In v0.9.4, RequiresApproval is ALWAYS true.
type ValidationPlan struct {
	// Question is what this plan answers.
	Question string `json:"question"`

	// Steps are the structured validation steps.
	Steps []ValidationStep `json:"steps"`

	// ExpectedConfirmation describes what would confirm the hypothesis.
	ExpectedConfirmation string `json:"expected_confirmation"`

	// ExpectedRefutation describes what would refute the hypothesis.
	ExpectedRefutation string `json:"expected_refutation"`

	// Constraints define safety boundaries.
	Constraints ValidationConstraints `json:"constraints"`
}

// ValidationConstraints define safety boundaries for validation.
type ValidationConstraints struct {
	AuthorizedTargetOnly bool `json:"authorized_target_only"` // Always true
	NonDestructive       bool `json:"non_destructive"`        // Always true in v0.9.4
	BoundedRequests      int  `json:"bounded_requests"`       // Max requests (0 = N/A)
	NoPersistence        bool `json:"no_persistence"`         // Always true
	RequiresApproval     bool `json:"requires_approval"`      // Always true in v0.9.4
}

// ResearchResponse is the structured output from research reasoning.
type ResearchResponse struct {
	// Hypotheses are the AI-generated research hypotheses.
	Hypotheses []ResearchHypothesis `json:"hypotheses"`

	// AdditionalQuestions are AI-proposed research questions
	// beyond what the opportunity generator created.
	AdditionalQuestions []ResearchQuestion `json:"additional_questions"`

	// ValidationPlans describe how to test the hypotheses.
	ValidationPlans []ValidationPlan `json:"validation_plans"`

	// Limitations describe what the evidence does NOT cover.
	Limitations []string `json:"limitations"`

	// Uncertainties are explicit "I don't know" items.
	Uncertainties []string `json:"uncertainties"`
}
