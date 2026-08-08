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
