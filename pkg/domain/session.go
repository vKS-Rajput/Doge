package domain

import (
	"time"

	"github.com/google/uuid"
)

// SessionType classifies the kind of AI invocation.
type SessionType string

const (
	// SessionAsk is a direct question from the researcher.
	SessionAsk SessionType = "ask"

	// SessionAnalyze is an explicit analysis command.
	SessionAnalyze SessionType = "analyze"
)

// Session represents a single AI invocation (ask or analyze) with
// full reasoning graph. Sessions are first-class, browsable entities
// that preserve the complete chain from question to answer.
//
// The reasoning graph (ReasoningSteps) makes every AI conclusion
// auditable: you can trace what evidence was retrieved, how it was
// analyzed, and what confidence was assigned at each step.
type Session struct {
	// ID is the unique identifier for this session.
	ID uuid.UUID `json:"id"`

	// Type classifies whether this was an "ask" or "analyze" invocation.
	Type SessionType `json:"type"`

	// Question is the researcher's original question or analysis command.
	Question string `json:"question"`

	// ContextSnapshot lists the entity IDs that were included in the
	// AI's context for this invocation.
	ContextSnapshot []uuid.UUID `json:"context_snapshot"`

	// TokensUsed is the total number of tokens consumed by this invocation.
	TokensUsed int `json:"tokens_used"`

	// ModelUsed identifies which model was used for this invocation.
	ModelUsed string `json:"model_used"`

	// RawResponse is the unverified output from the model.
	RawResponse string `json:"raw_response"`

	// VerifiedResponse is the output after passing through the
	// Verification Engine. Nil if the response was rejected.
	VerifiedResponse *string `json:"verified_response,omitempty"`

	// Rejected is true if the Verification Engine rejected the response.
	Rejected bool `json:"rejected"`

	// RejectionReason explains why the response was rejected, if applicable.
	RejectionReason *string `json:"rejection_reason,omitempty"`

	// ReasoningSteps is the full reasoning chain, making the AI's
	// thought process auditable.
	ReasoningSteps []ReasoningStep `json:"reasoning_steps"`

	// Citations lists evidence references in the response.
	Citations []Citation `json:"citations"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// Duration is the wall-clock time for the entire invocation.
	Duration time.Duration `json:"duration"`

	// CreatedAt is when this session started.
	CreatedAt time.Time `json:"created_at"`

	// CompletedAt is when this session finished.
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ReasoningStep is a single step in the AI's reasoning chain.
// The sequence of steps makes the AI's conclusions auditable:
// retrieve evidence → analyze it → draw conclusions → cite sources.
type ReasoningStep struct {
	// ID is the unique identifier for this step.
	ID uuid.UUID `json:"id"`

	// SessionID links to the parent session.
	SessionID uuid.UUID `json:"session_id"`

	// StepIndex is the order of this step within the reasoning chain.
	StepIndex int `json:"step_index"`

	// Type classifies what this step does in the reasoning process.
	// Values: "retrieve", "analyze", "conclude", "cite"
	Type string `json:"type"`

	// Input is what this step received.
	Input string `json:"input"`

	// Output is what this step produced.
	Output string `json:"output"`

	// EvidenceIDs lists the evidence used in this step.
	EvidenceIDs []uuid.UUID `json:"evidence_ids"`

	// Confidence is the confidence level at this step,
	// from 0.0 (no confidence) to 1.0 (full confidence).
	Confidence float64 `json:"confidence"`

	// CreatedAt is when this step was executed.
	CreatedAt time.Time `json:"created_at"`
}

// Citation is a reference from an AI response to a specific piece
// of evidence, making claims verifiable. Every claim in the AI's
// output should have a corresponding Citation.
type Citation struct {
	// ID is the unique identifier for this citation.
	ID uuid.UUID `json:"id"`

	// SessionID links to the parent session.
	SessionID uuid.UUID `json:"session_id"`

	// EvidenceID links to the evidence being cited.
	EvidenceID uuid.UUID `json:"evidence_id"`

	// EntityID links to the entity being referenced.
	EntityID uuid.UUID `json:"entity_id"`

	// ClaimText is the AI's claim text that this citation supports.
	ClaimText string `json:"claim_text"`

	// Position is the character offset in the response where this
	// citation appears.
	Position int `json:"position"`

	// CreatedAt is when this citation was recorded.
	CreatedAt time.Time `json:"created_at"`
}
