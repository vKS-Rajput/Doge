package domain

import (
	"time"

	"github.com/google/uuid"
)

// ExperimentEvidence captures the complete request/response pair from a single experiment.
// This is the atomic unit of proof in DOGE V2.
type ExperimentEvidence struct {
	ID           uuid.UUID      `json:"id"`
	MissionID    uuid.UUID      `json:"mission_id"`
	HypothesisID *uuid.UUID     `json:"hypothesis_id,omitempty"`
	Description  string         `json:"description"`

	// Request
	RequestMethod  string            `json:"request_method"`
	RequestURL     string            `json:"request_url"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RequestBody    string            `json:"request_body,omitempty"`

	// Response
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ResponseTimeMs  int64             `json:"response_time_ms"`

	// Interpretation
	Interpretation string `json:"interpretation"`
	IsAnomalous    bool   `json:"is_anomalous"`

	CapturedAt time.Time `json:"captured_at"`
}

// Experiment represents a planned or executed experiment designed to test a hypothesis.
type Experiment struct {
	ID           uuid.UUID         `json:"id"`
	MissionID    uuid.UUID         `json:"mission_id"`
	HypothesisID *uuid.UUID        `json:"hypothesis_id,omitempty"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`

	// What this experiment should distinguish
	ExpectedOutcomeIfTrue  string `json:"expected_outcome_if_true"`
	ExpectedOutcomeIfFalse string `json:"expected_outcome_if_false"`

	// Execution details
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`

	// Result
	Status       string            `json:"status"` // "planned", "executed", "failed"
	Evidence     *ExperimentEvidence `json:"evidence,omitempty"`
	InformationGained float64      `json:"information_gained"`

	CreatedAt    time.Time         `json:"created_at"`
	ExecutedAt   *time.Time        `json:"executed_at,omitempty"`
}
