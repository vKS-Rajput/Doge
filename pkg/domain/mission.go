package domain

import (
	"time"

	"github.com/google/uuid"
)

// MissionStatus tracks the lifecycle of a research mission.
type MissionStatus string

const (
	MissionPending    MissionStatus = "PENDING"
	MissionActive     MissionStatus = "ACTIVE"
	MissionCompleted  MissionStatus = "COMPLETED"
	MissionFailed     MissionStatus = "FAILED"
	MissionCancelled  MissionStatus = "CANCELLED"
)

// ResearcherType identifies what kind of specialized researcher should handle a mission.
type ResearcherType string

const (
	ResearcherRecon         ResearcherType = "recon"
	ResearcherAPI           ResearcherType = "api"
	ResearcherAuthorization ResearcherType = "authorization"
	ResearcherValidation    ResearcherType = "validation"
	ResearcherImpact        ResearcherType = "impact"
	ResearcherExploit       ResearcherType = "exploit"
	ResearcherChain         ResearcherType = "chain"
	ResearcherWorkflow      ResearcherType = "workflow"
	ResearcherAnomaly       ResearcherType = "anomaly"
)

// MissionBrief is the scoped context provided to a specialized researcher for a focused mission.
// It contains everything the researcher needs — and nothing more.
type MissionBrief struct {
	ID             uuid.UUID      `json:"id"`
	ResearcherType ResearcherType `json:"researcher_type"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`

	// Target context
	TargetBaseURL  string            `json:"target_base_url"`
	Credentials    map[string]string `json:"credentials,omitempty"`

	// World model slice — only what this mission needs
	KnownEndpoints []string          `json:"known_endpoints,omitempty"`
	KnownUsers     []string          `json:"known_users,omitempty"`
	KnownObjects   []string          `json:"known_objects,omitempty"`

	// Hypotheses this mission should investigate
	Hypotheses     []MissionHypothesis `json:"hypotheses,omitempty"`

	// Unknowns this mission should reduce
	Unknowns       []string          `json:"unknowns,omitempty"`

	// Constraints
	MaxRequests    int               `json:"max_requests"`
	MaxDuration    time.Duration     `json:"max_duration"`
	AllowedMethods []string          `json:"allowed_methods,omitempty"`

	// Success/failure criteria
	SuccessCriteria string           `json:"success_criteria"`
	FailureCriteria string           `json:"failure_criteria"`

	CreatedAt      time.Time         `json:"created_at"`
}

// MissionHypothesis is a hypothesis provided to a researcher for investigation.
type MissionHypothesis struct {
	ID                   uuid.UUID `json:"id"`
	Title                string    `json:"title"`
	Statement            string    `json:"statement"`
	Confidence           float64   `json:"confidence"`
	ConfirmationCriteria string    `json:"confirmation_criteria"`
	RefutationCriteria   string    `json:"refutation_criteria"`
}

// MissionResult is the structured output returned by a researcher after completing a mission.
type MissionResult struct {
	MissionID      uuid.UUID         `json:"mission_id"`
	Status         MissionStatus     `json:"status"`
	ResearcherType ResearcherType    `json:"researcher_type"`

	// What was discovered
	Observations   []MissionObservation     `json:"observations,omitempty"`
	Endpoints      []string                 `json:"endpoints,omitempty"`
	Objects        []string                 `json:"objects,omitempty"`
	Users          []string                 `json:"users,omitempty"`

	// Hypothesis outcomes
	HypothesisUpdates []MissionHypothesisUpdate    `json:"hypothesis_updates,omitempty"`

	// Evidence collected
	Evidence       []ExperimentEvidence     `json:"evidence,omitempty"`

	// New unknowns surfaced
	NewUnknowns    []string                 `json:"new_unknowns,omitempty"`

	// New hypotheses generated
	NewHypotheses  []MissionHypothesis      `json:"new_hypotheses,omitempty"`

	// Candidate findings
	CandidateFindings []CandidateVulnerability `json:"candidate_findings,omitempty"`

	// Recommendations for next research
	NextSteps      []string                 `json:"next_steps,omitempty"`

	// Execution metadata
	RequestsMade   int                      `json:"requests_made"`
	Duration       time.Duration            `json:"duration"`
	CompletedAt    time.Time                `json:"completed_at"`
	Summary        string                   `json:"summary"`
}

// MissionObservation is a structured observation from a research mission.
type MissionObservation struct {
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Endpoint    string         `json:"endpoint,omitempty"`
	Method      string         `json:"method,omitempty"`
	StatusCode  int            `json:"status_code,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	ObservedAt  time.Time      `json:"observed_at"`
}

// MissionHypothesisUpdate records how a mission changed a hypothesis.
type MissionHypothesisUpdate struct {
	HypothesisID  uuid.UUID `json:"hypothesis_id"`
	NewConfidence float64   `json:"new_confidence"`
	NewStatus     string    `json:"new_status"` // "supported", "contradicted", "rejected", "confirmed"
	Reason        string    `json:"reason"`
	EvidenceRef   string    `json:"evidence_ref,omitempty"`
}

// CandidateVulnerability is a potential vulnerability discovered by a researcher,
// pending independent validation.
type CandidateVulnerability struct {
	ID                uuid.UUID          `json:"id"`
	Title             string             `json:"title"`
	Type              string             `json:"type"` // e.g., "BOLA", "IDOR", "SSRF"
	Severity          string             `json:"severity"`
	Endpoint          string             `json:"endpoint"`
	Description       string             `json:"description"`
	Evidence          []ExperimentEvidence `json:"evidence"`
	ReproductionSteps []string           `json:"reproduction_steps"`
	Impact            string             `json:"impact"`
	HypothesisID      *uuid.UUID         `json:"hypothesis_id,omitempty"`
	DiscoveredAt      time.Time          `json:"discovered_at"`
}

// ProvenFinding is a validated, independently reproduced, impact-demonstrated finding.
type ProvenFinding struct {
	ID                uuid.UUID               `json:"id"`
	CandidateID       uuid.UUID               `json:"candidate_id"`
	Title             string                  `json:"title"`
	Type              string                  `json:"type"`
	Severity          string                  `json:"severity"`
	Endpoint          string                  `json:"endpoint"`
	Description       string                  `json:"description"`

	// Complete evidence chain
	DiscoveryEvidence    []ExperimentEvidence  `json:"discovery_evidence"`
	ValidationEvidence   []ExperimentEvidence  `json:"validation_evidence"`
	ImpactEvidence       []ExperimentEvidence  `json:"impact_evidence,omitempty"`

	ReproductionSteps    []string              `json:"reproduction_steps"`
	ImpactDemonstration  string                `json:"impact_demonstration,omitempty"`

	// Provenance — full trace from observation to proof
	DiscoveryMissionID   uuid.UUID             `json:"discovery_mission_id"`
	ValidationMissionID  uuid.UUID             `json:"validation_mission_id"`
	ImpactMissionID      *uuid.UUID            `json:"impact_mission_id,omitempty"`
	HypothesisID         *uuid.UUID            `json:"hypothesis_id,omitempty"`

	ValidatedAt          time.Time             `json:"validated_at"`
}
