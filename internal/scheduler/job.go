package scheduler

import (
	"time"

	"github.com/google/uuid"
)

// Job represents a unit of work the scheduler wants to execute.
//
// Jobs are created by deterministic scheduler rules, NOT by AI.
// Each job tracks its full lifecycle from creation through completion.
type Job struct {
	// ID uniquely identifies this job.
	ID uuid.UUID `json:"id"`

	// InvestigationID links to the owning investigation.
	InvestigationID uuid.UUID `json:"investigation_id"`

	// Tool is the tool name from the registry.
	Tool string `json:"tool"`

	// Arguments are the tool-specific arguments.
	Arguments []string `json:"arguments"`

	// Target is the specific target for this job.
	Target string `json:"target"`

	// Reason explains why this job was created.
	// Example: "Port 443 discovered by nmap"
	Reason string `json:"reason"`

	// Priority determines queue ordering.
	Priority JobPriority `json:"priority"`

	// Status tracks the job lifecycle.
	Status JobStatus `json:"status"`

	// TriggerEventID is the event that caused this job.
	TriggerEventID uuid.UUID `json:"trigger_event_id"`

	// Execution metadata.
	CreatedAt       time.Time      `json:"created_at"`
	StartedAt       *time.Time     `json:"started_at,omitempty"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
	Duration        time.Duration  `json:"duration"`
	ExitCode        int            `json:"exit_code"`
	StdoutArtifact  *uuid.UUID     `json:"stdout_artifact,omitempty"`
	StderrArtifact  *uuid.UUID     `json:"stderr_artifact,omitempty"`
	Error           string         `json:"error,omitempty"`

	// Ingestion results.
	ObservationsCreated int `json:"observations_created"`
	ParseErrors         int `json:"parse_errors"`
}

// JobPriority determines queue ordering.
type JobPriority int

const (
	JobPriorityCritical JobPriority = 0
	JobPriorityHigh     JobPriority = 1
	JobPriorityNormal   JobPriority = 2
	JobPriorityLow      JobPriority = 3
)

// JobStatus tracks the job lifecycle.
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobApproval  JobStatus = "awaiting_approval"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
)

// IsTerminal returns true if the job is in a final state.
func (s JobStatus) IsTerminal() bool {
	return s == JobCompleted || s == JobFailed || s == JobCancelled
}

// NewJob creates a new queued job.
func NewJob(investigationID uuid.UUID, tool, target, reason string, priority JobPriority) Job {
	return Job{
		ID:              uuid.New(),
		InvestigationID: investigationID,
		Tool:            tool,
		Target:          target,
		Reason:          reason,
		Priority:        priority,
		Status:          JobQueued,
		CreatedAt:       time.Now().UTC(),
	}
}
