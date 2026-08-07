package domain

import (
	"time"

	"github.com/google/uuid"
)

// TaskType classifies the kind of research action a task represents.
type TaskType string

const (
	TaskExploreEndpoint    TaskType = "explore_endpoint"
	TaskReviewJS           TaskType = "review_js"
	TaskTestAuth           TaskType = "test_auth"
	TaskInvestigateInsight TaskType = "investigate_insight"
	TaskVerifyHypothesis   TaskType = "verify_hypothesis"
	TaskScreenshotNeeded   TaskType = "screenshot_needed"
	TaskGeneral            TaskType = "general"
)

// TaskPriority indicates how urgent a task is.
type TaskPriority string

const (
	TaskPriorityCritical TaskPriority = "critical"
	TaskPriorityHigh     TaskPriority = "high"
	TaskPriorityMedium   TaskPriority = "medium"
	TaskPriorityLow      TaskPriority = "low"
)

// TaskStatus tracks the lifecycle of a task.
type TaskStatus string

const (
	TaskPending    TaskStatus = "pending"
	TaskInProgress TaskStatus = "in_progress"
	TaskCompleted  TaskStatus = "completed"
	TaskSkipped    TaskStatus = "skipped"
)

// EstimatedEffort indicates how much time a task is expected to require.
type EstimatedEffort string

const (
	EffortQuick    EstimatedEffort = "quick"
	EffortModerate EstimatedEffort = "moderate"
	EffortDeep     EstimatedEffort = "deep"
)

// Task is a prioritized, actionable research item surfaced by the
// Task Engine. Tasks are generated from insights, hypotheses, and
// workspace state analysis.
//
// The Task Engine transforms the workspace from a passive data store
// into an active research assistant by surfacing what the researcher
// should investigate next, ranked by priority and risk.
type Task struct {
	// ID is the unique identifier for this task.
	ID uuid.UUID `json:"id"`

	// Title is a short, actionable description of what to do.
	Title string `json:"title"`

	// Description provides context on why this task is important
	// and how to approach it.
	Description string `json:"description"`

	// Type classifies the kind of research action.
	Type TaskType `json:"type"`

	// Priority indicates how urgent this task is.
	Priority TaskPriority `json:"priority"`

	// Risk estimates how risky it is to ignore this task,
	// from 0.0 (negligible) to 1.0 (critical risk).
	Risk float64 `json:"risk"`

	// Confidence indicates how confident the system is that this
	// task is relevant, from 0.0 (speculative) to 1.0 (certain).
	Confidence float64 `json:"confidence"`

	// EvidenceCount is the number of evidence items that support
	// this task's relevance.
	EvidenceCount int `json:"evidence_count"`

	// EstimatedEffort indicates how much time this task is expected
	// to require.
	EstimatedEffort EstimatedEffort `json:"estimated_effort"`

	// Status tracks the lifecycle of this task.
	Status TaskStatus `json:"status"`

	// EntityIDs lists the entities related to this task.
	EntityIDs []uuid.UUID `json:"entity_ids"`

	// InsightID links to the insight that generated this task,
	// if applicable.
	InsightID *uuid.UUID `json:"insight_id,omitempty"`

	// HypothesisID links to the hypothesis that generated this task,
	// if applicable.
	HypothesisID *uuid.UUID `json:"hypothesis_id,omitempty"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this task was generated.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this task was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// CompletedAt is when this task was completed or skipped.
	// Nil if the task is still active.
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// TaskUpdate represents a partial update to a task.
type TaskUpdate struct {
	Status      *TaskStatus `json:"status,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
}

// TaskFilter specifies criteria for listing tasks.
type TaskFilter struct {
	ProjectID *uuid.UUID    `json:"project_id,omitempty"`
	Status    *TaskStatus   `json:"status,omitempty"`
	Priority  *TaskPriority `json:"priority,omitempty"`
	Type      *TaskType     `json:"type,omitempty"`
	Limit     int           `json:"limit,omitempty"`
	Offset    int           `json:"offset,omitempty"`
}
