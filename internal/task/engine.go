// Package task provides the Task Engine, which generates actionable
// research tasks from insights.
//
// The Task Engine subscribes to insight.detected events and creates
// prioritized, actionable tasks for the researcher. Each task has:
//   - Priority (critical, high, medium, low)
//   - Title and description
//   - Link to the triggering insight
//   - Status tracking (pending, in_progress, done, skipped)
//
// No AI. Tasks are generated from deterministic rules.
package task

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Priority classifies the urgency of a task.
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityMedium   Priority = "medium"
	PriorityLow      Priority = "low"
)

// Status tracks a task's lifecycle.
type Status string

const (
	StatusPending    Status = "pending"
	StatusInProgress Status = "in_progress"
	StatusDone       Status = "done"
	StatusSkipped    Status = "skipped"
)

// Task is an actionable research item.
type Task struct {
	ID          uuid.UUID   `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Type        string      `json:"type"`
	Priority    Priority    `json:"priority"`
	Status      Status      `json:"status"`
	EntityIDs   []uuid.UUID `json:"entity_ids"`
	InsightID   *uuid.UUID  `json:"insight_id,omitempty"`
	ProjectID   uuid.UUID   `json:"project_id"`
	CreatedAt   time.Time   `json:"created_at"`
}

// Engine generates and manages tasks.
type Engine struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// NewEngine creates a new Task Engine.
func NewEngine(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Engine {
	return &Engine{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// Subscribe registers the task engine as a handler for insight events.
func (e *Engine) Subscribe() {
	e.bus.Subscribe(events.TopicInsightDetected, e.onInsightDetected)
	e.logger.Info("task engine subscribed")
}

// Query returns tasks matching the filter.
func (e *Engine) Query(ctx context.Context, projectID uuid.UUID, status string, limit int) ([]Task, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, title, description, type, priority, status,
	                 entity_ids, insight_id, project_id, created_at
	          FROM tasks WHERE project_id = ?`
	args := []any{projectID.String()}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC"
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := e.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			continue
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func (e *Engine) onInsightDetected(ctx context.Context, event events.Event) error {
	ie := event.(events.InsightDetected)

	// Load the insight to get title and description.
	var title, description, severity string
	var projectID string
	err := e.db.QueryRowContext(ctx,
		`SELECT title, description, severity, project_id FROM insights WHERE id = ?`,
		ie.InsightID.String()).Scan(&title, &description, &severity, &projectID)
	if err != nil {
		e.logger.Warn("failed to load insight for task generation", "insight_id", ie.InsightID.String(), "error", err)
		return nil
	}

	// Map insight severity to task priority.
	priority := severityToPriority(severity)

	// Generate a task from the insight.
	task := Task{
		ID:          uuid.New(),
		Title:       taskTitle(ie.Type, title),
		Description: taskDescription(ie.Type, description),
		Type:        ie.Type,
		Priority:    priority,
		Status:      StatusPending,
		EntityIDs:   ie.EntityIDs,
		InsightID:   &ie.InsightID,
		ProjectID:   uuid.MustParse(projectID),
		CreatedAt:   time.Now().UTC(),
	}

	if err := e.persist(ctx, task); err != nil {
		e.logger.Warn("failed to persist task", "error", err)
		return nil
	}

	e.logger.Info("task created",
		"priority", string(priority),
		"title", task.Title,
		"type", ie.Type,
	)

	// Emit event.
	e.bus.Publish(ctx, events.TaskCreated{
		BaseEvent: events.NewBaseEvent(),
		TaskID:    task.ID,
		Type:      ie.Type,
		Priority:  string(priority),
		EntityIDs: ie.EntityIDs,
	})

	return nil
}

func (e *Engine) persist(ctx context.Context, task Task) error {
	entityIDsJSON, _ := json.Marshal(uuidStrings(task.EntityIDs))
	var insightID *string
	if task.InsightID != nil {
		s := task.InsightID.String()
		insightID = &s
	}

	_, err := e.db.ExecContext(ctx,
		`INSERT INTO tasks (id, title, description, type, priority, status,
		                    entity_ids, insight_id, project_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		task.ID.String(), task.Title, task.Description, task.Type,
		string(task.Priority), string(task.Status), string(entityIDsJSON),
		insightID, task.ProjectID.String(), task.CreatedAt.Format(time.RFC3339))
	return err
}

// taskTitle generates a task-appropriate title from an insight.
func taskTitle(insightType, insightTitle string) string {
	switch insightType {
	case "admin_path":
		return "Review admin interface access controls"
	case "api_endpoint":
		return "Test API endpoint authentication"
	case "sensitive_path":
		return "Verify sensitive path is not exposed"
	case "insecure_http":
		return "Assess plaintext HTTP exposure"
	case "interesting_technology":
		return "Research known vulnerabilities for technology"
	case "auth_endpoint":
		return "Test authentication mechanism"
	case "debug_endpoint":
		return "Verify debug endpoint is restricted"
	case "file_upload":
		return "Test file upload restrictions"
	default:
		return "Investigate: " + insightTitle
	}
}

// taskDescription adds actionable guidance.
func taskDescription(insightType, insightDesc string) string {
	switch insightType {
	case "admin_path":
		return insightDesc + "\n\nSuggested actions:\n• Check for default credentials\n• Test for authentication bypass\n• Enumerate admin functionality"
	case "api_endpoint":
		return insightDesc + "\n\nSuggested actions:\n• Test for missing authentication\n• Check for IDOR vulnerabilities\n• Review rate limiting"
	case "sensitive_path":
		return insightDesc + "\n\nSuggested actions:\n• Attempt to access the path\n• Check for information disclosure\n• Verify access controls"
	case "auth_endpoint":
		return insightDesc + "\n\nSuggested actions:\n• Test default credentials\n• Check for brute-force protection\n• Test authentication bypass"
	case "debug_endpoint":
		return insightDesc + "\n\nSuggested actions:\n• Check if endpoint is publicly accessible\n• Review information disclosed\n• Test for command injection"
	default:
		return insightDesc
	}
}

func severityToPriority(severity string) Priority {
	switch severity {
	case "critical":
		return PriorityCritical
	case "high":
		return PriorityHigh
	case "medium":
		return PriorityMedium
	case "low":
		return PriorityLow
	default:
		return PriorityLow
	}
}

func uuidStrings(ids []uuid.UUID) []string {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	return strs
}

func scanTask(rows *sql.Rows) (Task, error) {
	var t Task
	var id, title, desc, taskType, priority, status, entityIDsJSON, projectID, createdAt string
	var insightID *string

	err := rows.Scan(&id, &title, &desc, &taskType, &priority, &status,
		&entityIDsJSON, &insightID, &projectID, &createdAt)
	if err != nil {
		return t, err
	}

	t.ID = uuid.MustParse(id)
	t.Title = title
	t.Description = desc
	t.Type = taskType
	t.Priority = Priority(priority)
	t.Status = Status(status)
	t.ProjectID = uuid.MustParse(projectID)
	t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	if insightID != nil {
		uid := uuid.MustParse(*insightID)
		t.InsightID = &uid
	}

	var entityIDStrs []string
	_ = json.Unmarshal([]byte(entityIDsJSON), &entityIDStrs)
	for _, s := range entityIDStrs {
		if uid, err := uuid.Parse(s); err == nil {
			t.EntityIDs = append(t.EntityIDs, uid)
		}
	}

	return t, nil
}
