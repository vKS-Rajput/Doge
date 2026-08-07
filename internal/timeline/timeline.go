// Package timeline provides an append-only timeline of workspace events.
//
// The Timeline records significant events as they occur:
//   - Artifact stored
//   - Observation created
//   - Entity created / enriched
//   - Relationship created
//
// It depends on events, not the graph. This means:
//   - Timeline works even before the knowledge graph exists
//   - Replay works naturally (replay events = rebuild timeline)
//   - Every action is traceable to a point in time
//
// The Timeline is append-only. Events are never modified or deleted.
package timeline

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Entry represents a single timeline event.
type Entry struct {
	ID          uuid.UUID `json:"id"`
	Type        string    `json:"type"`         // e.g., "artifact.stored", "entity.created"
	SubjectType string    `json:"subject_type"` // e.g., "artifact", "entity", "observation"
	SubjectID   string    `json:"subject_id"`   // ID of the subject
	Action      string    `json:"action"`       // Human-readable description
	ProjectID   uuid.UUID `json:"project_id"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// Filter specifies criteria for querying timeline events.
type Filter struct {
	ProjectID   *uuid.UUID
	SubjectType string // Filter by subject type (e.g., "entity")
	Since       *time.Time
	Until       *time.Time
	Limit       int
}

// Timeline records and queries workspace events.
type Timeline struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// New creates a new Timeline.
func New(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Timeline {
	return &Timeline{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// Subscribe registers the timeline as a handler for all significant events.
// Call this once during app startup.
func (t *Timeline) Subscribe() {
	t.bus.Subscribe(events.TopicArtifactStored, t.onArtifactStored)
	t.bus.Subscribe(events.TopicObservationBatch, t.onObservationBatch)
	t.bus.Subscribe(events.TopicEntityCreated, t.onEntityCreated)
	t.bus.Subscribe(events.TopicEntityEnriched, t.onEntityEnriched)
	t.bus.Subscribe(events.TopicRelationshipCreated, t.onRelationshipCreated)
	t.bus.Subscribe(events.TopicArtifactDuplicate, t.onArtifactDuplicate)
	t.logger.Info("timeline subscribed to events")
}

// Query returns timeline entries matching the filter, ordered by time descending.
func (t *Timeline) Query(ctx context.Context, filter Filter) ([]Entry, error) {
	query := `SELECT id, type, subject_type, subject_id, action, project_id, occurred_at
	          FROM timeline_events WHERE 1=1`
	var args []any

	if filter.ProjectID != nil {
		query += " AND project_id = ?"
		args = append(args, filter.ProjectID.String())
	}
	if filter.SubjectType != "" {
		query += " AND subject_type = ?"
		args = append(args, filter.SubjectType)
	}
	if filter.Since != nil {
		query += " AND occurred_at >= ?"
		args = append(args, filter.Since.Format(time.RFC3339))
	}
	if filter.Until != nil {
		query += " AND occurred_at <= ?"
		args = append(args, filter.Until.Format(time.RFC3339))
	}

	query += " ORDER BY occurred_at DESC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := t.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var id, projectID, occurredAt string

		err := rows.Scan(&id, &e.Type, &e.SubjectType, &e.SubjectID,
			&e.Action, &projectID, &occurredAt)
		if err != nil {
			return nil, err
		}

		e.ID = uuid.MustParse(id)
		e.ProjectID = uuid.MustParse(projectID)
		e.OccurredAt, _ = time.Parse(time.RFC3339, occurredAt)
		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// append adds a single entry to the timeline.
func (t *Timeline) append(ctx context.Context, entry Entry) {
	_, err := t.db.ExecContext(ctx,
		`INSERT INTO timeline_events (id, type, subject_type, subject_id, action, project_id, occurred_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entry.ID.String(), entry.Type, entry.SubjectType, entry.SubjectID,
		entry.Action, entry.ProjectID.String(), entry.OccurredAt.Format(time.RFC3339))
	if err != nil {
		t.logger.Warn("failed to append timeline entry", "error", err)
	}
}

// --- Event Handlers ---

func (t *Timeline) onArtifactStored(ctx context.Context, event events.Event) error {
	e := event.(events.ArtifactStored)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "artifact.stored",
		SubjectType: "artifact",
		SubjectID:   e.ArtifactID.String(),
		Action:      fmt.Sprintf("Imported file: %s", e.Path),
		ProjectID:   e.ProjectID,
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func (t *Timeline) onArtifactDuplicate(ctx context.Context, event events.Event) error {
	e := event.(events.ArtifactDuplicate)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "artifact.duplicate",
		SubjectType: "artifact",
		SubjectID:   e.ExistingArtifactID.String(),
		Action:      fmt.Sprintf("Duplicate file detected (SHA256: %s...)", e.SHA256[:12]),
		ProjectID:   uuid.Nil, // Duplicate events don't carry project ID in event struct.
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func (t *Timeline) onObservationBatch(ctx context.Context, event events.Event) error {
	e := event.(events.ObservationBatch)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "observation.batch",
		SubjectType: "observation",
		SubjectID:   e.ArtifactID.String(),
		Action:      fmt.Sprintf("Created %d %s observations", e.Count, e.Type),
		ProjectID:   e.ProjectID,
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func (t *Timeline) onEntityCreated(ctx context.Context, event events.Event) error {
	e := event.(events.EntityCreated)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "entity.created",
		SubjectType: "entity",
		SubjectID:   e.EntityID.String(),
		Action:      fmt.Sprintf("Discovered %s: %s", e.Type, truncate(e.Value, 60)),
		ProjectID:   e.ProjectID,
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func (t *Timeline) onEntityEnriched(ctx context.Context, event events.Event) error {
	e := event.(events.EntityEnriched)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "entity.enriched",
		SubjectType: "entity",
		SubjectID:   e.EntityID.String(),
		Action:      fmt.Sprintf("Enriched entity with %d new attributes", len(e.NewAttributes)),
		ProjectID:   uuid.Nil, // Enriched events don't carry project ID.
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func (t *Timeline) onRelationshipCreated(ctx context.Context, event events.Event) error {
	e := event.(events.RelationshipCreated)
	t.append(ctx, Entry{
		ID:          uuid.New(),
		Type:        "relationship.created",
		SubjectType: "relationship",
		SubjectID:   e.RelationshipID.String(),
		Action:      fmt.Sprintf("Linked entities via %s", e.Type),
		ProjectID:   e.ProjectID,
		OccurredAt:  e.EventTime(),
	})
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
