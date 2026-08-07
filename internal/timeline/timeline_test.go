package timeline

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/pkg/events"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY, workspace_id TEXT, slug TEXT, name TEXT,
			status TEXT DEFAULT 'active', created_at TEXT, updated_at TEXT
		);
		CREATE TABLE IF NOT EXISTS timeline_events (
			id TEXT PRIMARY KEY, type TEXT NOT NULL, subject_type TEXT NOT NULL,
			subject_id TEXT NOT NULL, action TEXT NOT NULL,
			before_state TEXT, after_state TEXT,
			project_id TEXT NOT NULL, occurred_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_timeline_occurred ON timeline_events(occurred_at);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTimeline_SubscribeAndRecord(t *testing.T) {
	db := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	tl := New(db, eventBus, logging.NewNop())
	tl.Subscribe()

	projectID := uuid.New()
	now := time.Now().UTC()
	db.Exec(`INSERT INTO projects (id, workspace_id, slug, name, status, created_at, updated_at)
		VALUES (?, ?, 'test', 'Test', 'active', ?, ?)`,
		projectID.String(), uuid.New().String(), now.Format(time.RFC3339), now.Format(time.RFC3339))

	// Publish events.
	eventBus.Publish(context.Background(), events.ArtifactStored{
		BaseEvent:  events.NewBaseEvent(),
		ArtifactID: uuid.New(),
		Path:       "/data/httpx_output.jsonl",
		SHA256:     "abc123def456",
		ProjectID:  projectID,
	})

	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "https://example.com",
		ProjectID: projectID,
	})

	eventBus.Publish(context.Background(), events.RelationshipCreated{
		BaseEvent:      events.NewBaseEvent(),
		RelationshipID: uuid.New(),
		SourceEntityID: uuid.New(),
		TargetEntityID: uuid.New(),
		Type:           "serves",
		ProjectID:      projectID,
	})

	// Drain to process events.
	eventBus.Drain()

	// Query timeline.
	entries, err := tl.Query(context.Background(), Filter{
		ProjectID: &projectID,
		Limit:     50,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("expected 3 timeline entries, got %d", len(entries))
	}

	// Verify event types recorded.
	types := map[string]bool{}
	for _, e := range entries {
		types[e.Type] = true
	}
	for _, want := range []string{"artifact.stored", "entity.created", "relationship.created"} {
		if !types[want] {
			t.Errorf("expected timeline entry of type %q", want)
		}
	}
}

func TestTimeline_QueryBySubjectType(t *testing.T) {
	db := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	tl := New(db, eventBus, logging.NewNop())
	tl.Subscribe()

	projectID := uuid.New()
	now := time.Now().UTC()
	db.Exec(`INSERT INTO projects (id, workspace_id, slug, name, status, created_at, updated_at)
		VALUES (?, ?, 'test', 'Test', 'active', ?, ?)`,
		projectID.String(), uuid.New().String(), now.Format(time.RFC3339), now.Format(time.RFC3339))

	// Publish two different event types.
	eventBus.Publish(context.Background(), events.ArtifactStored{
		BaseEvent: events.NewBaseEvent(), ArtifactID: uuid.New(),
		Path: "/a.jsonl", SHA256: "abc", ProjectID: projectID,
	})
	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(), EntityID: uuid.New(),
		Type: "url", Value: "https://a.com", ProjectID: projectID,
	})
	eventBus.Drain()

	// Query only entity events.
	entries, _ := tl.Query(context.Background(), Filter{
		ProjectID:   &projectID,
		SubjectType: "entity",
	})
	if len(entries) != 1 {
		t.Errorf("expected 1 entity entry, got %d", len(entries))
	}
}

func TestTimeline_EmptyWorkspace(t *testing.T) {
	db := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	tl := New(db, eventBus, logging.NewNop())

	entries, err := tl.Query(context.Background(), Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
