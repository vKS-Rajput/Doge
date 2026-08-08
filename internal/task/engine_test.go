package task

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

func setupTestDB(t *testing.T) (*sql.DB, uuid.UUID) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE projects (
			id TEXT PRIMARY KEY, workspace_id TEXT, slug TEXT, name TEXT,
			status TEXT DEFAULT 'active', created_at TEXT, updated_at TEXT
		);
		CREATE TABLE insights (
			id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL,
			description TEXT DEFAULT '', severity TEXT DEFAULT 'info',
			entity_ids TEXT DEFAULT '[]', evidence_ids TEXT DEFAULT '[]',
			rule_id TEXT, diff_id TEXT, acknowledged INTEGER DEFAULT 0,
			project_id TEXT NOT NULL, detected_at TEXT NOT NULL
		);
		CREATE TABLE tasks (
			id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
			type TEXT NOT NULL, priority TEXT DEFAULT 'medium',
			risk REAL DEFAULT 0.0, confidence REAL DEFAULT 0.0,
			evidence_count INTEGER DEFAULT 0,
			estimated_effort TEXT DEFAULT 'moderate',
			status TEXT DEFAULT 'pending', entity_ids TEXT DEFAULT '[]',
			insight_id TEXT, hypothesis_id TEXT,
			project_id TEXT NOT NULL, created_at TEXT, updated_at TEXT, completed_at TEXT
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	projectID := uuid.New()
	now := time.Now().UTC().Format(time.RFC3339)
	db.Exec(`INSERT INTO projects VALUES (?, ?, 'test', 'Test', 'active', ?, ?)`,
		projectID.String(), uuid.New().String(), now, now)

	return db, projectID
}

func TestTaskEngine_CreatesFromInsight(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	// Create an insight first.
	insightID := uuid.New()
	now := time.Now().UTC().Format(time.RFC3339)
	db.Exec(`INSERT INTO insights (id, type, title, description, severity, project_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		insightID.String(), "admin_path", "Admin path detected: /admin",
		"URL contains '/admin'", "high", projectID.String(), now)

	// Publish insight.detected event.
	ruleID := "admin_path"
	eventBus.Publish(context.Background(), events.InsightDetected{
		BaseEvent: events.NewBaseEvent(),
		InsightID: insightID,
		Type:      "admin_path",
		Severity:  "high",
		EntityIDs: []uuid.UUID{uuid.New()},
		RuleID:    &ruleID,
	})
	eventBus.Drain()

	// Query tasks.
	tasks, err := engine.Query(context.Background(), projectID, "", 50)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	task := tasks[0]
	if task.Priority != PriorityHigh {
		t.Errorf("priority = %s, want high", task.Priority)
	}
	if task.Title != "Review admin interface access controls" {
		t.Errorf("unexpected title: %s", task.Title)
	}
	if task.InsightID == nil {
		t.Error("task should be linked to insight")
	}
}

func TestTaskEngine_PriorityOrdering(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	now := time.Now().UTC().Format(time.RFC3339)

	// Create insights with different severities.
	insightLow := uuid.New()
	insightHigh := uuid.New()
	db.Exec(`INSERT INTO insights (id, type, title, description, severity, project_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		insightLow.String(), "insecure_http", "Insecure HTTP", "desc", "medium", projectID.String(), now)
	db.Exec(`INSERT INTO insights (id, type, title, description, severity, project_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		insightHigh.String(), "admin_path", "Admin path", "desc", "high", projectID.String(), now)

	// Publish in "wrong" order — medium first, high second.
	ruleHTTP := "insecure_http"
	eventBus.Publish(context.Background(), events.InsightDetected{
		BaseEvent: events.NewBaseEvent(), InsightID: insightLow,
		Type: "insecure_http", Severity: "medium", EntityIDs: []uuid.UUID{uuid.New()},
		RuleID: &ruleHTTP,
	})
	ruleAdmin := "admin_path"
	eventBus.Publish(context.Background(), events.InsightDetected{
		BaseEvent: events.NewBaseEvent(), InsightID: insightHigh,
		Type: "admin_path", Severity: "high", EntityIDs: []uuid.UUID{uuid.New()},
		RuleID: &ruleAdmin,
	})
	eventBus.Drain()

	// Query — should be ordered by priority (high first).
	tasks, _ := engine.Query(context.Background(), projectID, "", 50)
	if len(tasks) < 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}

	if tasks[0].Priority != PriorityHigh {
		t.Errorf("first task should be high priority, got %s", tasks[0].Priority)
	}
}

func TestTaskEngine_FilterByStatus(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	now := time.Now().UTC().Format(time.RFC3339)
	insightID := uuid.New()
	db.Exec(`INSERT INTO insights (id, type, title, description, severity, project_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		insightID.String(), "api_endpoint", "API", "desc", "medium", projectID.String(), now)

	ruleAPI := "api_endpoint"
	eventBus.Publish(context.Background(), events.InsightDetected{
		BaseEvent: events.NewBaseEvent(), InsightID: insightID,
		Type: "api_endpoint", Severity: "medium", EntityIDs: []uuid.UUID{uuid.New()},
		RuleID: &ruleAPI,
	})
	eventBus.Drain()

	// Filter by "done" — should return nothing.
	tasks, _ := engine.Query(context.Background(), projectID, "done", 50)
	if len(tasks) != 0 {
		t.Errorf("expected 0 done tasks, got %d", len(tasks))
	}

	// Filter by "pending" — should return the task.
	tasks, _ = engine.Query(context.Background(), projectID, "pending", 50)
	if len(tasks) != 1 {
		t.Errorf("expected 1 pending task, got %d", len(tasks))
	}
}
