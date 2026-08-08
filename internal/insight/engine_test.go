package insight

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

func TestEngine_AdminPathRule(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	// Publish entity.created for an admin URL.
	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "https://example.com/admin/dashboard",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, err := engine.Query(context.Background(), projectID, 50)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	found := false
	for _, i := range insights {
		if i.RuleID == "admin_path" {
			found = true
			if i.Severity != SeverityHigh {
				t.Errorf("expected high severity, got %s", i.Severity)
			}
		}
	}
	if !found {
		t.Error("expected admin_path insight to be detected")
	}
}

func TestEngine_InsecureHTTPRule(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "http://staging.example.com",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, _ := engine.Query(context.Background(), projectID, 50)

	found := false
	for _, i := range insights {
		if i.RuleID == "insecure_http" {
			found = true
		}
	}
	if !found {
		t.Error("expected insecure_http insight to be detected")
	}
}

func TestEngine_APIEndpointRule(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "https://api.example.com/api/v1/users",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, _ := engine.Query(context.Background(), projectID, 50)

	found := false
	for _, i := range insights {
		if i.RuleID == "api_endpoint" {
			found = true
		}
	}
	if !found {
		t.Error("expected api_endpoint insight to be detected")
	}
}

func TestEngine_TechnologyRule(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "technology",
		Value:     "wordpress",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, _ := engine.Query(context.Background(), projectID, 50)
	found := false
	for _, i := range insights {
		if i.RuleID == "interesting_technology" {
			found = true
		}
	}
	if !found {
		t.Error("expected interesting_technology insight to be detected")
	}
}

func TestEngine_NoMatchForSafeEntity(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	// A normal URL that doesn't match any rule.
	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "https://www.example.com/about",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, _ := engine.Query(context.Background(), projectID, 50)
	if len(insights) != 0 {
		t.Errorf("expected no insights for safe URL, got %d", len(insights))
		for _, i := range insights {
			t.Logf("  unexpected: %s — %s", i.RuleID, i.Title)
		}
	}
}

func TestEngine_MultipleRulesMatch(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.Subscribe()

	// This URL matches both admin_path and auth_endpoint.
	eventBus.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  uuid.New(),
		Type:      "url",
		Value:     "https://example.com/admin/login",
		ProjectID: projectID,
	})
	eventBus.Drain()

	insights, _ := engine.Query(context.Background(), projectID, 50)
	if len(insights) < 2 {
		t.Errorf("expected at least 2 insights (admin_path + auth_endpoint), got %d", len(insights))
	}

	ruleIDs := map[string]bool{}
	for _, i := range insights {
		ruleIDs[i.RuleID] = true
	}
	if !ruleIDs["admin_path"] {
		t.Error("expected admin_path rule to match")
	}
	if !ruleIDs["auth_endpoint"] {
		t.Error("expected auth_endpoint rule to match")
	}
}
