package diff

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/logging"

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
		CREATE TABLE entities (
			id TEXT PRIMARY KEY, canonical_id TEXT, type TEXT, value TEXT,
			attributes TEXT DEFAULT '{}', project_id TEXT, observation_count INTEGER DEFAULT 0,
			first_seen_at TEXT, last_seen_at TEXT, created_at TEXT, updated_at TEXT,
			UNIQUE(type, value, project_id)
		);
		CREATE TABLE relationships (
			id TEXT PRIMARY KEY, source_entity_id TEXT, target_entity_id TEXT,
			type TEXT, attributes TEXT DEFAULT '{}', observation_id TEXT,
			project_id TEXT, first_seen_at TEXT, last_seen_at TEXT,
			created_at TEXT, updated_at TEXT,
			UNIQUE(source_entity_id, target_entity_id, type, project_id)
		);
		CREATE TABLE observations (
			id TEXT PRIMARY KEY, type TEXT, artifact_id TEXT, source_tool TEXT,
			project_id TEXT, data TEXT DEFAULT '{}', raw_value TEXT,
			checksum TEXT, observed_at TEXT, ingested_at TEXT, parser_version TEXT,
			UNIQUE(checksum, project_id)
		);
		CREATE TABLE snapshots (
			id TEXT PRIMARY KEY, label TEXT, entity_count INTEGER DEFAULT 0,
			relationship_count INTEGER DEFAULT 0, observation_count INTEGER DEFAULT 0,
			entity_hashes TEXT DEFAULT '{}', project_id TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE diffs (
			id TEXT PRIMARY KEY, snapshot_a_id TEXT, snapshot_b_id TEXT,
			entities_added TEXT DEFAULT '[]', entities_removed TEXT DEFAULT '[]',
			entities_changed TEXT DEFAULT '[]', summary TEXT DEFAULT '',
			project_id TEXT NOT NULL, computed_at TEXT NOT NULL
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

func insertEntity(db *sql.DB, projectID uuid.UUID, entityType, value, attrs string) {
	now := time.Now().UTC().Format(time.RFC3339)
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, attributes, project_id,
		observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		uuid.New().String(), uuid.New().String(), entityType, value, attrs,
		projectID.String(), now, now, now, now)
}

func TestTakeSnapshot(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{"status_code":200}`)
	insertEntity(db, projectID, "technology", "nginx", `{}`)

	engine := NewEngine(db, eventBus, logging.NewNop())
	snap, err := engine.TakeSnapshot(context.Background(), projectID, "initial")
	if err != nil {
		t.Fatalf("TakeSnapshot() error = %v", err)
	}

	if snap.Label != "initial" {
		t.Errorf("label = %q, want 'initial'", snap.Label)
	}
	if snap.EntityCount != 2 {
		t.Errorf("entity_count = %d, want 2", snap.EntityCount)
	}
}

func TestDiff_NoChanges(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{}`)

	engine := NewEngine(db, eventBus, logging.NewNop())

	// Take same snapshot twice — no changes.
	snapA, _ := engine.TakeSnapshot(context.Background(), projectID, "before")
	snapB, _ := engine.TakeSnapshot(context.Background(), projectID, "after")

	result, err := engine.ComputeDiff(context.Background(), snapA.ID, snapB.ID)
	if err != nil {
		t.Fatalf("ComputeDiff() error = %v", err)
	}

	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(result.Removed))
	}
}

func TestDiff_AddedEntities(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{}`)

	engine := NewEngine(db, eventBus, logging.NewNop())
	snapA, _ := engine.TakeSnapshot(context.Background(), projectID, "before")

	// Add new entities.
	insertEntity(db, projectID, "technology", "nginx", `{}`)
	insertEntity(db, projectID, "subdomain", "admin.example.com", `{}`)

	snapB, _ := engine.TakeSnapshot(context.Background(), projectID, "after")

	result, err := engine.ComputeDiff(context.Background(), snapA.ID, snapB.ID)
	if err != nil {
		t.Fatalf("ComputeDiff() error = %v", err)
	}

	if len(result.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(result.Removed))
	}
}

func TestDiff_RemovedEntities(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{}`)
	insertEntity(db, projectID, "technology", "nginx", `{}`)

	engine := NewEngine(db, eventBus, logging.NewNop())
	snapA, _ := engine.TakeSnapshot(context.Background(), projectID, "before")

	// Remove entity.
	db.Exec(`DELETE FROM entities WHERE type = 'technology'`)

	snapB, _ := engine.TakeSnapshot(context.Background(), projectID, "after")

	result, err := engine.ComputeDiff(context.Background(), snapA.ID, snapB.ID)
	if err != nil {
		t.Fatalf("ComputeDiff() error = %v", err)
	}

	if len(result.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(result.Removed))
	}
	if len(result.Removed) > 0 && result.Removed[0].Value != "nginx" {
		t.Errorf("removed entity = %q, want 'nginx'", result.Removed[0].Value)
	}
}

func TestDiff_ChangedEntities(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{"status_code":200}`)

	engine := NewEngine(db, eventBus, logging.NewNop())
	snapA, _ := engine.TakeSnapshot(context.Background(), projectID, "before")

	// Change attributes.
	db.Exec(`UPDATE entities SET attributes = '{"status_code":403,"title":"Forbidden"}' WHERE type = 'url'`)

	snapB, _ := engine.TakeSnapshot(context.Background(), projectID, "after")

	result, err := engine.ComputeDiff(context.Background(), snapA.ID, snapB.ID)
	if err != nil {
		t.Fatalf("ComputeDiff() error = %v", err)
	}

	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed, got %d", len(result.Changed))
	}
}

func TestDiff_MixedChanges(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	insertEntity(db, projectID, "url", "https://example.com", `{"status_code":200}`)
	insertEntity(db, projectID, "technology", "apache", `{}`)

	engine := NewEngine(db, eventBus, logging.NewNop())
	snapA, _ := engine.TakeSnapshot(context.Background(), projectID, "before")

	// Remove apache, add nginx, change URL attributes.
	db.Exec(`DELETE FROM entities WHERE value = 'apache'`)
	insertEntity(db, projectID, "technology", "nginx", `{}`)
	db.Exec(`UPDATE entities SET attributes = '{"status_code":301}' WHERE value = 'https://example.com'`)

	snapB, _ := engine.TakeSnapshot(context.Background(), projectID, "after")

	result, _ := engine.ComputeDiff(context.Background(), snapA.ID, snapB.ID)

	if len(result.Added) != 1 {
		t.Errorf("expected 1 added (nginx), got %d", len(result.Added))
	}
	if len(result.Removed) != 1 {
		t.Errorf("expected 1 removed (apache), got %d", len(result.Removed))
	}
	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed (url), got %d", len(result.Changed))
	}

	if result.Summary() != "+1 added, -1 removed, ~1 changed" {
		t.Errorf("unexpected summary: %s", result.Summary())
	}
}

func TestListSnapshots(t *testing.T) {
	db, projectID := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()
	defer eventBus.Drain()

	engine := NewEngine(db, eventBus, logging.NewNop())
	engine.TakeSnapshot(context.Background(), projectID, "snap-1")
	engine.TakeSnapshot(context.Background(), projectID, "snap-2")

	snapshots, err := engine.ListSnapshots(context.Background(), projectID)
	if err != nil {
		t.Fatalf("ListSnapshots() error = %v", err)
	}
	if len(snapshots) != 2 {
		t.Errorf("expected 2 snapshots, got %d", len(snapshots))
	}
}
