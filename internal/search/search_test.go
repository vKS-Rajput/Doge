package search

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
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
		CREATE TABLE observations (
			id TEXT PRIMARY KEY, type TEXT, artifact_id TEXT, source_tool TEXT,
			project_id TEXT, data TEXT DEFAULT '{}', raw_value TEXT,
			checksum TEXT, observed_at TEXT, ingested_at TEXT, parser_version TEXT,
			UNIQUE(checksum, project_id)
		);
		CREATE TABLE artifacts (
			id TEXT PRIMARY KEY, sha256 TEXT, original_path TEXT, stored_path TEXT,
			file_name TEXT, file_size INTEGER DEFAULT 0, mime_type TEXT DEFAULT '',
			parser_used TEXT DEFAULT '', imported_at TEXT, project_id TEXT,
			version INTEGER DEFAULT 1, metadata TEXT DEFAULT '{}'
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

func seedTestData(t *testing.T, db *sql.DB, projectID uuid.UUID) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	artID := uuid.New()

	// Entities.
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'url', 'https://admin.example.com', ?, 5, ?, ?, ?, ?)`,
		uuid.New().String(), uuid.New().String(), projectID.String(), now, now, now, now)
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'technology', 'nginx', ?, 3, ?, ?, ?, ?)`,
		uuid.New().String(), uuid.New().String(), projectID.String(), now, now, now, now)

	// Artifacts.
	db.Exec(`INSERT INTO artifacts (id, sha256, original_path, stored_path, file_name, file_size, mime_type, imported_at, project_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artID.String(), "abc", "/test", "/test", "httpx_admin.jsonl", 1024, "text/plain", now, projectID.String())

	// Observations.
	db.Exec(`INSERT INTO observations (id, type, artifact_id, source_tool, project_id, raw_value, checksum, observed_at, ingested_at, parser_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), "http_probe", artID.String(), "httpx", projectID.String(),
		`{"url":"https://admin.example.com","status_code":200}`, "chk1", now, now, "1.0.0")
}

func TestSearch_Entities(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedTestData(t, db, projectID)

	engine := NewEngine(db, logging.NewNop())
	results, err := engine.Search(context.Background(), "admin", Options{
		ProjectID: &projectID,
		Types:     []ResultType{ResultEntity},
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 entity result, got %d", len(results))
	}
	if results[0].Type != ResultEntity {
		t.Errorf("type = %s, want entity", results[0].Type)
	}
}

func TestSearch_AllTypes(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedTestData(t, db, projectID)

	engine := NewEngine(db, logging.NewNop())
	results, err := engine.Search(context.Background(), "admin", Options{
		ProjectID: &projectID,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// Should find: entity (admin.example.com), observation (raw_value contains admin),
	// artifact (httpx_admin.jsonl).
	if len(results) < 3 {
		t.Errorf("expected at least 3 results across types, got %d", len(results))
		for _, r := range results {
			t.Logf("  %s: %s", r.Type, r.Title)
		}
	}

	// Entity should be ranked higher (more evidence).
	if results[0].Type != ResultEntity {
		t.Errorf("highest ranked result should be entity, got %s", results[0].Type)
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	db, _ := setupTestDB(t)
	engine := NewEngine(db, logging.NewNop())

	results, err := engine.Search(context.Background(), "", Options{})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty query, got %d", len(results))
	}
}

func TestSearch_NoResults(t *testing.T) {
	db, projectID := setupTestDB(t)
	engine := NewEngine(db, logging.NewNop())

	results, err := engine.Search(context.Background(), "nonexistent", Options{
		ProjectID: &projectID,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_Ranking(t *testing.T) {
	db, projectID := setupTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)

	// Entity with high observation count should rank higher.
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'url', 'https://example.com/login', ?, 10, ?, ?, ?, ?)`,
		uuid.New().String(), uuid.New().String(), projectID.String(), now, now, now, now)
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'url', 'https://example.com/logout', ?, 1, ?, ?, ?, ?)`,
		uuid.New().String(), uuid.New().String(), projectID.String(), now, now, now, now)

	engine := NewEngine(db, logging.NewNop())
	results, _ := engine.Search(context.Background(), "example.com", Options{
		ProjectID: &projectID,
		Types:     []ResultType{ResultEntity},
	})

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	// Higher observation count → higher score → ranked first.
	if results[0].Score < results[1].Score {
		t.Error("entity with more observations should be ranked higher")
	}
}
