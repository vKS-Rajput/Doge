package retriever

import (
	"context"
	"database/sql"
	"strings"
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
		CREATE TABLE relationships (
			id TEXT PRIMARY KEY, source_entity_id TEXT, target_entity_id TEXT,
			type TEXT, attributes TEXT DEFAULT '{}', observation_id TEXT,
			project_id TEXT, first_seen_at TEXT, last_seen_at TEXT,
			created_at TEXT, updated_at TEXT
		);
		CREATE TABLE observations (
			id TEXT PRIMARY KEY, type TEXT, artifact_id TEXT, source_tool TEXT,
			project_id TEXT, data TEXT DEFAULT '{}', raw_value TEXT,
			checksum TEXT, observed_at TEXT, ingested_at TEXT, parser_version TEXT
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
		CREATE TABLE timeline_events (
			id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
			subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
			summary TEXT NOT NULL, metadata TEXT DEFAULT '{}',
			project_id TEXT NOT NULL, occurred_at TEXT NOT NULL
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

func seedData(db *sql.DB, projectID uuid.UUID) {
	now := time.Now().UTC().Format(time.RFC3339)
	pid := projectID.String()

	// Entities.
	e1 := uuid.New().String()
	e2 := uuid.New().String()
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, attributes, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'url', 'https://admin.example.com', '{"status_code":200}', ?, 2, ?, ?, ?, ?)`,
		e1, e1, pid, now, now, now, now)
	db.Exec(`INSERT INTO entities (id, canonical_id, type, value, attributes, project_id, observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, 'technology', 'nginx', '{}', ?, 3, ?, ?, ?, ?)`,
		e2, e2, pid, now, now, now, now)

	// Relationship.
	db.Exec(`INSERT INTO relationships (id, source_entity_id, target_entity_id, type, attributes, project_id, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, ?, 'uses_technology', '{}', ?, ?, ?, ?, ?)`,
		uuid.New().String(), e1, e2, pid, now, now, now, now)

	// Observation.
	db.Exec(`INSERT INTO observations (id, type, artifact_id, source_tool, project_id, data, raw_value, checksum, observed_at, ingested_at, parser_version)
		VALUES (?, 'http_probe', ?, 'httpx', ?, '{}', '{"url":"https://admin.example.com"}', ?, ?, ?, '1.0.0')`,
		uuid.New().String(), uuid.New().String(), pid, uuid.New().String(), now, now)

	// Insight.
	db.Exec(`INSERT INTO insights (id, type, title, description, severity, project_id, detected_at)
		VALUES (?, 'admin_path', 'Admin path detected: admin.example.com', 'URL contains /admin', 'high', ?, ?)`,
		uuid.New().String(), pid, now)

	// Task.
	db.Exec(`INSERT INTO tasks (id, title, description, type, priority, status, project_id, created_at)
		VALUES (?, 'Review admin interface', 'Check authentication on admin endpoint', 'admin_path', 'high', 'pending', ?, ?)`,
		uuid.New().String(), pid, now)

	// Timeline event.
	db.Exec(`INSERT INTO timeline_events (id, event_type, subject_type, subject_id, summary, project_id, occurred_at)
		VALUES (?, 'entity.created', 'entity', ?, 'Discovered url: https://admin.example.com', ?, ?)`,
		uuid.New().String(), e1, pid, now)
}

func TestRetrieve_AdminQuestion(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedData(db, projectID)

	r := New(db, logging.NewNop())
	bundle, err := r.Retrieve(context.Background(), "What admin endpoints exist?", projectID, Options{MaxEvidence: 50})
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if len(bundle.Evidence) == 0 {
		t.Fatal("expected evidence, got none")
	}

	// Should find entity, insight, task, observation, timeline.
	types := map[string]bool{}
	for _, e := range bundle.Evidence {
		types[string(e.Type)] = true
	}

	if !types["entity"] {
		t.Error("expected entity evidence")
	}
	if !types["insight"] {
		t.Error("expected insight evidence")
	}
	if !types["task"] {
		t.Error("expected task evidence")
	}
}

func TestRetrieve_TechnologyQuestion(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedData(db, projectID)

	r := New(db, logging.NewNop())
	bundle, err := r.Retrieve(context.Background(), "Is nginx being used?", projectID, Options{MaxEvidence: 50})
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	found := false
	for _, e := range bundle.Evidence {
		if e.Type == EvidenceEntity && strings.Contains(e.Summary, "nginx") {
			found = true
		}
	}
	if !found {
		t.Error("expected to find nginx entity")
		for _, e := range bundle.Evidence {
			t.Logf("  %s: %s", e.Type, e.Summary)
		}
	}
}

func TestRetrieve_EmptyQuestion(t *testing.T) {
	db, projectID := setupTestDB(t)

	r := New(db, logging.NewNop())
	bundle, err := r.Retrieve(context.Background(), "", projectID, Options{})
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if len(bundle.Evidence) != 0 {
		t.Errorf("expected 0 evidence for empty question, got %d", len(bundle.Evidence))
	}
}

func TestRetrieve_Dedup(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedData(db, projectID)

	r := New(db, logging.NewNop())
	// "admin example" has two keywords that both match the admin entity.
	bundle, _ := r.Retrieve(context.Background(), "admin example", projectID, Options{MaxEvidence: 50})

	// Count entity IDs — should be deduped.
	entityIDs := map[string]int{}
	for _, e := range bundle.Evidence {
		if e.Type == EvidenceEntity {
			entityIDs[e.ID]++
		}
	}
	for id, count := range entityIDs {
		if count > 1 {
			t.Errorf("entity %s appeared %d times (should be 1)", id[:8], count)
		}
	}
}

func TestRetrieve_BundleSummary(t *testing.T) {
	db, projectID := setupTestDB(t)
	seedData(db, projectID)

	r := New(db, logging.NewNop())
	bundle, _ := r.Retrieve(context.Background(), "admin", projectID, Options{MaxEvidence: 50})

	summary := bundle.Summary()
	if summary == "No evidence found" {
		t.Error("expected non-empty summary")
	}
}

func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		question string
		want     []string
	}{
		{"What admin endpoints exist?", []string{"admin", "endpoints", "exist"}},
		{"Show me nginx servers", []string{"nginx", "servers"}},
		{"", nil},
		{"the a an is", nil},
	}

	for _, tt := range tests {
		got := extractKeywords(tt.question)
		if len(got) != len(tt.want) {
			t.Errorf("extractKeywords(%q) = %v, want %v", tt.question, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("extractKeywords(%q)[%d] = %q, want %q", tt.question, i, got[i], tt.want[i])
			}
		}
	}
}
