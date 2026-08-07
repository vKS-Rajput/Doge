package entity

import (
	"context"
	"database/sql"
	"embed"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"

	_ "modernc.org/sqlite"
)

//go:embed testdata/schema.sql
var testSchema embed.FS

// setupTestDB creates an in-memory SQLite database with the entity
// and observation tables for testing.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	schema, err := testSchema.ReadFile("testdata/schema.sql")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		t.Fatalf("creating schema: %v", err)
	}

	return db
}

func setupTestStore(t *testing.T) (*Store, *bus.Bus, *sql.DB, uuid.UUID) {
	t.Helper()

	db := setupTestDB(t)
	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	store := NewStore(db, eventBus, logging.NewNop())

	// Create a test project.
	projectID := uuid.New()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`INSERT INTO projects (id, workspace_id, slug, name, status, created_at, updated_at)
		 VALUES (?, ?, 'test', 'Test Project', 'active', ?, ?)`,
		projectID.String(), uuid.New().String(), now, now)
	if err != nil {
		t.Fatal(err)
	}

	return store, eventBus, db, projectID
}

func TestStore_IngestCreatesEntity(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	observationID := uuid.New()
	result, err := store.Ingest(context.Background(), domain.EntityURL,
		"https://Example.COM:443/path",
		map[string]any{"status_code": 200},
		observationID, projectID, time.Now())
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}

	if !result.Created {
		t.Error("expected new entity to be created")
	}
	if result.Entity.Value != "https://example.com/path" {
		t.Errorf("value = %q, want canonical form 'https://example.com/path'", result.Entity.Value)
	}
	if result.Entity.Type != domain.EntityURL {
		t.Errorf("type = %q, want 'url'", result.Entity.Type)
	}
	if result.Entity.ObservationCount != 1 {
		t.Errorf("observation_count = %d, want 1", result.Entity.ObservationCount)
	}
}

func TestStore_IngestEnrichesExisting(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	obs1 := uuid.New()
	obs2 := uuid.New()

	// First ingest.
	result1, _ := store.Ingest(context.Background(), domain.EntityURL,
		"https://example.com",
		map[string]any{"status_code": 200},
		obs1, projectID, time.Now().Add(-time.Hour))

	// Second ingest — same entity, new attributes.
	result2, err := store.Ingest(context.Background(), domain.EntityURL,
		"https://EXAMPLE.COM:443/", // Different form, same canonical identity.
		map[string]any{"title": "Admin Panel"},
		obs2, projectID, time.Now())
	if err != nil {
		t.Fatalf("second Ingest() error = %v", err)
	}

	if result2.Created {
		t.Error("expected enrichment, not creation")
	}
	if result2.Entity.ID != result1.Entity.ID {
		t.Error("enriched entity should have same ID as original")
	}
	if result2.Entity.ObservationCount != 2 {
		t.Errorf("observation_count = %d, want 2", result2.Entity.ObservationCount)
	}

	// Check merged attributes.
	if result2.Entity.Attributes["status_code"] == nil {
		t.Error("original attribute 'status_code' should be preserved")
	}
	if result2.Entity.Attributes["title"] != "Admin Panel" {
		t.Error("new attribute 'title' should be added")
	}
}

func TestStore_IngestDifferentTypes(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	// Same value, different types → different entities.
	r1, _ := store.Ingest(context.Background(), domain.EntityURL,
		"example.com", map[string]any{}, uuid.New(), projectID, time.Now())

	r2, _ := store.Ingest(context.Background(), domain.EntityDomain,
		"example.com", map[string]any{}, uuid.New(), projectID, time.Now())

	if r1.Entity.ID == r2.Entity.ID {
		t.Error("different types should create different entities")
	}
}

func TestStore_Get(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	result, _ := store.Ingest(context.Background(), domain.EntityURL,
		"https://example.com", map[string]any{}, uuid.New(), projectID, time.Now())

	entity, err := store.Get(context.Background(), result.Entity.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if entity.ID != result.Entity.ID {
		t.Error("Get should return the same entity")
	}
}

func TestStore_Query(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	store.Ingest(context.Background(), domain.EntityURL,
		"https://admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	store.Ingest(context.Background(), domain.EntityURL,
		"https://api.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	store.Ingest(context.Background(), domain.EntityTechnology,
		"nginx", map[string]any{}, uuid.New(), projectID, time.Now())

	// Query by type.
	urlType := domain.EntityURL
	urls, err := store.Query(context.Background(), domain.EntityFilter{
		ProjectID: &projectID,
		Type:      &urlType,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(urls) != 2 {
		t.Errorf("expected 2 URL entities, got %d", len(urls))
	}

	// Query by value.
	results, _ := store.Query(context.Background(), domain.EntityFilter{
		ProjectID:     &projectID,
		ValueContains: "admin",
	})
	if len(results) != 1 {
		t.Errorf("expected 1 entity containing 'admin', got %d", len(results))
	}
}

func TestStore_IngestRelationship(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	// Create two entities.
	r1, _ := store.Ingest(context.Background(), domain.EntitySubdomain,
		"admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	r2, _ := store.Ingest(context.Background(), domain.EntityURL,
		"https://admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())

	// Create relationship.
	now := time.Now()
	rel := domain.Relationship{
		SourceEntityID: r1.Entity.ID,
		TargetEntityID: r2.Entity.ID,
		Type:           domain.RelServes,
		Attributes:     map[string]any{},
		ProjectID:      projectID,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}

	created, isNew, err := store.IngestRelationship(context.Background(), rel)
	if err != nil {
		t.Fatalf("IngestRelationship() error = %v", err)
	}
	if !isNew {
		t.Error("expected new relationship")
	}
	if created.ID == uuid.Nil {
		t.Error("relationship should have an ID")
	}

	// Second ingest of same relationship should update, not create.
	_, isNew2, err := store.IngestRelationship(context.Background(), rel)
	if err != nil {
		t.Fatalf("second IngestRelationship() error = %v", err)
	}
	if isNew2 {
		t.Error("expected update, not creation")
	}
}

func TestStore_GetRelationships(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	r1, _ := store.Ingest(context.Background(), domain.EntitySubdomain,
		"admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	r2, _ := store.Ingest(context.Background(), domain.EntityURL,
		"https://admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())

	now := time.Now()
	store.IngestRelationship(context.Background(), domain.Relationship{
		SourceEntityID: r1.Entity.ID,
		TargetEntityID: r2.Entity.ID,
		Type:           domain.RelServes,
		Attributes:     map[string]any{},
		ProjectID:      projectID,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	})

	// Outgoing from host.
	outgoing, err := store.GetRelationships(context.Background(), r1.Entity.ID, domain.DirectionOutgoing)
	if err != nil {
		t.Fatalf("GetRelationships() error = %v", err)
	}
	if len(outgoing) != 1 {
		t.Errorf("expected 1 outgoing relationship, got %d", len(outgoing))
	}

	// Incoming to URL.
	incoming, _ := store.GetRelationships(context.Background(), r2.Entity.ID, domain.DirectionIncoming)
	if len(incoming) != 1 {
		t.Errorf("expected 1 incoming relationship, got %d", len(incoming))
	}
}

func TestStore_Neighborhood(t *testing.T) {
	store, eventBus, _, projectID := setupTestStore(t)
	defer eventBus.Drain()

	// Create: host → serves → url → uses_technology → nginx
	rHost, _ := store.Ingest(context.Background(), domain.EntitySubdomain,
		"admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	rURL, _ := store.Ingest(context.Background(), domain.EntityURL,
		"https://admin.example.com", map[string]any{}, uuid.New(), projectID, time.Now())
	rTech, _ := store.Ingest(context.Background(), domain.EntityTechnology,
		"nginx", map[string]any{}, uuid.New(), projectID, time.Now())

	now := time.Now()
	store.IngestRelationship(context.Background(), domain.Relationship{
		SourceEntityID: rHost.Entity.ID, TargetEntityID: rURL.Entity.ID,
		Type: domain.RelServes, Attributes: map[string]any{},
		ProjectID: projectID, FirstSeenAt: now, LastSeenAt: now,
	})
	store.IngestRelationship(context.Background(), domain.Relationship{
		SourceEntityID: rURL.Entity.ID, TargetEntityID: rTech.Entity.ID,
		Type: domain.RelUsesTechnology, Attributes: map[string]any{},
		ProjectID: projectID, FirstSeenAt: now, LastSeenAt: now,
	})

	// Neighborhood depth 1 from URL.
	subgraph, err := store.Neighborhood(context.Background(), rURL.Entity.ID, 1)
	if err != nil {
		t.Fatalf("Neighborhood() error = %v", err)
	}

	// Should include URL (root), host, and nginx (1-hop neighbors).
	if len(subgraph.Entities) != 3 {
		t.Errorf("expected 3 entities in neighborhood, got %d", len(subgraph.Entities))
	}
	if len(subgraph.Relationships) != 2 {
		t.Errorf("expected 2 relationships in neighborhood, got %d", len(subgraph.Relationships))
	}
}

func TestMaterializer_HTTPProbe(t *testing.T) {
	store, eventBus, db, projectID := setupTestStore(t)

	materializer := NewMaterializer(store, db, eventBus, logging.NewNop())
	materializer.Subscribe()

	// Insert a test artifact.
	artifactID := uuid.New()
	now := time.Now().UTC()
	db.Exec(`INSERT INTO artifacts (id, sha256, original_path, stored_path, file_name,
		file_size, mime_type, imported_at, project_id, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID.String(), "abc123", "/test", "/test", "test.jsonl",
		100, "text/plain", now.Format(time.RFC3339), projectID.String(), 1)

	// Insert test observations (simulating what the parser + observation store would produce).
	obsID := uuid.New()
	db.Exec(`INSERT INTO observations (id, type, artifact_id, source_tool, project_id, data,
		raw_value, checksum, observed_at, ingested_at, parser_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		obsID.String(), "http_probe", artifactID.String(), "httpx", projectID.String(),
		`{"url":"https://admin.example.com","status_code":200,"host":"admin.example.com","technologies":["Nginx","PHP"]}`,
		`{"url":"https://admin.example.com"}`, "checksum1",
		now.Format(time.RFC3339), now.Format(time.RFC3339), "1.0.0")

	// Publish observation.batch event — this triggers materialization.
	eventBus.Publish(context.Background(), events.ObservationBatch{
		BaseEvent:      events.NewBaseEvent(),
		ObservationIDs: []uuid.UUID{obsID},
		Type:           "http_probe",
		ArtifactID:     artifactID,
		ProjectID:      projectID,
		Count:          1,
	})

	// Drain to ensure the event is processed.
	eventBus.Drain()

	// Verify entities were created.
	entities, err := store.Query(context.Background(), domain.EntityFilter{
		ProjectID: &projectID,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	// Should have: 1 URL + 1 subdomain + 2 technologies = 4 entities.
	if len(entities) != 4 {
		t.Errorf("expected 4 materialized entities, got %d", len(entities))
		for _, e := range entities {
			t.Logf("  entity: type=%s value=%s", e.Type, e.Value)
		}
	}

	// Verify relationships exist.
	urlType := domain.EntityURL
	urls, _ := store.Query(context.Background(), domain.EntityFilter{
		ProjectID: &projectID,
		Type:      &urlType,
	})
	if len(urls) > 0 {
		rels, _ := store.GetRelationships(context.Background(), urls[0].ID, domain.DirectionBoth)
		// URL should have: 1 incoming "serves" from host + 2 outgoing "uses_technology" = 3 rels.
		if len(rels) != 3 {
			t.Errorf("expected 3 relationships for URL entity, got %d", len(rels))
		}
	}
}
