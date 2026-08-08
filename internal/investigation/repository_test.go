package investigation

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Minimal schema for investigation tests.
	schema := `
		CREATE TABLE projects (id TEXT PRIMARY KEY, workspace_id TEXT, slug TEXT, name TEXT);
		CREATE TABLE entities (id TEXT PRIMARY KEY, type TEXT, value TEXT, project_id TEXT);

		CREATE TABLE investigations (
			id TEXT PRIMARY KEY, title TEXT NOT NULL, objective TEXT DEFAULT '',
			status TEXT DEFAULT 'active', target_ids TEXT DEFAULT '[]',
			conclusions TEXT DEFAULT '[]', notes TEXT DEFAULT '',
			project_id TEXT NOT NULL, created_at TEXT, updated_at TEXT, concluded_at TEXT
		);
		CREATE TABLE tested_surfaces (
			id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL,
			entity_id TEXT, category TEXT NOT NULL, status TEXT DEFAULT 'untested',
			evidence_ids TEXT DEFAULT '[]', notes TEXT DEFAULT '',
			project_id TEXT NOT NULL, tested_at TEXT, created_at TEXT, updated_at TEXT,
			UNIQUE(investigation_id, entity_id, category)
		);
		CREATE TABLE hypotheses (
			id TEXT PRIMARY KEY, title TEXT, description TEXT, type TEXT, status TEXT,
			confidence REAL, entity_ids TEXT DEFAULT '[]',
			supporting_evidence TEXT DEFAULT '[]', refuting_evidence TEXT DEFAULT '[]',
			notes TEXT, project_id TEXT, proposed_by TEXT, created_at TEXT, updated_at TEXT,
			resolved_at TEXT, investigation_id TEXT
		);
		CREATE TABLE tasks (
			id TEXT PRIMARY KEY, title TEXT, description TEXT, type TEXT, priority TEXT,
			risk REAL, confidence REAL, evidence_count INTEGER, estimated_effort TEXT,
			status TEXT, entity_ids TEXT DEFAULT '[]', insight_id TEXT, hypothesis_id TEXT,
			project_id TEXT, created_at TEXT, updated_at TEXT, completed_at TEXT,
			investigation_id TEXT
		);
		CREATE TABLE findings (
			id TEXT PRIMARY KEY, title TEXT, description TEXT, severity TEXT, status TEXT,
			entity_ids TEXT DEFAULT '[]', evidence_ids TEXT DEFAULT '[]',
			hypothesis_id TEXT, notes TEXT, project_id TEXT, created_at TEXT, updated_at TEXT,
			confirmed_at TEXT, investigation_id TEXT
		);
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY, type TEXT, question TEXT,
			context_snapshot TEXT DEFAULT '[]', tokens_used INTEGER, model_used TEXT,
			raw_response TEXT, verified_response TEXT, rejected INTEGER,
			rejection_reason TEXT, project_id TEXT, duration_ms INTEGER,
			created_at TEXT, completed_at TEXT, investigation_id TEXT
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	// Insert test project.
	projectID := uuid.New()
	_, err = db.Exec("INSERT INTO projects (id, workspace_id, slug, name) VALUES (?, ?, 'test', 'Test')",
		projectID.String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func testProjectID(db *sql.DB) uuid.UUID {
	var id string
	db.QueryRow("SELECT id FROM projects LIMIT 1").Scan(&id)
	return uuid.MustParse(id)
}

func newTestRepo(t *testing.T, db *sql.DB) *Repository {
	eventBus := bus.New(bus.Options{Logger: slog.Default()})
	return New(db, eventBus, slog.Default())
}

func TestCreateAndGetInvestigation(t *testing.T) {
	db := setupTestDB(t)
	repo := newTestRepo(t, db)
	ctx := context.Background()
	projectID := testProjectID(db)

	inv := &domain.Investigation{
		Title:     "Admin Interface Security",
		Objective: "Assess admin panel for auth bypass",
		ProjectID: projectID,
	}

	if err := repo.Create(ctx, inv); err != nil {
		t.Fatal(err)
	}

	if inv.ID == uuid.Nil {
		t.Error("investigation ID should be set")
	}
	if inv.Status != domain.InvestigationActive {
		t.Errorf("expected active, got %s", inv.Status)
	}

	// Retrieve it.
	got, err := repo.Get(ctx, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Admin Interface Security" {
		t.Errorf("expected title 'Admin Interface Security', got '%s'", got.Title)
	}
	if got.Objective != "Assess admin panel for auth bypass" {
		t.Errorf("expected objective, got '%s'", got.Objective)
	}
}

func TestListInvestigations(t *testing.T) {
	db := setupTestDB(t)
	repo := newTestRepo(t, db)
	ctx := context.Background()
	projectID := testProjectID(db)

	repo.Create(ctx, &domain.Investigation{Title: "Investigation A", ProjectID: projectID})
	repo.Create(ctx, &domain.Investigation{Title: "Investigation B", ProjectID: projectID})

	investigations, err := repo.List(ctx, domain.InvestigationFilter{ProjectID: &projectID})
	if err != nil {
		t.Fatal(err)
	}
	if len(investigations) != 2 {
		t.Errorf("expected 2 investigations, got %d", len(investigations))
	}
}

func TestConcludeInvestigation(t *testing.T) {
	db := setupTestDB(t)
	repo := newTestRepo(t, db)
	ctx := context.Background()
	projectID := testProjectID(db)

	inv := &domain.Investigation{Title: "Temp", ProjectID: projectID}
	repo.Create(ctx, inv)

	now := time.Now().UTC()
	status := domain.InvestigationConcluded
	err := repo.Update(ctx, inv.ID, domain.InvestigationUpdate{
		Status:      &status,
		ConcludedAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify concluded investigation is immutable.
	newObj := "new objective"
	err = repo.Update(ctx, inv.ID, domain.InvestigationUpdate{Objective: &newObj})
	if err == nil {
		t.Error("expected error when modifying concluded investigation")
	}
}

func TestConclusionRequiresProvenance(t *testing.T) {
	db := setupTestDB(t)
	repo := newTestRepo(t, db)
	ctx := context.Background()
	projectID := testProjectID(db)

	inv := &domain.Investigation{Title: "Test", ProjectID: projectID}
	repo.Create(ctx, inv)

	// Conclusion without provenance should fail.
	err := repo.AddConclusion(ctx, inv.ID, domain.Conclusion{
		Text:   "Admin is safe",
		Status: domain.ConclusionConfirmed,
		Author: "researcher",
		// No EvidenceIDs or FindingIDs — should fail.
	})
	if err == nil {
		t.Error("expected error for conclusion without provenance")
	}

	// Conclusion with provenance should succeed.
	err = repo.AddConclusion(ctx, inv.ID, domain.Conclusion{
		Text:        "Admin requires authentication",
		Status:      domain.ConclusionConfirmed,
		EvidenceIDs: []string{"e0000001"},
		Author:      "researcher",
	})
	if err != nil {
		t.Errorf("valid conclusion should succeed: %v", err)
	}

	// Verify it was stored.
	got, _ := repo.Get(ctx, inv.ID)
	if len(got.Conclusions) != 1 {
		t.Errorf("expected 1 conclusion, got %d", len(got.Conclusions))
	}
}

func TestTestedSurfaces(t *testing.T) {
	db := setupTestDB(t)
	repo := newTestRepo(t, db)
	ctx := context.Background()
	projectID := testProjectID(db)

	inv := &domain.Investigation{Title: "Surface Test", ProjectID: projectID}
	repo.Create(ctx, inv)

	// Register surfaces.
	auth := &domain.TestedSurface{InvestigationID: inv.ID, Category: "authentication", ProjectID: projectID}
	authz := &domain.TestedSurface{InvestigationID: inv.ID, Category: "authorization", ProjectID: projectID}
	upload := &domain.TestedSurface{InvestigationID: inv.ID, Category: "file_upload", ProjectID: projectID}

	repo.CreateSurface(ctx, auth)
	repo.CreateSurface(ctx, authz)
	repo.CreateSurface(ctx, upload)

	// Mark one as tested.
	repo.MarkSurfaceTested(ctx, auth.ID, []string{"e001"})

	// List and verify.
	surfaces, err := repo.ListSurfaces(ctx, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(surfaces) != 3 {
		t.Errorf("expected 3 surfaces, got %d", len(surfaces))
	}

	var testedCount, untestedCount int
	for _, s := range surfaces {
		if s.Status == domain.SurfaceTested {
			testedCount++
		} else {
			untestedCount++
		}
	}
	if testedCount != 1 {
		t.Errorf("expected 1 tested, got %d", testedCount)
	}
	if untestedCount != 2 {
		t.Errorf("expected 2 untested, got %d", untestedCount)
	}
}

func TestFindingRequiresEvidence(t *testing.T) {
	// Domain-level validation.
	noEvidence := domain.Finding{Title: "IDOR found"}
	if err := domain.ValidateFinding(noEvidence); err == nil {
		t.Error("expected error for finding without evidence")
	}

	withEvidence := domain.Finding{Title: "IDOR found", EvidenceIDs: []uuid.UUID{uuid.New()}}
	if err := domain.ValidateFinding(withEvidence); err != nil {
		t.Errorf("finding with evidence should be valid: %v", err)
	}
}
