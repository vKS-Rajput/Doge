package coverage

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Create minimal schema needed for coverage queries.
	_, err = db.Exec(`
		CREATE TABLE observations (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			source_tool TEXT NOT NULL DEFAULT '',
			project_id TEXT NOT NULL,
			data TEXT DEFAULT '{}',
			raw_value TEXT DEFAULT '',
			checksum TEXT DEFAULT '',
			observed_at DATETIME,
			ingested_at DATETIME,
			parser_version TEXT DEFAULT ''
		);
		CREATE TABLE entities (
			id TEXT PRIMARY KEY,
			canonical_id TEXT,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			project_id TEXT NOT NULL,
			attributes TEXT DEFAULT '{}',
			first_seen DATETIME,
			last_seen DATETIME,
			created_at DATETIME
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func insertObs(t *testing.T, db *sql.DB, projectID uuid.UUID, obsType string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		_, err := db.Exec(`
			INSERT INTO observations (id, type, project_id) VALUES (?, ?, ?)
		`, uuid.New().String(), obsType, projectID.String())
		if err != nil {
			t.Fatal(err)
		}
	}
}

func insertEntity(t *testing.T, db *sql.DB, projectID uuid.UUID, entType, value string) {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO entities (id, canonical_id, type, value, project_id)
		VALUES (?, ?, ?, ?, ?)
	`, id.String(), id.String(), entType, value, projectID.String())
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmptyCoverage(t *testing.T) {
	db := testDB(t)
	engine := NewEngine(db)
	projectID := uuid.New()

	report, err := engine.Analyze(projectID)
	if err != nil {
		t.Fatal(err)
	}

	if report.TotalScore != 0 {
		t.Errorf("empty project score = %f, want 0", report.TotalScore)
	}
	if report.TotalObservations != 0 {
		t.Errorf("empty project observations = %d, want 0", report.TotalObservations)
	}
	if len(report.Categories) != 8 {
		t.Errorf("categories = %d, want 8", len(report.Categories))
	}
}

func TestDiscoveryCoverage(t *testing.T) {
	db := testDB(t)
	engine := NewEngine(db)
	projectID := uuid.New()

	// Insert port scan observations.
	insertObs(t, db, projectID, "port_scan", 15)

	report, err := engine.Analyze(projectID)
	if err != nil {
		t.Fatal(err)
	}

	// Find discovery category.
	var discovery CategoryCoverage
	for _, c := range report.Categories {
		if c.Category == CategoryDiscovery {
			discovery = c
			break
		}
	}

	if discovery.Score == 0 {
		t.Error("discovery score should be > 0 after port scans")
	}
	if discovery.Evidence != 15 {
		t.Errorf("discovery evidence = %d, want 15", discovery.Evidence)
	}
}

func TestWebMappingCoverage(t *testing.T) {
	db := testDB(t)
	engine := NewEngine(db)
	projectID := uuid.New()

	// Insert HTTP probes and endpoints.
	insertObs(t, db, projectID, "http_probe", 10)
	insertObs(t, db, projectID, "endpoint_discovery", 25)

	for i := 0; i < 30; i++ {
		insertEntity(t, db, projectID, "endpoint", "/api/endpoint-"+uuid.New().String()[:4])
	}

	report, err := engine.Analyze(projectID)
	if err != nil {
		t.Fatal(err)
	}

	var webMapping CategoryCoverage
	for _, c := range report.Categories {
		if c.Category == CategoryWebMapping {
			webMapping = c
			break
		}
	}

	if webMapping.Score == 0 {
		t.Error("web mapping score should be > 0")
	}
	if webMapping.Total != 30 {
		t.Errorf("web mapping total = %d, want 30", webMapping.Total)
	}
}

func TestTotalScoreWeighted(t *testing.T) {
	db := testDB(t)
	engine := NewEngine(db)
	projectID := uuid.New()

	// Add extensive evidence across categories.
	insertObs(t, db, projectID, "port_scan", 20)
	insertObs(t, db, projectID, "http_probe", 50)
	insertObs(t, db, projectID, "endpoint_discovery", 100)
	insertObs(t, db, projectID, "technology_detection", 10)

	for i := 0; i < 60; i++ {
		insertEntity(t, db, projectID, "endpoint", "/path-"+uuid.New().String()[:4])
	}
	for i := 0; i < 8; i++ {
		insertEntity(t, db, projectID, "technology", "tech-"+uuid.New().String()[:4])
	}

	report, err := engine.Analyze(projectID)
	if err != nil {
		t.Fatal(err)
	}

	if report.TotalScore <= 0 {
		t.Error("total score should be positive with evidence")
	}
	if report.TotalObservations != 180 {
		t.Errorf("total observations = %d, want 180", report.TotalObservations)
	}
}
