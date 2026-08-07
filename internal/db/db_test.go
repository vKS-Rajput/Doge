package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_InMemory(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if database.Conn() == nil {
		t.Fatal("expected non-nil connection")
	}
}

func TestOpen_FileDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	database, err := Open(path, Options{WALMode: true, BusyTimeoutMs: 3000})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	// Verify file was created.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("database file should exist after Open()")
	}
}

func TestOpen_WALMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal_test.db")

	database, err := Open(path, Options{WALMode: true})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	// Verify WAL mode is active.
	var mode string
	err = database.Conn().QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatalf("PRAGMA journal_mode error = %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want 'wal'", mode)
	}
}

func TestOpen_ForeignKeysEnabled(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	var fk int
	err = database.Conn().QueryRow("PRAGMA foreign_keys").Scan(&fk)
	if err != nil {
		t.Fatalf("PRAGMA foreign_keys error = %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1 (enabled)", fk)
	}
}

func TestHealth(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := database.Health(context.Background()); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestHealth_AfterClose(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	database.Close()

	if err := database.Health(context.Background()); err == nil {
		t.Error("Health() should return error after Close()")
	}
}

func TestMigrate(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Verify migrations table has an entry.
	var count int
	err = database.Conn().QueryRow("SELECT COUNT(*) FROM migrations").Scan(&count)
	if err != nil {
		t.Fatalf("querying migrations count: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one migration record")
	}

	// Verify core tables exist by querying them.
	tables := []string{
		"projects", "artifacts", "observations", "entities",
		"relationships", "evidence", "correlations", "insights",
		"findings", "hypotheses", "tasks", "timeline_events",
		"snapshots", "diffs", "sessions", "reasoning_steps",
		"citations", "rules", "cache_entries", "embedding_metadata",
	}
	for _, table := range tables {
		var name string
		err := database.Conn().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q should exist after migration: %v", table, err)
		}
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	// Run migrations twice — should not fail.
	if err := database.Migrate(); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := database.Migrate(); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}

	// Should still have exactly one migration record.
	var count int
	err = database.Conn().QueryRow("SELECT COUNT(*) FROM migrations WHERE version = 1").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 migration record for version 1, got %d", count)
	}
}

func TestMigrate_VerifyIndexes(t *testing.T) {
	database, err := Open(":memory:", Options{WALMode: false})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Verify key indexes exist.
	indexes := []string{
		"idx_artifacts_project",
		"idx_observations_type",
		"idx_entities_type",
		"idx_entities_value",
		"idx_rel_source",
		"idx_evidence_claim",
		"idx_timeline_project",
		"idx_tasks_priority",
		"idx_sessions_project",
	}
	for _, idx := range indexes {
		var name string
		err := database.Conn().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("index %q should exist after migration: %v", idx, err)
		}
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close_test.db")

	database, err := Open(path, Options{WALMode: true})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	// Write some data to ensure WAL has content.
	if err := database.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// Close should not error.
	if err := database.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestLoadMigrations(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}

	if len(migrations) == 0 {
		t.Fatal("expected at least one embedded migration")
	}

	// Verify sorted by version.
	for i := 1; i < len(migrations); i++ {
		if migrations[i].version <= migrations[i-1].version {
			t.Errorf("migrations not sorted: version %d after %d",
				migrations[i].version, migrations[i-1].version)
		}
	}

	// First migration should be version 1.
	if migrations[0].version != 1 {
		t.Errorf("first migration version = %d, want 1", migrations[0].version)
	}
}
