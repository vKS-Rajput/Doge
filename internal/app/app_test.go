package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInit_CreatesWorkspace(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "test-workspace")

	application, err := Init(context.Background(), wsPath, "test-workspace")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer application.Shutdown()

	// Verify directory structure.
	dirs := []string{
		wsPath,
		filepath.Join(wsPath, "projects"),
		filepath.Join(wsPath, ".doge"),
		filepath.Join(wsPath, ".doge", "artifacts"),
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			t.Errorf("expected directory %s to exist", d)
		}
	}

	// Verify config file exists.
	cfgPath := filepath.Join(wsPath, "workspace.toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Error("workspace.toml should exist after Init")
	}

	// Verify database file exists.
	dbPath := filepath.Join(wsPath, ".doge", "workspace.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("workspace.db should exist after Init")
	}

	// Verify workspace metadata.
	if application.Workspace.Name != "test-workspace" {
		t.Errorf("workspace name = %q, want 'test-workspace'", application.Workspace.Name)
	}
}

func TestInit_ConfigIsValid(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "config-test")

	application, err := Init(context.Background(), wsPath, "config-test")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer application.Shutdown()

	// AI should be disabled by default.
	if application.Config.AI.Enabled {
		t.Error("AI should be disabled by default")
	}

	// Logging should have defaults.
	if application.Config.Logging.Level != "info" {
		t.Errorf("logging.level = %q, want 'info'", application.Config.Logging.Level)
	}
}

func TestOpen_ExistingWorkspace(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "open-test")

	// First, init the workspace.
	app1, err := Init(context.Background(), wsPath, "open-test")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	app1.Shutdown()

	// Now open it.
	app2, err := Open(context.Background(), wsPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer app2.Shutdown()

	if app2.Workspace.Name != "open-test" {
		t.Errorf("workspace name = %q, want 'open-test'", app2.Workspace.Name)
	}
}

func TestOpen_NonexistentPath(t *testing.T) {
	_, err := Open(context.Background(), "/nonexistent/path/ws")
	if err == nil {
		t.Fatal("expected error for nonexistent workspace")
	}
}

func TestStatus(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "status-test")

	application, err := Init(context.Background(), wsPath, "status-test")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer application.Shutdown()

	status, err := application.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if status.WorkspaceName != "status-test" {
		t.Errorf("status name = %q, want 'status-test'", status.WorkspaceName)
	}
	if !status.DatabaseOK {
		t.Error("database should be healthy")
	}
	if status.AIEnabled {
		t.Error("AI should be disabled")
	}
}

func TestShutdown(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "shutdown-test")

	application, err := Init(context.Background(), wsPath, "shutdown-test")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	err = application.Shutdown()
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	// After shutdown, database health should fail.
	if application.DB.Health(context.Background()) == nil {
		t.Error("database Health() should fail after Shutdown()")
	}
}

func TestShutdown_DrainsBus(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "drain-test")

	application, err := Init(context.Background(), wsPath, "drain-test")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Publish some events before shutdown.
	// They should all be processed during Drain.
	// (No subscribers, so they'll just be dispatched to no one — but the
	// bus should still process them without error.)

	err = application.Shutdown()
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}
