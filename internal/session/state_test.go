package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSaveAndLoadState(t *testing.T) {
	wsPath := t.TempDir()
	dogeDir := filepath.Join(wsPath, ".doge")
	os.MkdirAll(dogeDir, 0755)

	state := PersistedState{
		InvestigationID: uuid.New(),
		Target:          "10.10.11.123",
		TargetType:      "ip",
		Environment:     "htb",
		Status:          StatusActive,
		Phase:           PhaseDiscovering,
		PhaseSummary:    "Running initial reconnaissance",
		StartedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		PID:             os.Getpid(),
		Observations:    42,
		Entities:        15,
		Correlations:    7,
		NoveltySignals:  3,
		Opportunities:   2,
		JobsQueued:      4,
		JobsRunning:     1,
		JobsCompleted:   12,
		JobsFailed:      1,
		AutoRecon:       true,
		WorkspacePath:   wsPath,
	}

	// Write state.
	path := filepath.Join(dogeDir, SessionFile)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Load state.
	loaded, err := LoadState(wsPath)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if loaded.Target != "10.10.11.123" {
		t.Errorf("target = %s, want 10.10.11.123", loaded.Target)
	}
	if loaded.Environment != "htb" {
		t.Errorf("environment = %s, want htb", loaded.Environment)
	}
	if loaded.Observations != 42 {
		t.Errorf("observations = %d, want 42", loaded.Observations)
	}
	if loaded.JobsCompleted != 12 {
		t.Errorf("jobs completed = %d, want 12", loaded.JobsCompleted)
	}
	if !loaded.AutoRecon {
		t.Error("auto_recon should be true")
	}
}

func TestLoadStateNotFound(t *testing.T) {
	wsPath := t.TempDir()
	_, err := LoadState(wsPath)
	if err == nil {
		t.Error("should fail when no session.json exists")
	}
}

func TestClearState(t *testing.T) {
	wsPath := t.TempDir()
	dogeDir := filepath.Join(wsPath, ".doge")
	os.MkdirAll(dogeDir, 0755)

	// Write a file.
	path := filepath.Join(dogeDir, SessionFile)
	os.WriteFile(path, []byte("{}"), 0644)

	if _, err := os.Stat(path); err != nil {
		t.Fatal("file should exist before clear")
	}

	ClearState(wsPath)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed after clear")
	}
}

func TestIsSessionRunning(t *testing.T) {
	// No session file.
	if IsSessionRunning(t.TempDir()) {
		t.Error("should return false when no session exists")
	}

	// Stale session.
	wsPath := t.TempDir()
	dogeDir := filepath.Join(wsPath, ".doge")
	os.MkdirAll(dogeDir, 0755)

	stale := PersistedState{
		Status:    StatusActive,
		UpdatedAt: time.Now().Add(-5 * time.Minute), // 5 minutes ago
		PID:       os.Getpid(),
	}
	data, _ := json.MarshalIndent(stale, "", "  ")
	os.WriteFile(filepath.Join(dogeDir, SessionFile), data, 0644)

	if IsSessionRunning(wsPath) {
		t.Error("should return false for stale session (5 min old)")
	}

	// Fresh session.
	fresh := PersistedState{
		Status:    StatusActive,
		UpdatedAt: time.Now(),
		PID:       os.Getpid(),
	}
	data, _ = json.MarshalIndent(fresh, "", "  ")
	os.WriteFile(filepath.Join(dogeDir, SessionFile), data, 0644)

	if !IsSessionRunning(wsPath) {
		t.Error("should return true for fresh active session")
	}
}
