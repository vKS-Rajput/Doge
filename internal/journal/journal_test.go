package journal

import (
	"database/sql"
	"testing"
	"time"

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
	return db
}

func TestStoreRecord(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	if err := store.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	projectID := uuid.New()
	exec := &Execution{
		ID:          uuid.New(),
		Tool:        "nmap",
		Command:     "nmap -sCV target",
		Target:      "10.10.11.25",
		Observations: 17,
		ExitCode:    0,
		ProjectID:   projectID,
		StartedAt:   time.Now().Add(-30 * time.Second),
		CompletedAt: time.Now(),
		IngestedAt:  time.Now(),
	}

	if err := store.Record(exec); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Verify count.
	count, err := store.Count(projectID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	// Verify total observations.
	total, err := store.TotalObservations(projectID)
	if err != nil {
		t.Fatal(err)
	}
	if total != 17 {
		t.Errorf("total observations = %d, want 17", total)
	}
}

func TestStoreRecent(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	if err := store.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	projectID := uuid.New()
	now := time.Now()

	// Insert 5 entries.
	tools := []string{"nmap", "httpx", "katana", "ffuf", "nuclei"}
	for i, tool := range tools {
		exec := &Execution{
			ID:          uuid.New(),
			Tool:        tool,
			Target:      "target.com",
			Observations: (i + 1) * 10,
			ExitCode:    0,
			ProjectID:   projectID,
			StartedAt:   now.Add(time.Duration(i) * time.Minute),
			CompletedAt: now.Add(time.Duration(i)*time.Minute + 30*time.Second),
			IngestedAt:  now.Add(time.Duration(i) * time.Minute),
		}
		if err := store.Record(exec); err != nil {
			t.Fatal(err)
		}
	}

	// Get recent 3.
	recent, err := store.Recent(projectID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 3 {
		t.Fatalf("recent = %d entries, want 3", len(recent))
	}

	// Most recent first.
	if recent[0].Tool != "nuclei" {
		t.Errorf("recent[0].Tool = %q, want nuclei", recent[0].Tool)
	}
	if recent[2].Tool != "katana" {
		t.Errorf("recent[2].Tool = %q, want katana", recent[2].Tool)
	}
}

func TestStoreByTool(t *testing.T) {
	db := testDB(t)
	store := NewStore(db)
	if err := store.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	projectID := uuid.New()
	now := time.Now()

	// Insert mixed entries.
	for i, tool := range []string{"nmap", "httpx", "nmap", "katana", "nmap"} {
		exec := &Execution{
			ID:        uuid.New(),
			Tool:      tool,
			Target:    "target.com",
			ExitCode:  0,
			ProjectID: projectID,
			StartedAt:   now.Add(time.Duration(i) * time.Minute),
			CompletedAt: now.Add(time.Duration(i)*time.Minute + 10*time.Second),
			IngestedAt:  now.Add(time.Duration(i) * time.Minute),
		}
		if err := store.Record(exec); err != nil {
			t.Fatal(err)
		}
	}

	// Query nmap only.
	nmaps, err := store.ByTool(projectID, "nmap")
	if err != nil {
		t.Fatal(err)
	}
	if len(nmaps) != 3 {
		t.Errorf("nmap entries = %d, want 3", len(nmaps))
	}
}

func TestExecutionSummary(t *testing.T) {
	e := &Execution{
		Tool:         "nmap",
		Target:       "target.com",
		Observations: 17,
	}
	got := e.Summary()
	want := "nmap → target.com (17 observations)"
	if got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}
