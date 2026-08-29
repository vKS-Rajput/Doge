package journal

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Store persists journal entries to SQLite.
type Store struct {
	db *sql.DB
}

// NewStore creates a journal store. Call EnsureTable before first use.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// EnsureTable creates the journal table if it doesn't exist.
func (s *Store) EnsureTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS journal (
			id            TEXT PRIMARY KEY,
			tool          TEXT NOT NULL,
			command       TEXT DEFAULT '',
			target        TEXT NOT NULL,
			artifact_path TEXT DEFAULT '',
			artifact_id   TEXT DEFAULT '',
			observations  INTEGER DEFAULT 0,
			exit_code     INTEGER DEFAULT -1,
			notes         TEXT DEFAULT '',
			project_id    TEXT NOT NULL,
			started_at    DATETIME NOT NULL,
			completed_at  DATETIME NOT NULL,
			ingested_at   DATETIME NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("creating journal table: %w", err)
	}

	// Index for quick lookups.
	_, err = s.db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_journal_tool ON journal(tool);
		CREATE INDEX IF NOT EXISTS idx_journal_target ON journal(target);
		CREATE INDEX IF NOT EXISTS idx_journal_project ON journal(project_id);
	`)
	return err
}

// Record saves a journal entry.
func (s *Store) Record(exec *Execution) error {
	_, err := s.db.Exec(`
		INSERT INTO journal (id, tool, command, target, artifact_path, artifact_id,
			observations, exit_code, notes, project_id, started_at, completed_at, ingested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		exec.ID.String(),
		exec.Tool,
		exec.Command,
		exec.Target,
		exec.ArtifactPath,
		exec.ArtifactID.String(),
		exec.Observations,
		exec.ExitCode,
		exec.Notes,
		exec.ProjectID.String(),
		exec.StartedAt.Format(time.RFC3339),
		exec.CompletedAt.Format(time.RFC3339),
		exec.IngestedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("recording journal entry: %w", err)
	}
	return nil
}

// Recent returns the N most recent journal entries.
func (s *Store) Recent(projectID uuid.UUID, limit int) ([]Execution, error) {
	rows, err := s.db.Query(`
		SELECT id, tool, command, target, artifact_path, artifact_id,
			observations, exit_code, notes, project_id, started_at, completed_at, ingested_at
		FROM journal
		WHERE project_id = ?
		ORDER BY ingested_at DESC
		LIMIT ?
	`, projectID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("querying journal: %w", err)
	}
	defer rows.Close()

	return scanExecutions(rows)
}

// All returns all journal entries for a project, ordered by time.
func (s *Store) All(projectID uuid.UUID) ([]Execution, error) {
	rows, err := s.db.Query(`
		SELECT id, tool, command, target, artifact_path, artifact_id,
			observations, exit_code, notes, project_id, started_at, completed_at, ingested_at
		FROM journal
		WHERE project_id = ?
		ORDER BY ingested_at ASC
	`, projectID.String())
	if err != nil {
		return nil, fmt.Errorf("querying journal: %w", err)
	}
	defer rows.Close()

	return scanExecutions(rows)
}

// ByTool returns entries for a specific tool.
func (s *Store) ByTool(projectID uuid.UUID, tool string) ([]Execution, error) {
	rows, err := s.db.Query(`
		SELECT id, tool, command, target, artifact_path, artifact_id,
			observations, exit_code, notes, project_id, started_at, completed_at, ingested_at
		FROM journal
		WHERE project_id = ? AND tool = ?
		ORDER BY ingested_at DESC
	`, projectID.String(), tool)
	if err != nil {
		return nil, fmt.Errorf("querying journal by tool: %w", err)
	}
	defer rows.Close()

	return scanExecutions(rows)
}

// Count returns the total number of journal entries for a project.
func (s *Store) Count(projectID uuid.UUID) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM journal WHERE project_id = ?
	`, projectID.String()).Scan(&count)
	return count, err
}

// TotalObservations returns the total observations across all executions.
func (s *Store) TotalObservations(projectID uuid.UUID) (int, error) {
	var total int
	err := s.db.QueryRow(`
		SELECT COALESCE(SUM(observations), 0) FROM journal WHERE project_id = ?
	`, projectID.String()).Scan(&total)
	return total, err
}

func scanExecutions(rows *sql.Rows) ([]Execution, error) {
	var results []Execution
	for rows.Next() {
		var e Execution
		var id, artifactID, projectID string
		var startedAt, completedAt, ingestedAt string

		err := rows.Scan(
			&id, &e.Tool, &e.Command, &e.Target,
			&e.ArtifactPath, &artifactID,
			&e.Observations, &e.ExitCode, &e.Notes,
			&projectID, &startedAt, &completedAt, &ingestedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning journal row: %w", err)
		}

		e.ID, _ = uuid.Parse(id)
		e.ArtifactID, _ = uuid.Parse(artifactID)
		e.ProjectID, _ = uuid.Parse(projectID)
		e.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		e.CompletedAt, _ = time.Parse(time.RFC3339, completedAt)
		e.IngestedAt, _ = time.Parse(time.RFC3339, ingestedAt)

		results = append(results, e)
	}
	return results, rows.Err()
}
