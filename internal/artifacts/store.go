// Package artifacts provides content-addressable artifact storage.
//
// The Artifact Store is the intake point for all external data entering
// the workspace. Every file — whether dropped in a watched directory,
// imported via CLI, or piped through stdin — passes through here.
//
// Responsibilities:
//   - Copy file content to content-addressable storage (SHA256 paths)
//   - Calculate hashes (SHA256) and detect MIME type
//   - Deduplicate by content hash within a project
//   - Persist artifact metadata in the database
//   - Emit artifact.stored / artifact.duplicate events via the Event Bus
//
// The Store does NOT parse files. Parsing is the Parser Registry's job.
package artifacts

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Store manages content-addressable artifact storage.
type Store struct {
	basePath string   // Root path for content storage (e.g., .doge/artifacts/)
	db       *sql.DB
	bus      *bus.Bus
	logger   *slog.Logger
}

// NewStore creates a new artifact store.
//
// basePath is the directory where artifact content is stored in
// content-addressable layout: <basePath>/<sha256[:2]>/<sha256[2:]>
func NewStore(basePath string, db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Store {
	return &Store{
		basePath: basePath,
		db:       db,
		bus:      eventBus,
		logger:   logger,
	}
}

// ImportResult describes the outcome of an import operation.
type ImportResult struct {
	Artifact    domain.Artifact
	IsNew       bool   // true if this is a new artifact, false if duplicate
	DuplicateOf string // If duplicate, the ID of the existing artifact
}

// Import imports a file into the artifact store. The file is copied to
// content-addressable storage, its metadata is recorded in the database,
// and an event is emitted.
//
// If a file with the same SHA256 already exists for this project,
// the existing artifact is returned with IsNew=false and an
// artifact.duplicate event is emitted instead.
func (s *Store) Import(ctx context.Context, sourcePath string, projectID uuid.UUID) (*ImportResult, error) {
	// Open source file.
	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("opening source file: %w", err)
	}
	defer f.Close()

	// Get file info.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source file: %w", err)
	}

	// Read content and compute SHA256.
	hasher := sha256.New()
	content, err := io.ReadAll(io.TeeReader(f, hasher))
	if err != nil {
		return nil, fmt.Errorf("reading source file: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Check for duplicate.
	existing, err := s.getBySHA256(ctx, hash, projectID)
	if err == nil {
		// Duplicate found.
		s.logger.Info("duplicate artifact detected",
			"sha256", hash,
			"existing_id", existing.ID.String(),
			"file", sourcePath,
		)

		s.bus.Publish(ctx, events.ArtifactDuplicate{
			BaseEvent:          events.NewBaseEvent(),
			ArtifactID:         uuid.New(),
			ExistingArtifactID: existing.ID,
			SHA256:             hash,
		})

		return &ImportResult{
			Artifact:    existing,
			IsNew:       false,
			DuplicateOf: existing.ID.String(),
		}, nil
	}

	// Detect MIME type from content (first 512 bytes).
	mimeType := detectMIME(content)

	// Store content in content-addressable layout.
	storedPath, err := s.storeContent(hash, content)
	if err != nil {
		return nil, fmt.Errorf("storing content: %w", err)
	}

	// Build artifact record.
	now := time.Now().UTC()
	artifact := domain.Artifact{
		ID:           uuid.New(),
		SHA256:       hash,
		OriginalPath: sourcePath,
		StoredPath:   storedPath,
		FileName:     filepath.Base(sourcePath),
		FileSize:     info.Size(),
		MIMEType:     mimeType,
		ImportedAt:   now,
		ProjectID:    projectID,
		Version:      1,
		Metadata:     make(map[string]string),
	}

	// Persist to database.
	if err := s.create(ctx, artifact); err != nil {
		return nil, fmt.Errorf("persisting artifact: %w", err)
	}

	s.logger.Info("artifact stored",
		"id", artifact.ID.String(),
		"sha256", hash,
		"file", artifact.FileName,
		"size", artifact.FileSize,
		"mime", artifact.MIMEType,
	)

	// Emit event.
	s.bus.Publish(ctx, events.ArtifactStored{
		BaseEvent:  events.NewBaseEvent(),
		ArtifactID: artifact.ID,
		SHA256:     hash,
		Path:       sourcePath,
		ProjectID:  projectID,
	})

	return &ImportResult{
		Artifact: artifact,
		IsNew:    true,
	}, nil
}

// GetByID retrieves an artifact by its ID.
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (domain.Artifact, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sha256, original_path, stored_path, file_name, file_size,
		        mime_type, parser_used, imported_at, project_id, version
		 FROM artifacts WHERE id = ?`, id.String())

	return scanArtifact(row)
}

// ReadContent returns a reader for the artifact's stored content.
func (s *Store) ReadContent(artifact domain.Artifact) (io.ReadCloser, error) {
	return os.Open(artifact.StoredPath)
}

// MarkParsed records which parser was used to process this artifact.
func (s *Store) MarkParsed(ctx context.Context, artifactID uuid.UUID, parserName string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE artifacts SET parser_used = ? WHERE id = ?`,
		parserName, artifactID.String())
	return err
}

// storeContent writes content to content-addressable storage.
// Layout: <basePath>/<sha256[:2]>/<sha256[2:]>
func (s *Store) storeContent(hash string, content []byte) (string, error) {
	dir := filepath.Join(s.basePath, hash[:2])
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating storage dir: %w", err)
	}

	storedPath := filepath.Join(dir, hash[2:])

	// Skip if already stored (content-addressable = idempotent).
	if _, err := os.Stat(storedPath); err == nil {
		return storedPath, nil
	}

	if err := os.WriteFile(storedPath, content, 0644); err != nil {
		return "", fmt.Errorf("writing content: %w", err)
	}

	return storedPath, nil
}

// create persists an artifact record to the database.
func (s *Store) create(ctx context.Context, a domain.Artifact) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO artifacts (id, sha256, original_path, stored_path, file_name,
		                        file_size, mime_type, parser_used, imported_at,
		                        project_id, version, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')`,
		a.ID.String(), a.SHA256, a.OriginalPath, a.StoredPath, a.FileName,
		a.FileSize, a.MIMEType, a.ParserUsed, a.ImportedAt.Format(time.RFC3339),
		a.ProjectID.String(), a.Version)
	return err
}

// getBySHA256 looks up an artifact by content hash within a project.
func (s *Store) getBySHA256(ctx context.Context, hash string, projectID uuid.UUID) (domain.Artifact, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sha256, original_path, stored_path, file_name, file_size,
		        mime_type, parser_used, imported_at, project_id, version
		 FROM artifacts WHERE sha256 = ? AND project_id = ?`,
		hash, projectID.String())

	return scanArtifact(row)
}

// scanArtifact reads an artifact from a database row.
func scanArtifact(row *sql.Row) (domain.Artifact, error) {
	var a domain.Artifact
	var id, projectID, importedAt string

	err := row.Scan(&id, &a.SHA256, &a.OriginalPath, &a.StoredPath, &a.FileName,
		&a.FileSize, &a.MIMEType, &a.ParserUsed, &importedAt, &projectID, &a.Version)
	if err != nil {
		return domain.Artifact{}, err
	}

	a.ID = uuid.MustParse(id)
	a.ProjectID = uuid.MustParse(projectID)
	a.ImportedAt, _ = time.Parse(time.RFC3339, importedAt)

	return a, nil
}

// detectMIME detects the MIME type from file content using Go's
// built-in content sniffing (first 512 bytes).
func detectMIME(content []byte) string {
	if len(content) == 0 {
		return "application/octet-stream"
	}
	sniffLen := 512
	if len(content) < sniffLen {
		sniffLen = len(content)
	}
	return http.DetectContentType(content[:sniffLen])
}
