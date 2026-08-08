// Package investigation provides the Investigation Repository
// for managing research journeys and tested surfaces.
package investigation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Repository manages investigation persistence.
type Repository struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// New creates a new Investigation Repository.
func New(db *sql.DB, bus *bus.Bus, logger *slog.Logger) *Repository {
	return &Repository{db: db, bus: bus, logger: logger}
}

// Create inserts a new investigation.
func (r *Repository) Create(ctx context.Context, inv *domain.Investigation) error {
	inv.ID = uuid.New()
	inv.Status = domain.InvestigationActive
	inv.CreatedAt = time.Now().UTC()
	inv.UpdatedAt = inv.CreatedAt

	targetJSON, _ := json.Marshal(inv.TargetIDs)
	conclusionsJSON, _ := json.Marshal(inv.Conclusions)

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO investigations (id, title, objective, status, target_ids, conclusions, notes, project_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.ID.String(), inv.Title, inv.Objective, string(inv.Status),
		string(targetJSON), string(conclusionsJSON), inv.Notes,
		inv.ProjectID.String(), inv.CreatedAt.Format(time.RFC3339),
		inv.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("creating investigation: %w", err)
	}

	r.logger.Info("investigation created", "id", inv.ID, "title", inv.Title)
	return nil
}

// Get retrieves an investigation by ID.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*domain.Investigation, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, title, objective, status, target_ids, conclusions, notes, project_id, created_at, updated_at, concluded_at
		 FROM investigations WHERE id = ?`, id.String())
	return scanInvestigation(row)
}

// List returns investigations matching the filter.
func (r *Repository) List(ctx context.Context, filter domain.InvestigationFilter) ([]domain.Investigation, error) {
	query := `SELECT id, title, objective, status, target_ids, conclusions, notes, project_id, created_at, updated_at, concluded_at
	           FROM investigations WHERE 1=1`
	var args []any

	if filter.ProjectID != nil {
		query += " AND project_id = ?"
		args = append(args, filter.ProjectID.String())
	}
	if filter.Status != nil {
		query += " AND status = ?"
		args = append(args, string(*filter.Status))
	}
	query += " ORDER BY updated_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing investigations: %w", err)
	}
	defer rows.Close()

	var results []domain.Investigation
	for rows.Next() {
		inv, err := scanInvestigationRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *inv)
	}
	return results, rows.Err()
}

// Update modifies an investigation. Enforces lifecycle rules:
// - CONCLUDED investigations cannot be modified (except reopening).
func (r *Repository) Update(ctx context.Context, id uuid.UUID, update domain.InvestigationUpdate) error {
	inv, err := r.Get(ctx, id)
	if err != nil {
		return err
	}

	// Enforce immutability of concluded investigations.
	if inv.Status == domain.InvestigationConcluded && update.Status == nil {
		return fmt.Errorf("concluded investigations are immutable: create a new investigation or reopen")
	}

	sets := []string{"updated_at = ?"}
	args := []any{time.Now().UTC().Format(time.RFC3339)}

	if update.Status != nil {
		sets = append(sets, "status = ?")
		args = append(args, string(*update.Status))
	}
	if update.Objective != nil {
		sets = append(sets, "objective = ?")
		args = append(args, *update.Objective)
	}
	if update.Notes != nil {
		sets = append(sets, "notes = ?")
		args = append(args, *update.Notes)
	}
	if update.ConcludedAt != nil {
		sets = append(sets, "concluded_at = ?")
		args = append(args, update.ConcludedAt.Format(time.RFC3339))
	}

	query := fmt.Sprintf("UPDATE investigations SET %s WHERE id = ?", joinSets(sets))
	args = append(args, id.String())

	_, err = r.db.ExecContext(ctx, query, args...)
	return err
}

// AddConclusion adds a provenance-backed conclusion.
func (r *Repository) AddConclusion(ctx context.Context, id uuid.UUID, conclusion domain.Conclusion) error {
	if err := domain.ValidateConclusion(conclusion); err != nil {
		return fmt.Errorf("invalid conclusion: %w", err)
	}

	inv, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if inv.Status == domain.InvestigationConcluded {
		return fmt.Errorf("cannot add conclusion to concluded investigation")
	}

	conclusion.CreatedAt = time.Now().UTC()
	inv.Conclusions = append(inv.Conclusions, conclusion)

	conclusionsJSON, _ := json.Marshal(inv.Conclusions)
	_, err = r.db.ExecContext(ctx,
		`UPDATE investigations SET conclusions = ?, updated_at = ? WHERE id = ?`,
		string(conclusionsJSON), time.Now().UTC().Format(time.RFC3339), id.String())
	return err
}

// AddTarget adds an entity target to an investigation.
func (r *Repository) AddTarget(ctx context.Context, id uuid.UUID, entityID uuid.UUID) error {
	inv, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if inv.Status == domain.InvestigationConcluded {
		return fmt.Errorf("cannot modify concluded investigation")
	}

	inv.TargetIDs = append(inv.TargetIDs, entityID)
	targetJSON, _ := json.Marshal(inv.TargetIDs)
	_, err = r.db.ExecContext(ctx,
		`UPDATE investigations SET target_ids = ?, updated_at = ? WHERE id = ?`,
		string(targetJSON), time.Now().UTC().Format(time.RFC3339), id.String())
	return err
}

// --- Tested Surfaces ---

// CreateSurface registers a new tested surface.
func (r *Repository) CreateSurface(ctx context.Context, s *domain.TestedSurface) error {
	s.ID = uuid.New()
	s.Status = domain.SurfaceUntested
	s.CreatedAt = time.Now().UTC()
	s.UpdatedAt = s.CreatedAt

	evidenceJSON, _ := json.Marshal(s.EvidenceIDs)
	var entityID *string
	if s.EntityID != nil {
		eid := s.EntityID.String()
		entityID = &eid
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tested_surfaces (id, investigation_id, entity_id, category, status, evidence_ids, notes, project_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID.String(), s.InvestigationID.String(), entityID, s.Category,
		string(s.Status), string(evidenceJSON), s.Notes,
		s.ProjectID.String(), s.CreatedAt.Format(time.RFC3339),
		s.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

// MarkSurfaceTested marks a surface as tested with evidence.
func (r *Repository) MarkSurfaceTested(ctx context.Context, id uuid.UUID, evidenceIDs []string) error {
	now := time.Now().UTC()
	evidenceJSON, _ := json.Marshal(evidenceIDs)
	_, err := r.db.ExecContext(ctx,
		`UPDATE tested_surfaces SET status = ?, evidence_ids = ?, tested_at = ?, updated_at = ? WHERE id = ?`,
		string(domain.SurfaceTested), string(evidenceJSON),
		now.Format(time.RFC3339), now.Format(time.RFC3339), id.String())
	return err
}

// ListSurfaces returns all tested surfaces for an investigation.
func (r *Repository) ListSurfaces(ctx context.Context, investigationID uuid.UUID) ([]domain.TestedSurface, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, investigation_id, entity_id, category, status, evidence_ids, notes, project_id, tested_at, created_at, updated_at
		 FROM tested_surfaces WHERE investigation_id = ? ORDER BY category`,
		investigationID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.TestedSurface
	for rows.Next() {
		s, err := scanSurface(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *s)
	}
	return results, rows.Err()
}

// --- Scan helpers ---

type scannable interface {
	Scan(dest ...any) error
}

func scanInvestigation(row *sql.Row) (*domain.Investigation, error) {
	var inv domain.Investigation
	var id, projectID, status string
	var targetJSON, conclusionsJSON string
	var createdAt, updatedAt string
	var concludedAt *string

	err := row.Scan(&id, &inv.Title, &inv.Objective, &status,
		&targetJSON, &conclusionsJSON, &inv.Notes, &projectID,
		&createdAt, &updatedAt, &concludedAt)
	if err != nil {
		return nil, fmt.Errorf("scanning investigation: %w", err)
	}

	inv.ID = uuid.MustParse(id)
	inv.ProjectID = uuid.MustParse(projectID)
	inv.Status = domain.InvestigationStatus(status)
	json.Unmarshal([]byte(targetJSON), &inv.TargetIDs)
	json.Unmarshal([]byte(conclusionsJSON), &inv.Conclusions)
	inv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	inv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	if concludedAt != nil {
		t, _ := time.Parse(time.RFC3339, *concludedAt)
		inv.ConcludedAt = &t
	}

	return &inv, nil
}

func scanInvestigationRow(rows *sql.Rows) (*domain.Investigation, error) {
	var inv domain.Investigation
	var id, projectID, status string
	var targetJSON, conclusionsJSON string
	var createdAt, updatedAt string
	var concludedAt *string

	err := rows.Scan(&id, &inv.Title, &inv.Objective, &status,
		&targetJSON, &conclusionsJSON, &inv.Notes, &projectID,
		&createdAt, &updatedAt, &concludedAt)
	if err != nil {
		return nil, fmt.Errorf("scanning investigation: %w", err)
	}

	inv.ID = uuid.MustParse(id)
	inv.ProjectID = uuid.MustParse(projectID)
	inv.Status = domain.InvestigationStatus(status)
	json.Unmarshal([]byte(targetJSON), &inv.TargetIDs)
	json.Unmarshal([]byte(conclusionsJSON), &inv.Conclusions)
	inv.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	inv.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	if concludedAt != nil {
		t, _ := time.Parse(time.RFC3339, *concludedAt)
		inv.ConcludedAt = &t
	}

	return &inv, nil
}

func scanSurface(rows *sql.Rows) (*domain.TestedSurface, error) {
	var s domain.TestedSurface
	var id, invID, status, projectID string
	var entityID *string
	var evidenceJSON string
	var testedAt *string
	var createdAt, updatedAt string

	err := rows.Scan(&id, &invID, &entityID, &s.Category, &status,
		&evidenceJSON, &s.Notes, &projectID, &testedAt,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("scanning surface: %w", err)
	}

	s.ID = uuid.MustParse(id)
	s.InvestigationID = uuid.MustParse(invID)
	s.ProjectID = uuid.MustParse(projectID)
	s.Status = domain.TestedSurfaceStatus(status)
	json.Unmarshal([]byte(evidenceJSON), &s.EvidenceIDs)
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	if entityID != nil {
		eid := uuid.MustParse(*entityID)
		s.EntityID = &eid
	}
	if testedAt != nil {
		t, _ := time.Parse(time.RFC3339, *testedAt)
		s.TestedAt = &t
	}

	return &s, nil
}

func joinSets(sets []string) string {
	result := ""
	for i, s := range sets {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
