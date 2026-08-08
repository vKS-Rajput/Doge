// Package memory provides the Research Memory Service.
//
// Memory answers: "What was I investigating, what did I test,
// and what remains unexplored?"
//
// Four memory layers:
//
//  1. Session Memory — current conversation context
//  2. Investigation Memory — research journey state
//  3. Workspace Memory — persistent project knowledge
//  4. Timeline Memory — historical changes
//
// Memory trust model:
//
//	Session        → Historical record (not authoritative)
//	Hypothesis     → Hypothetical (AI can create)
//	Task           → Derived/actionable
//	Finding        → Evidence-backed (researcher-confirmed only)
//	Conclusion     → Evidence-backed with provenance
//	Tested Surface → Observed research state
//	AI reasoning   → Never authoritative
//
// Key rule:
//
//	Verification can reject or downgrade an AI claim,
//	but the AI can never promote its own claim into an observation.
package memory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/investigation"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Service provides research memory operations.
type Service struct {
	db     *sql.DB
	repo   *investigation.Repository
	logger *slog.Logger
}

// NewService creates a new Memory Service.
func NewService(db *sql.DB, repo *investigation.Repository, logger *slog.Logger) *Service {
	return &Service{db: db, repo: repo, logger: logger}
}

// --- Investigation Memory ---

// InvestigationState is a complete snapshot of an investigation's
// current state, ready for rendering or AI context injection.
type InvestigationState struct {
	Investigation    domain.Investigation    `json:"investigation"`
	Hypotheses       []domain.Hypothesis     `json:"hypotheses"`
	Tasks            []domain.Task           `json:"tasks"`
	Findings         []domain.Finding        `json:"findings"`
	TestedSurfaces   []domain.TestedSurface  `json:"tested_surfaces"`
	RecentSessions   []SessionSummary        `json:"recent_sessions"`
	Stats            InvestigationStats      `json:"stats"`
}

// InvestigationStats summarizes the investigation for quick display.
type InvestigationStats struct {
	HypothesesActive int `json:"hypotheses_active"`
	HypothesesTotal  int `json:"hypotheses_total"`
	TasksPending     int `json:"tasks_pending"`
	TasksTotal       int `json:"tasks_total"`
	FindingsTotal    int `json:"findings_total"`
	SurfacesTested   int `json:"surfaces_tested"`
	SurfacesTotal    int `json:"surfaces_total"`
	SessionsTotal    int `json:"sessions_total"`
}

// SessionSummary is a lightweight view of a past AI session.
type SessionSummary struct {
	ID        uuid.UUID `json:"id"`
	Question  string    `json:"question"`
	ModelUsed string    `json:"model_used"`
	Rejected  bool      `json:"rejected"`
	CreatedAt time.Time `json:"created_at"`
}

// GetInvestigationState returns the complete structured state.
func (s *Service) GetInvestigationState(ctx context.Context, investigationID uuid.UUID) (*InvestigationState, error) {
	inv, err := s.repo.Get(ctx, investigationID)
	if err != nil {
		return nil, fmt.Errorf("getting investigation: %w", err)
	}

	state := &InvestigationState{
		Investigation: *inv,
	}

	// Load hypotheses.
	state.Hypotheses, err = s.listHypotheses(ctx, investigationID)
	if err != nil {
		return nil, err
	}

	// Load tasks.
	state.Tasks, err = s.listTasks(ctx, investigationID)
	if err != nil {
		return nil, err
	}

	// Load findings.
	state.Findings, err = s.listFindings(ctx, investigationID)
	if err != nil {
		return nil, err
	}

	// Load tested surfaces.
	state.TestedSurfaces, err = s.repo.ListSurfaces(ctx, investigationID)
	if err != nil {
		return nil, err
	}

	// Load recent sessions.
	state.RecentSessions, err = s.listRecentSessions(ctx, investigationID, 5)
	if err != nil {
		return nil, err
	}

	// Compute stats.
	state.Stats = computeStats(state)

	return state, nil
}

// --- Session Memory ---

// SaveSession persists an AI session, optionally linking it to an investigation.
func (s *Service) SaveSession(ctx context.Context, session *domain.Session) error {
	var invID *string
	// Check if there's an active investigation for this project.
	activeInv, err := s.ActiveInvestigation(ctx, session.ProjectID)
	if err == nil && activeInv != nil {
		id := activeInv.ID.String()
		invID = &id
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, type, question, context_snapshot, tokens_used, model_used, raw_response, verified_response, rejected, rejection_reason, project_id, duration_ms, created_at, completed_at, investigation_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID.String(), string(session.Type), session.Question,
		"[]", session.TokensUsed, session.ModelUsed,
		session.RawResponse, session.VerifiedResponse,
		session.Rejected, session.RejectionReason,
		session.ProjectID.String(), session.Duration.Milliseconds(),
		session.CreatedAt.Format(time.RFC3339),
		nilTimeStr(session.CompletedAt), invID,
	)
	if err != nil {
		return fmt.Errorf("saving session: %w", err)
	}

	s.logger.Info("session saved", "id", session.ID, "question", session.Question)
	return nil
}

// --- Workspace Memory ---

// WorkspaceSummary provides a high-level view of the workspace.
type WorkspaceSummary struct {
	EntityCount       int `json:"entity_count"`
	RelationshipCount int `json:"relationship_count"`
	ObservationCount  int `json:"observation_count"`
	InsightCount      int `json:"insight_count"`
	TaskCount         int `json:"task_count"`
	InvestigationCount int `json:"investigation_count"`
	FindingCount      int `json:"finding_count"`
}

// GetWorkspaceSummary returns workspace-level statistics.
func (s *Service) GetWorkspaceSummary(ctx context.Context, projectID uuid.UUID) (*WorkspaceSummary, error) {
	summary := &WorkspaceSummary{}

	queries := []struct {
		query string
		dest  *int
	}{
		{"SELECT COUNT(*) FROM entities WHERE project_id = ?", &summary.EntityCount},
		{"SELECT COUNT(*) FROM relationships WHERE project_id = ?", &summary.RelationshipCount},
		{"SELECT COUNT(*) FROM observations WHERE project_id = ?", &summary.ObservationCount},
		{"SELECT COUNT(*) FROM insights WHERE project_id = ?", &summary.InsightCount},
		{"SELECT COUNT(*) FROM tasks WHERE project_id = ?", &summary.TaskCount},
		{"SELECT COUNT(*) FROM investigations WHERE project_id = ?", &summary.InvestigationCount},
		{"SELECT COUNT(*) FROM findings WHERE project_id = ?", &summary.FindingCount},
	}

	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.query, projectID.String()).Scan(q.dest); err != nil {
			return nil, fmt.Errorf("workspace summary: %w", err)
		}
	}

	return summary, nil
}

// ActiveInvestigation returns the most recently active investigation.
func (s *Service) ActiveInvestigation(ctx context.Context, projectID uuid.UUID) (*domain.Investigation, error) {
	status := domain.InvestigationActive
	investigations, err := s.repo.List(ctx, domain.InvestigationFilter{
		ProjectID: &projectID,
		Status:    &status,
		Limit:     1,
	})
	if err != nil {
		return nil, err
	}
	if len(investigations) == 0 {
		return nil, nil
	}
	return &investigations[0], nil
}

// --- Internal query helpers ---

func (s *Service) listHypotheses(ctx context.Context, investigationID uuid.UUID) ([]domain.Hypothesis, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, title, description, type, status, confidence, entity_ids, supporting_evidence, refuting_evidence, notes, project_id, proposed_by, created_at, updated_at, resolved_at
		 FROM hypotheses WHERE investigation_id = ? ORDER BY created_at DESC`,
		investigationID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.Hypothesis
	for rows.Next() {
		var h domain.Hypothesis
		var id, projectID, hType, status, proposedBy string
		var entityJSON, supportJSON, refuteJSON string
		var resolvedAt *string

		err := rows.Scan(&id, &h.Title, &h.Description, &hType, &status,
			&h.Confidence, &entityJSON, &supportJSON, &refuteJSON,
			&h.Notes, &projectID, &proposedBy, &h.CreatedAt, &h.UpdatedAt, &resolvedAt)
		if err != nil {
			return nil, err
		}

		h.ID = uuid.MustParse(id)
		h.ProjectID = uuid.MustParse(projectID)
		h.Type = domain.HypothesisType(hType)
		h.Status = domain.HypothesisStatus(status)
		h.ProposedBy = domain.HypothesisProposer(proposedBy)
		json.Unmarshal([]byte(entityJSON), &h.EntityIDs)
		json.Unmarshal([]byte(supportJSON), &h.SupportingEvidence)
		json.Unmarshal([]byte(refuteJSON), &h.RefutingEvidence)

		if resolvedAt != nil {
			t, _ := time.Parse(time.RFC3339, *resolvedAt)
			h.ResolvedAt = &t
		}
		results = append(results, h)
	}
	return results, rows.Err()
}

func (s *Service) listTasks(ctx context.Context, investigationID uuid.UUID) ([]domain.Task, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, title, description, type, priority, risk, confidence, evidence_count, estimated_effort, status, entity_ids, insight_id, hypothesis_id, project_id, created_at, updated_at, completed_at
		 FROM tasks WHERE investigation_id = ? ORDER BY priority, created_at DESC`,
		investigationID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.Task
	for rows.Next() {
		var t domain.Task
		var id, projectID, tType, priority, effort, status string
		var entityJSON string
		var insightID, hypothesisID *string
		var completedAt *string

		err := rows.Scan(&id, &t.Title, &t.Description, &tType, &priority,
			&t.Risk, &t.Confidence, &t.EvidenceCount, &effort, &status,
			&entityJSON, &insightID, &hypothesisID, &projectID,
			&t.CreatedAt, &t.UpdatedAt, &completedAt)
		if err != nil {
			return nil, err
		}

		t.ID = uuid.MustParse(id)
		t.ProjectID = uuid.MustParse(projectID)
		t.Type = domain.TaskType(tType)
		t.Priority = domain.TaskPriority(priority)
		t.EstimatedEffort = domain.EstimatedEffort(effort)
		t.Status = domain.TaskStatus(status)
		json.Unmarshal([]byte(entityJSON), &t.EntityIDs)

		if insightID != nil {
			uid := uuid.MustParse(*insightID)
			t.InsightID = &uid
		}
		if hypothesisID != nil {
			uid := uuid.MustParse(*hypothesisID)
			t.HypothesisID = &uid
		}
		if completedAt != nil {
			ct, _ := time.Parse(time.RFC3339, *completedAt)
			t.CompletedAt = &ct
		}
		results = append(results, t)
	}
	return results, rows.Err()
}

func (s *Service) listFindings(ctx context.Context, investigationID uuid.UUID) ([]domain.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, title, description, severity, status, entity_ids, evidence_ids, hypothesis_id, notes, project_id, created_at, updated_at, confirmed_at
		 FROM findings WHERE investigation_id = ? ORDER BY created_at DESC`,
		investigationID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.Finding
	for rows.Next() {
		var f domain.Finding
		var id, projectID, severity, status string
		var entityJSON, evidenceJSON string
		var hypothesisID *string
		var confirmedAt *string

		err := rows.Scan(&id, &f.Title, &f.Description, &severity, &status,
			&entityJSON, &evidenceJSON, &hypothesisID,
			&f.Notes, &projectID, &f.CreatedAt, &f.UpdatedAt, &confirmedAt)
		if err != nil {
			return nil, err
		}

		f.ID = uuid.MustParse(id)
		f.ProjectID = uuid.MustParse(projectID)
		f.Severity = domain.Severity(severity)
		f.Status = domain.FindingStatus(status)
		json.Unmarshal([]byte(entityJSON), &f.EntityIDs)
		json.Unmarshal([]byte(evidenceJSON), &f.EvidenceIDs)

		if hypothesisID != nil {
			uid := uuid.MustParse(*hypothesisID)
			f.HypothesisID = &uid
		}
		if confirmedAt != nil {
			ct, _ := time.Parse(time.RFC3339, *confirmedAt)
			f.ConfirmedAt = &ct
		}
		results = append(results, f)
	}
	return results, rows.Err()
}

func (s *Service) listRecentSessions(ctx context.Context, investigationID uuid.UUID, limit int) ([]SessionSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, question, model_used, rejected, created_at
		 FROM sessions WHERE investigation_id = ?
		 ORDER BY created_at DESC LIMIT ?`,
		investigationID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SessionSummary
	for rows.Next() {
		var ss SessionSummary
		var id string
		err := rows.Scan(&id, &ss.Question, &ss.ModelUsed, &ss.Rejected, &ss.CreatedAt)
		if err != nil {
			return nil, err
		}
		ss.ID = uuid.MustParse(id)
		results = append(results, ss)
	}
	return results, rows.Err()
}

func computeStats(state *InvestigationState) InvestigationStats {
	stats := InvestigationStats{
		HypothesesTotal: len(state.Hypotheses),
		TasksTotal:      len(state.Tasks),
		FindingsTotal:   len(state.Findings),
		SurfacesTotal:   len(state.TestedSurfaces),
		SessionsTotal:   len(state.RecentSessions),
	}

	for _, h := range state.Hypotheses {
		if h.Status == domain.HypothesisProposed || h.Status == domain.HypothesisInvestigating {
			stats.HypothesesActive++
		}
	}
	for _, t := range state.Tasks {
		if t.Status == domain.TaskPending || t.Status == domain.TaskInProgress {
			stats.TasksPending++
		}
	}
	for _, s := range state.TestedSurfaces {
		if s.Status == domain.SurfaceTested {
			stats.SurfacesTested++
		}
	}

	return stats
}

func nilTimeStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}
