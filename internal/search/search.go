// Package search provides workspace-wide search across all data types.
//
// Search is not just a graph query. It searches:
//   - Entities (by value)
//   - Observations (by raw value and source tool)
//   - Artifacts (by filename)
//
// Results are ranked by relevance and returned in a unified format.
package search

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ResultType classifies what kind of object a search result is.
type ResultType string

const (
	ResultEntity      ResultType = "entity"
	ResultObservation ResultType = "observation"
	ResultArtifact    ResultType = "artifact"
)

// Result is a single search result with unified display fields.
type Result struct {
	Type       ResultType `json:"type"`
	ID         string     `json:"id"`
	Title      string     `json:"title"`       // Primary display text.
	Subtitle   string     `json:"subtitle"`    // Secondary context.
	MatchField string     `json:"match_field"` // Which field matched.
	Score      int        `json:"score"`       // Relevance score (higher = better).
}

// Options configures a search query.
type Options struct {
	ProjectID *uuid.UUID
	Types     []ResultType // Filter to specific result types (empty = all).
	Limit     int
}

// Engine performs workspace-wide search.
type Engine struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewEngine creates a new search engine.
func NewEngine(db *sql.DB, logger *slog.Logger) *Engine {
	return &Engine{
		db:     db,
		logger: logger,
	}
}

// Search performs a workspace-wide search and returns ranked results.
func (e *Engine) Search(ctx context.Context, query string, opts Options) ([]Result, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	var results []Result

	// Determine which types to search.
	searchAll := len(opts.Types) == 0
	typeSet := make(map[ResultType]bool)
	for _, t := range opts.Types {
		typeSet[t] = true
	}

	// Search entities.
	if searchAll || typeSet[ResultEntity] {
		entityResults, err := e.searchEntities(ctx, query, opts.ProjectID, limit)
		if err != nil {
			e.logger.Warn("entity search error", "error", err)
		} else {
			results = append(results, entityResults...)
		}
	}

	// Search observations.
	if searchAll || typeSet[ResultObservation] {
		obsResults, err := e.searchObservations(ctx, query, opts.ProjectID, limit)
		if err != nil {
			e.logger.Warn("observation search error", "error", err)
		} else {
			results = append(results, obsResults...)
		}
	}

	// Search artifacts.
	if searchAll || typeSet[ResultArtifact] {
		artResults, err := e.searchArtifacts(ctx, query, opts.ProjectID, limit)
		if err != nil {
			e.logger.Warn("artifact search error", "error", err)
		} else {
			results = append(results, artResults...)
		}
	}

	// Sort by score descending.
	sortByScore(results)

	// Apply overall limit.
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func (e *Engine) searchEntities(ctx context.Context, query string, projectID *uuid.UUID, limit int) ([]Result, error) {
	q := `SELECT id, type, value, observation_count FROM entities WHERE value LIKE ?`
	args := []any{"%" + query + "%"}

	if projectID != nil {
		q += " AND project_id = ?"
		args = append(args, projectID.String())
	}
	q += fmt.Sprintf(" ORDER BY observation_count DESC LIMIT %d", limit)

	rows, err := e.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Result
	for rows.Next() {
		var id, entityType, value string
		var obsCount int
		if err := rows.Scan(&id, &entityType, &value, &obsCount); err != nil {
			continue
		}

		score := 100
		if strings.EqualFold(value, query) {
			score = 200 // Exact match.
		}
		score += obsCount * 5 // Boost by evidence count.

		results = append(results, Result{
			Type:       ResultEntity,
			ID:         id,
			Title:      value,
			Subtitle:   fmt.Sprintf("%s • %d observations", entityType, obsCount),
			MatchField: "value",
			Score:      score,
		})
	}

	return results, nil
}

func (e *Engine) searchObservations(ctx context.Context, query string, projectID *uuid.UUID, limit int) ([]Result, error) {
	q := `SELECT id, type, source_tool, raw_value, observed_at FROM observations WHERE raw_value LIKE ?`
	args := []any{"%" + query + "%"}

	if projectID != nil {
		q += " AND project_id = ?"
		args = append(args, projectID.String())
	}
	q += fmt.Sprintf(" ORDER BY observed_at DESC LIMIT %d", limit)

	rows, err := e.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Result
	for rows.Next() {
		var id, obsType, sourceTool, rawValue, observedAt string
		if err := rows.Scan(&id, &obsType, &sourceTool, &rawValue, &observedAt); err != nil {
			continue
		}

		t, _ := time.Parse(time.RFC3339, observedAt)
		title := rawValue
		if len(title) > 80 {
			title = title[:80] + "..."
		}

		results = append(results, Result{
			Type:       ResultObservation,
			ID:         id,
			Title:      title,
			Subtitle:   fmt.Sprintf("%s • %s • %s", obsType, sourceTool, t.Format("2006-01-02 15:04")),
			MatchField: "raw_value",
			Score:      50,
		})
	}

	return results, nil
}

func (e *Engine) searchArtifacts(ctx context.Context, query string, projectID *uuid.UUID, limit int) ([]Result, error) {
	q := `SELECT id, file_name, mime_type, file_size, imported_at FROM artifacts WHERE file_name LIKE ?`
	args := []any{"%" + query + "%"}

	if projectID != nil {
		q += " AND project_id = ?"
		args = append(args, projectID.String())
	}
	q += fmt.Sprintf(" ORDER BY imported_at DESC LIMIT %d", limit)

	rows, err := e.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Result
	for rows.Next() {
		var id, fileName, mimeType, importedAt string
		var fileSize int64
		if err := rows.Scan(&id, &fileName, &mimeType, &fileSize, &importedAt); err != nil {
			continue
		}

		t, _ := time.Parse(time.RFC3339, importedAt)

		results = append(results, Result{
			Type:       ResultArtifact,
			ID:         id,
			Title:      fileName,
			Subtitle:   fmt.Sprintf("%s • %s • %s", mimeType, formatSize(fileSize), t.Format("2006-01-02 15:04")),
			MatchField: "file_name",
			Score:      30,
		})
	}

	return results, nil
}

// sortByScore sorts results by score descending using insertion sort
// (results are typically small, no need for sort.Slice import).
func sortByScore(results []Result) {
	for i := 1; i < len(results); i++ {
		key := results[i]
		j := i - 1
		for j >= 0 && results[j].Score < key.Score {
			results[j+1] = results[j]
			j--
		}
		results[j+1] = key
	}
}

func formatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
