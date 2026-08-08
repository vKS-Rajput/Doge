package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/entity"
	"github.com/vKS-Rajput/doge/internal/insight"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/search"
	"github.com/vKS-Rajput/doge/internal/task"
	"github.com/vKS-Rajput/doge/internal/timeline"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// TimelineEntries returns recent timeline entries for the workspace.
func (a *App) TimelineEntries(ctx context.Context, limit int) ([]timeline.Entry, error) {
	tl := timeline.New(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "timeline"))
	return tl.Query(ctx, timeline.Filter{
		ProjectID: &a.DefaultProjectID,
		Limit:     limit,
	})
}

// Search performs a workspace-wide search across entities, observations,
// and artifacts.
func (a *App) Search(ctx context.Context, query string, limit int) ([]search.Result, error) {
	engine := search.NewEngine(a.DB.Conn(), logging.WithModule(a.Logger, "search"))
	return engine.Search(ctx, query, search.Options{
		ProjectID: &a.DefaultProjectID,
		Limit:     limit,
	})
}

// GraphStats returns summary statistics for the Knowledge Graph.
func (a *App) GraphStats(ctx context.Context) (*domain.GraphStats, error) {
	store := entity.NewStore(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "entity"))
	stats, err := store.Stats(ctx, a.DefaultProjectID)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

// GraphNeighborhood returns a subgraph centered on an entity.
func (a *App) GraphNeighborhood(ctx context.Context, entityID uuid.UUID, depth int) (*domain.Subgraph, error) {
	store := entity.NewStore(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "entity"))
	return store.Neighborhood(ctx, entityID, depth)
}

// GraphSearch searches entities by value. If query is empty, lists all entities.
func (a *App) GraphSearch(ctx context.Context, query string, limit int) ([]domain.Entity, error) {
	store := entity.NewStore(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "entity"))

	if query == "" {
		return store.Query(ctx, domain.EntityFilter{
			ProjectID: &a.DefaultProjectID,
			Limit:     limit,
		})
	}

	return store.Search(ctx, query, a.DefaultProjectID, limit)
}

// EntityDetails returns a single entity with its relationships.
type EntityDetails struct {
	Entity        domain.Entity
	Relationships []domain.Relationship
}

// GetEntity returns entity details including relationships.
func (a *App) GetEntity(ctx context.Context, entityID uuid.UUID) (*EntityDetails, error) {
	store := entity.NewStore(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "entity"))

	e, err := store.Get(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("entity not found: %w", err)
	}

	rels, err := store.GetRelationships(ctx, entityID, domain.DirectionBoth)
	if err != nil {
		return nil, fmt.Errorf("loading relationships: %w", err)
	}

	return &EntityDetails{
		Entity:        e,
		Relationships: rels,
	}, nil
}

// Insights returns recent insights for the workspace.
func (a *App) Insights(ctx context.Context, limit int) ([]insight.Insight, error) {
	engine := insight.NewEngine(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "insight"))
	return engine.Query(ctx, a.DefaultProjectID, limit)
}

// Tasks returns tasks for the workspace.
func (a *App) Tasks(ctx context.Context, status string, limit int) ([]task.Task, error) {
	engine := task.NewEngine(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "task"))
	return engine.Query(ctx, a.DefaultProjectID, status, limit)
}
