package entity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Store persists entities and their provenance links.
//
// The Entity Store exposes only three operations:
//   - Ingest: create or enrich an entity
//   - Get: retrieve a single entity
//   - Query: list entities matching a filter
//
// There is no Update or Delete. Entities accumulate attributes over
// time as new observations arrive. This protects the immutability
// invariant through the API, not just the database.
type Store struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// NewStore creates a new entity store.
func NewStore(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Store {
	return &Store{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// IngestResult describes the outcome of ingesting a single entity.
type IngestResult struct {
	Entity  domain.Entity
	Created bool // true if new, false if enriched
}

// Ingest creates or enriches an entity. This is the only write operation.
//
// If an entity with the same (type, canonicalValue, projectID) already
// exists, it is enriched: attributes are merged, observation count is
// incremented, and last_seen_at is updated.
//
// If no such entity exists, a new one is created.
//
// In both cases, a provenance link (entity_observations) is created
// connecting this entity to the source observation.
func (s *Store) Ingest(ctx context.Context, entityType domain.EntityType, rawValue string, attributes map[string]any, observationID, projectID uuid.UUID, observedAt time.Time) (*IngestResult, error) {
	// Resolve canonical identity.
	canonicalValue := Resolve(entityType, rawValue)
	canonicalHash := CanonicalHash(entityType, canonicalValue)

	// Check if entity exists.
	existing, err := s.getByCanonical(ctx, entityType, canonicalValue, projectID)
	if err == nil {
		// Entity exists — enrich it.
		enriched, err := s.enrich(ctx, existing, attributes, observationID, observedAt)
		if err != nil {
			return nil, fmt.Errorf("enriching entity: %w", err)
		}

		return &IngestResult{Entity: enriched, Created: false}, nil
	}

	// Entity doesn't exist — create it.
	now := time.Now().UTC()
	attrJSON, _ := json.Marshal(attributes)

	entity := domain.Entity{
		ID:               uuid.New(),
		CanonicalID:      uuid.Nil, // Will be set to own ID below.
		Type:             entityType,
		Value:            canonicalValue,
		Attributes:       attributes,
		ProjectID:        projectID,
		ObservationCount: 1,
		FirstSeenAt:      observedAt,
		LastSeenAt:       observedAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	entity.CanonicalID = entity.ID // Canonical entities point to themselves.

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO entities (id, canonical_id, type, value, attributes, project_id,
		                       observation_count, first_seen_at, last_seen_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entity.ID.String(), entity.CanonicalID.String(), string(entity.Type),
		entity.Value, string(attrJSON), entity.ProjectID.String(),
		entity.ObservationCount,
		entity.FirstSeenAt.Format(time.RFC3339),
		entity.LastSeenAt.Format(time.RFC3339),
		entity.CreatedAt.Format(time.RFC3339),
		entity.UpdatedAt.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("inserting entity: %w", err)
	}

	// Create provenance link.
	if err := s.linkObservation(ctx, entity.ID, observationID); err != nil {
		return nil, fmt.Errorf("linking observation: %w", err)
	}

	s.logger.Debug("entity created",
		"id", entity.ID.String(),
		"type", string(entity.Type),
		"value", entity.Value,
		"canonical_hash", canonicalHash,
	)

	// Emit event.
	s.bus.Publish(ctx, events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		EntityID:  entity.ID,
		Type:      string(entity.Type),
		Value:     entity.Value,
		ProjectID: projectID,
	})

	return &IngestResult{Entity: entity, Created: true}, nil
}

// enrich merges new attributes into an existing entity.
func (s *Store) enrich(ctx context.Context, existing domain.Entity, newAttrs map[string]any, observationID uuid.UUID, observedAt time.Time) (domain.Entity, error) {
	// Merge attributes: new keys are added, existing keys are overwritten.
	merged := make(map[string]any)
	for k, v := range existing.Attributes {
		merged[k] = v
	}
	for k, v := range newAttrs {
		merged[k] = v
	}

	attrJSON, _ := json.Marshal(merged)
	now := time.Now().UTC()

	lastSeen := existing.LastSeenAt
	if observedAt.After(lastSeen) {
		lastSeen = observedAt
	}

	_, err := s.db.ExecContext(ctx,
		`UPDATE entities SET
			attributes = ?,
			observation_count = observation_count + 1,
			last_seen_at = ?,
			updated_at = ?
		 WHERE id = ?`,
		string(attrJSON),
		lastSeen.Format(time.RFC3339),
		now.Format(time.RFC3339),
		existing.ID.String())
	if err != nil {
		return domain.Entity{}, err
	}

	// Create provenance link.
	if err := s.linkObservation(ctx, existing.ID, observationID); err != nil {
		s.logger.Debug("provenance link exists", "entity_id", existing.ID.String(), "observation_id", observationID.String())
	}

	// Emit event.
	s.bus.Publish(ctx, events.EntityEnriched{
		BaseEvent:     events.NewBaseEvent(),
		EntityID:      existing.ID,
		NewAttributes: newAttrs,
		ObservationID: observationID,
	})

	existing.Attributes = merged
	existing.ObservationCount++
	existing.LastSeenAt = lastSeen
	existing.UpdatedAt = now

	return existing, nil
}

// linkObservation creates the provenance link between entity and observation.
func (s *Store) linkObservation(ctx context.Context, entityID, observationID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO entity_observations (entity_id, observation_id) VALUES (?, ?)`,
		entityID.String(), observationID.String())
	return err
}

// Get retrieves a single entity by ID.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (domain.Entity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, canonical_id, type, value, attributes, project_id,
		        observation_count, first_seen_at, last_seen_at, created_at, updated_at
		 FROM entities WHERE id = ?`, id.String())
	return scanEntity(row)
}

// Query returns entities matching the given filter.
func (s *Store) Query(ctx context.Context, filter domain.EntityFilter) ([]domain.Entity, error) {
	query := `SELECT id, canonical_id, type, value, attributes, project_id,
	                 observation_count, first_seen_at, last_seen_at, created_at, updated_at
	          FROM entities WHERE 1=1`
	var args []any

	if filter.ProjectID != nil {
		query += " AND project_id = ?"
		args = append(args, filter.ProjectID.String())
	}
	if filter.Type != nil {
		query += " AND type = ?"
		args = append(args, string(*filter.Type))
	}
	if filter.ValueContains != "" {
		query += " AND value LIKE ?"
		args = append(args, "%"+filter.ValueContains+"%")
	}

	query += " ORDER BY last_seen_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entities []domain.Entity
	for rows.Next() {
		e, err := scanEntityFromRows(rows)
		if err != nil {
			return nil, err
		}
		entities = append(entities, e)
	}
	return entities, rows.Err()
}

// Stats returns summary statistics for the entity store.
func (s *Store) Stats(ctx context.Context, projectID uuid.UUID) (domain.GraphStats, error) {
	var stats domain.GraphStats

	// Total entities.
	s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM entities WHERE project_id = ?`,
		projectID.String()).Scan(&stats.EntityCount)

	// Total relationships.
	s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM relationships WHERE project_id = ?`,
		projectID.String()).Scan(&stats.RelationshipCount)

	// Total observations.
	s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observations WHERE project_id = ?`,
		projectID.String()).Scan(&stats.ObservationCount)

	// Total artifacts.
	s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifacts WHERE project_id = ?`,
		projectID.String()).Scan(&stats.ArtifactCount)

	// Entity count by type.
	stats.EntityCountByType = make(map[domain.EntityType]int)
	rows, err := s.db.QueryContext(ctx,
		`SELECT type, COUNT(*) FROM entities WHERE project_id = ? GROUP BY type`,
		projectID.String())
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var c int
			if rows.Scan(&t, &c) == nil {
				stats.EntityCountByType[domain.EntityType(t)] = c
			}
		}
	}

	return stats, nil
}

// getByCanonical looks up an entity by its canonical (type, value, project).
func (s *Store) getByCanonical(ctx context.Context, entityType domain.EntityType, canonicalValue string, projectID uuid.UUID) (domain.Entity, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, canonical_id, type, value, attributes, project_id,
		        observation_count, first_seen_at, last_seen_at, created_at, updated_at
		 FROM entities WHERE type = ? AND value = ? AND project_id = ?`,
		string(entityType), canonicalValue, projectID.String())
	return scanEntity(row)
}

func scanEntity(row *sql.Row) (domain.Entity, error) {
	var e domain.Entity
	var id, canonicalID, entityType, projectID string
	var attrJSON string
	var firstSeen, lastSeen, createdAt, updatedAt string

	err := row.Scan(&id, &canonicalID, &entityType, &e.Value, &attrJSON,
		&projectID, &e.ObservationCount, &firstSeen, &lastSeen, &createdAt, &updatedAt)
	if err != nil {
		return domain.Entity{}, err
	}

	return populateEntity(id, canonicalID, entityType, e.Value, attrJSON, projectID,
		e.ObservationCount, firstSeen, lastSeen, createdAt, updatedAt)
}

func scanEntityFromRows(rows *sql.Rows) (domain.Entity, error) {
	var id, canonicalID, entityType, value, attrJSON, projectID string
	var obsCount int
	var firstSeen, lastSeen, createdAt, updatedAt string

	err := rows.Scan(&id, &canonicalID, &entityType, &value, &attrJSON,
		&projectID, &obsCount, &firstSeen, &lastSeen, &createdAt, &updatedAt)
	if err != nil {
		return domain.Entity{}, err
	}

	return populateEntity(id, canonicalID, entityType, value, attrJSON, projectID,
		obsCount, firstSeen, lastSeen, createdAt, updatedAt)
}

func populateEntity(id, canonicalID, entityType, value, attrJSON, projectID string,
	obsCount int, firstSeen, lastSeen, createdAt, updatedAt string) (domain.Entity, error) {

	e := domain.Entity{
		ID:               uuid.MustParse(id),
		CanonicalID:      uuid.MustParse(canonicalID),
		Type:             domain.EntityType(entityType),
		Value:            value,
		ProjectID:        uuid.MustParse(projectID),
		ObservationCount: obsCount,
	}

	_ = json.Unmarshal([]byte(attrJSON), &e.Attributes)
	if e.Attributes == nil {
		e.Attributes = make(map[string]any)
	}

	e.FirstSeenAt, _ = time.Parse(time.RFC3339, firstSeen)
	e.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return e, nil
}

// --- Relationship operations ---

// IngestRelationship creates or updates a relationship between two entities.
// If the relationship already exists (same source, target, type, project),
// LastSeenAt is updated. This is the only write operation for relationships.
func (s *Store) IngestRelationship(ctx context.Context, rel domain.Relationship) (*domain.Relationship, bool, error) {
	attrJSON, _ := json.Marshal(rel.Attributes)
	now := time.Now().UTC()

	// Try to find existing relationship.
	var existingID string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM relationships
		 WHERE source_entity_id = ? AND target_entity_id = ? AND type = ? AND project_id = ?`,
		rel.SourceEntityID.String(), rel.TargetEntityID.String(),
		string(rel.Type), rel.ProjectID.String()).Scan(&existingID)

	if err == nil {
		// Existing — update LastSeenAt and merge attributes.
		_, err := s.db.ExecContext(ctx,
			`UPDATE relationships SET last_seen_at = ?, updated_at = ?, attributes = ? WHERE id = ?`,
			rel.LastSeenAt.Format(time.RFC3339), now.Format(time.RFC3339),
			string(attrJSON), existingID)
		if err != nil {
			return nil, false, err
		}
		rel.ID = uuid.MustParse(existingID)
		return &rel, false, nil
	}

	// New relationship.
	if rel.ID == uuid.Nil {
		rel.ID = uuid.New()
	}
	rel.CreatedAt = now
	rel.UpdatedAt = now

	var obsID *string
	if rel.ObservationID != nil {
		s := rel.ObservationID.String()
		obsID = &s
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO relationships (id, source_entity_id, target_entity_id, type, attributes,
		                            observation_id, project_id, first_seen_at, last_seen_at,
		                            created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rel.ID.String(), rel.SourceEntityID.String(), rel.TargetEntityID.String(),
		string(rel.Type), string(attrJSON), obsID, rel.ProjectID.String(),
		rel.FirstSeenAt.Format(time.RFC3339), rel.LastSeenAt.Format(time.RFC3339),
		rel.CreatedAt.Format(time.RFC3339), rel.UpdatedAt.Format(time.RFC3339))
	if err != nil {
		return nil, false, fmt.Errorf("inserting relationship: %w", err)
	}

	s.bus.Publish(ctx, events.RelationshipCreated{
		BaseEvent:      events.NewBaseEvent(),
		RelationshipID: rel.ID,
		SourceEntityID: rel.SourceEntityID,
		TargetEntityID: rel.TargetEntityID,
		Type:           string(rel.Type),
		ProjectID:      rel.ProjectID,
	})

	return &rel, true, nil
}

// GetRelationships returns relationships for an entity in the given direction.
func (s *Store) GetRelationships(ctx context.Context, entityID uuid.UUID, direction domain.Direction) ([]domain.Relationship, error) {
	var query string
	var args []any

	switch direction {
	case domain.DirectionOutgoing:
		query = `SELECT id, source_entity_id, target_entity_id, type, attributes,
		                observation_id, project_id, first_seen_at, last_seen_at
		         FROM relationships WHERE source_entity_id = ?`
		args = []any{entityID.String()}
	case domain.DirectionIncoming:
		query = `SELECT id, source_entity_id, target_entity_id, type, attributes,
		                observation_id, project_id, first_seen_at, last_seen_at
		         FROM relationships WHERE target_entity_id = ?`
		args = []any{entityID.String()}
	case domain.DirectionBoth:
		query = `SELECT id, source_entity_id, target_entity_id, type, attributes,
		                observation_id, project_id, first_seen_at, last_seen_at
		         FROM relationships WHERE source_entity_id = ? OR target_entity_id = ?`
		args = []any{entityID.String(), entityID.String()}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rels []domain.Relationship
	for rows.Next() {
		r, err := scanRelationship(rows)
		if err != nil {
			return nil, err
		}
		rels = append(rels, r)
	}
	return rels, rows.Err()
}

func scanRelationship(rows *sql.Rows) (domain.Relationship, error) {
	var r domain.Relationship
	var id, sourceID, targetID, relType, attrJSON, projectID string
	var obsID *string
	var firstSeen, lastSeen string

	err := rows.Scan(&id, &sourceID, &targetID, &relType, &attrJSON,
		&obsID, &projectID, &firstSeen, &lastSeen)
	if err != nil {
		return domain.Relationship{}, err
	}

	r.ID = uuid.MustParse(id)
	r.SourceEntityID = uuid.MustParse(sourceID)
	r.TargetEntityID = uuid.MustParse(targetID)
	r.Type = domain.RelationshipType(relType)
	r.ProjectID = uuid.MustParse(projectID)
	r.FirstSeenAt, _ = time.Parse(time.RFC3339, firstSeen)
	r.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)

	if obsID != nil {
		parsed := uuid.MustParse(*obsID)
		r.ObservationID = &parsed
	}

	_ = json.Unmarshal([]byte(attrJSON), &r.Attributes)
	if r.Attributes == nil {
		r.Attributes = make(map[string]any)
	}

	return r, nil
}

// Neighborhood returns a subgraph centered on an entity.
func (s *Store) Neighborhood(ctx context.Context, entityID uuid.UUID, depth int) (*domain.Subgraph, error) {
	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3 // Cap depth to prevent expensive queries.
	}

	subgraph := &domain.Subgraph{
		Entities:      make(map[uuid.UUID]domain.Entity),
		Relationships: nil,
	}

	// BFS traversal.
	visited := map[uuid.UUID]bool{entityID: true}
	frontier := []uuid.UUID{entityID}

	// Get the root entity.
	root, err := s.Get(ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("root entity not found: %w", err)
	}
	subgraph.Entities[entityID] = root

	for d := 0; d < depth; d++ {
		var nextFrontier []uuid.UUID

		for _, eid := range frontier {
			rels, err := s.GetRelationships(ctx, eid, domain.DirectionBoth)
			if err != nil {
				continue
			}

			for _, rel := range rels {
				subgraph.Relationships = append(subgraph.Relationships, rel)

				// Add neighbor entities.
				neighbors := []uuid.UUID{rel.SourceEntityID, rel.TargetEntityID}
				for _, nid := range neighbors {
					if !visited[nid] {
						visited[nid] = true
						nextFrontier = append(nextFrontier, nid)

						neighbor, err := s.Get(ctx, nid)
						if err == nil {
							subgraph.Entities[nid] = neighbor
						}
					}
				}
			}
		}

		frontier = nextFrontier
	}

	return subgraph, nil
}

// Search searches entities by value substring, returning matches
// with context about their relationships.
func (s *Store) Search(ctx context.Context, query string, projectID uuid.UUID, limit int) ([]domain.Entity, error) {
	if limit <= 0 {
		limit = 50
	}

	q := strings.TrimSpace(query)
	if q == "" {
		return nil, nil
	}

	return s.Query(ctx, domain.EntityFilter{
		ProjectID:     &projectID,
		ValueContains: q,
		Limit:         limit,
	})
}
