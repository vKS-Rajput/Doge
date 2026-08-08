// Package diff provides the Diff Engine for comparing workspace state
// across points in time.
//
// The Diff Engine creates snapshots (point-in-time captures of the
// Knowledge Graph) and computes structural diffs between them.
//
// This is designed to become Doge's flagship feature:
//
//	doge diff previous current
//
//	+ 5 endpoints
//	+ GraphQL
//	- 1 header
//	Modified CSP
//	New redirect
//
// Architecture:
//
//	Snapshot A (materialized from current entity state)
//	    ↓
//	Structural Comparison
//	    ↓
//	DiffResult
//	    ↓
//	insight.detected events (for significant changes)
//
// The snapshots table stores entity hashes so diffs can be computed
// without loading every entity into memory.
package diff

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// EntitySnapshot captures an entity's identity and state at a point in time.
type EntitySnapshot struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Hash  string `json:"hash"` // Content hash of (type + value + sorted attributes).
}

// Snapshot is a point-in-time capture of the Knowledge Graph state.
type Snapshot struct {
	ID                uuid.UUID `json:"id"`
	Label             string    `json:"label"`
	EntityCount       int       `json:"entity_count"`
	RelationshipCount int       `json:"relationship_count"`
	ObservationCount  int       `json:"observation_count"`
	ProjectID         uuid.UUID `json:"project_id"`
	CreatedAt         time.Time `json:"created_at"`
}

// Change represents a single difference between two snapshots.
type Change struct {
	Action     string `json:"action"`      // "added", "removed", "changed"
	EntityType string `json:"entity_type"`
	Value      string `json:"value"`
	Detail     string `json:"detail,omitempty"` // Additional context for "changed" actions.
}

// DiffResult holds the complete comparison between two snapshots.
type DiffResult struct {
	ID          uuid.UUID `json:"id"`
	SnapshotA   Snapshot  `json:"snapshot_a"`
	SnapshotB   Snapshot  `json:"snapshot_b"`
	Added       []Change  `json:"added"`
	Removed     []Change  `json:"removed"`
	Changed     []Change  `json:"changed"`
	ProjectID   uuid.UUID `json:"project_id"`
	ComputedAt  time.Time `json:"computed_at"`
}

// Summary returns a human-readable summary of the diff.
func (d DiffResult) Summary() string {
	return fmt.Sprintf("+%d added, -%d removed, ~%d changed",
		len(d.Added), len(d.Removed), len(d.Changed))
}

// Engine creates snapshots and computes structural diffs.
type Engine struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// NewEngine creates a new Diff Engine.
func NewEngine(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Engine {
	return &Engine{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// TakeSnapshot creates a new point-in-time snapshot of the Knowledge Graph.
// The snapshot captures entity hashes for efficient diffing.
func (e *Engine) TakeSnapshot(ctx context.Context, projectID uuid.UUID, label string) (Snapshot, error) {
	now := time.Now().UTC()
	snapID := uuid.New()

	// Count entities, relationships, observations.
	var entityCount, relCount, obsCount int
	e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM entities WHERE project_id = ?`, projectID.String()).Scan(&entityCount)
	e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM relationships WHERE project_id = ?`, projectID.String()).Scan(&relCount)
	e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observations WHERE project_id = ?`, projectID.String()).Scan(&obsCount)

	// Build entity hashes map: {entity_id → content_hash}.
	entityHashes, err := e.buildEntityHashes(ctx, projectID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("building entity hashes: %w", err)
	}

	hashesJSON, err := json.Marshal(entityHashes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("marshaling entity hashes: %w", err)
	}

	// Persist snapshot.
	_, err = e.db.ExecContext(ctx,
		`INSERT INTO snapshots (id, label, entity_count, relationship_count,
		                        observation_count, entity_hashes, project_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		snapID.String(), label, entityCount, relCount, obsCount,
		string(hashesJSON), projectID.String(), now.Format(time.RFC3339))
	if err != nil {
		return Snapshot{}, fmt.Errorf("persisting snapshot: %w", err)
	}

	snapshot := Snapshot{
		ID:                snapID,
		Label:             label,
		EntityCount:       entityCount,
		RelationshipCount: relCount,
		ObservationCount:  obsCount,
		ProjectID:         projectID,
		CreatedAt:         now,
	}

	e.logger.Info("snapshot created",
		"id", snapID.String(),
		"label", label,
		"entities", entityCount,
		"relationships", relCount,
	)

	// Emit event.
	e.bus.Publish(ctx, events.SnapshotCreated{
		BaseEvent:   events.NewBaseEvent(),
		SnapshotID:  snapID,
		EntityCount: entityCount,
		ProjectID:   projectID,
	})

	return snapshot, nil
}

// ComputeDiff computes the structural difference between two snapshots.
func (e *Engine) ComputeDiff(ctx context.Context, snapshotAID, snapshotBID uuid.UUID) (*DiffResult, error) {
	// Load both snapshots.
	snapA, hashesA, err := e.loadSnapshot(ctx, snapshotAID)
	if err != nil {
		return nil, fmt.Errorf("loading snapshot A: %w", err)
	}
	snapB, hashesB, err := e.loadSnapshot(ctx, snapshotBID)
	if err != nil {
		return nil, fmt.Errorf("loading snapshot B: %w", err)
	}

	var added, removed, changed []Change

	// Find added and changed entities.
	for key, snapB := range hashesB {
		snapAEntry, exists := hashesA[key]
		if !exists {
			added = append(added, Change{
				Action:     "added",
				EntityType: snapB.Type,
				Value:      snapB.Value,
			})
		} else if snapAEntry.Hash != snapB.Hash {
			changed = append(changed, Change{
				Action:     "changed",
				EntityType: snapB.Type,
				Value:      snapB.Value,
				Detail:     "Attributes changed",
			})
		}
	}

	// Find removed entities.
	for key, snapAEntry := range hashesA {
		if _, exists := hashesB[key]; !exists {
			removed = append(removed, Change{
				Action:     "removed",
				EntityType: snapAEntry.Type,
				Value:      snapAEntry.Value,
			})
		}
	}

	// Sort for deterministic output.
	sortChanges(added)
	sortChanges(removed)
	sortChanges(changed)

	now := time.Now().UTC()
	diffID := uuid.New()

	result := &DiffResult{
		ID:         diffID,
		SnapshotA:  snapA,
		SnapshotB:  snapB,
		Added:      added,
		Removed:    removed,
		Changed:    changed,
		ProjectID:  snapA.ProjectID,
		ComputedAt: now,
	}

	// Persist diff.
	addedJSON, _ := json.Marshal(changeIDs(added))
	removedJSON, _ := json.Marshal(changeIDs(removed))
	changedJSON, _ := json.Marshal(changeIDs(changed))

	_, err = e.db.ExecContext(ctx,
		`INSERT INTO diffs (id, snapshot_a_id, snapshot_b_id,
		                    entities_added, entities_removed, entities_changed,
		                    summary, project_id, computed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		diffID.String(), snapshotAID.String(), snapshotBID.String(),
		string(addedJSON), string(removedJSON), string(changedJSON),
		result.Summary(), snapA.ProjectID.String(), now.Format(time.RFC3339))
	if err != nil {
		e.logger.Warn("failed to persist diff", "error", err)
	}

	e.logger.Info("diff computed",
		"id", diffID.String(),
		"added", len(added),
		"removed", len(removed),
		"changed", len(changed),
	)

	// Emit event.
	e.bus.Publish(ctx, events.DiffComputed{
		BaseEvent:    events.NewBaseEvent(),
		DiffID:       diffID,
		SnapshotAID:  snapshotAID,
		SnapshotBID:  snapshotBID,
		AddedCount:   len(added),
		RemovedCount: len(removed),
		ChangedCount: len(changed),
	})

	return result, nil
}

// ListSnapshots returns all snapshots for a project, ordered by creation time.
func (e *Engine) ListSnapshots(ctx context.Context, projectID uuid.UUID) ([]Snapshot, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT id, label, entity_count, relationship_count, observation_count,
		        project_id, created_at
		 FROM snapshots WHERE project_id = ?
		 ORDER BY created_at DESC`, projectID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			continue
		}
		snapshots = append(snapshots, s)
	}
	return snapshots, rows.Err()
}

// --- Internal ---

// buildEntityHashes creates a map of entity content hashes for the current state.
// Key is "type:value" to enable identity-based comparison.
func (e *Engine) buildEntityHashes(ctx context.Context, projectID uuid.UUID) (map[string]EntitySnapshot, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT id, type, value, attributes FROM entities WHERE project_id = ?`,
		projectID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hashes := make(map[string]EntitySnapshot)
	for rows.Next() {
		var id, entityType, value, attrsJSON string
		if err := rows.Scan(&id, &entityType, &value, &attrsJSON); err != nil {
			continue
		}

		// Content hash = sha256(type + value + sorted_attributes).
		hash := contentHash(entityType, value, attrsJSON)
		key := entityType + ":" + value

		hashes[key] = EntitySnapshot{
			ID:    id,
			Type:  entityType,
			Value: value,
			Hash:  hash,
		}
	}

	return hashes, rows.Err()
}

// contentHash creates a deterministic hash of an entity's content.
func contentHash(entityType, value, attrsJSON string) string {
	h := sha256.New()
	h.Write([]byte(entityType))
	h.Write([]byte(":"))
	h.Write([]byte(value))
	h.Write([]byte(":"))
	h.Write([]byte(attrsJSON))
	return fmt.Sprintf("%x", h.Sum(nil))[:16] // Short hash is fine for diffing.
}

func (e *Engine) loadSnapshot(ctx context.Context, id uuid.UUID) (Snapshot, map[string]EntitySnapshot, error) {
	var snap Snapshot
	var snapID, label, projectID, createdAt, hashesJSON string
	var entityCount, relCount, obsCount int

	err := e.db.QueryRowContext(ctx,
		`SELECT id, label, entity_count, relationship_count, observation_count,
		        entity_hashes, project_id, created_at
		 FROM snapshots WHERE id = ?`, id.String()).Scan(
		&snapID, &label, &entityCount, &relCount, &obsCount,
		&hashesJSON, &projectID, &createdAt)
	if err != nil {
		return snap, nil, err
	}

	snap.ID = uuid.MustParse(snapID)
	snap.Label = label
	snap.EntityCount = entityCount
	snap.RelationshipCount = relCount
	snap.ObservationCount = obsCount
	snap.ProjectID = uuid.MustParse(projectID)
	snap.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	var hashes map[string]EntitySnapshot
	if err := json.Unmarshal([]byte(hashesJSON), &hashes); err != nil {
		return snap, nil, fmt.Errorf("parsing entity hashes: %w", err)
	}

	return snap, hashes, nil
}

func scanSnapshot(rows *sql.Rows) (Snapshot, error) {
	var s Snapshot
	var id, label, projectID, createdAt string

	err := rows.Scan(&id, &label, &s.EntityCount, &s.RelationshipCount,
		&s.ObservationCount, &projectID, &createdAt)
	if err != nil {
		return s, err
	}

	s.ID = uuid.MustParse(id)
	s.Label = label
	s.ProjectID = uuid.MustParse(projectID)
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return s, nil
}

func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].EntityType != changes[j].EntityType {
			return changes[i].EntityType < changes[j].EntityType
		}
		return changes[i].Value < changes[j].Value
	})
}

func changeIDs(changes []Change) []string {
	ids := make([]string, len(changes))
	for i, c := range changes {
		ids[i] = c.EntityType + ":" + c.Value
	}
	return ids
}
