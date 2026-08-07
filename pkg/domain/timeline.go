package domain

import (
	"time"

	"github.com/google/uuid"
)

// TimelineEvent is an immutable record of a state change in the
// workspace. The timeline is append-only — events are never modified
// or deleted.
//
// The timeline serves two purposes:
//  1. Historical browsing: "when was entity X first seen?",
//     "what changed today?", "show me the last week of activity"
//  2. Event replay: the workspace state at any point in time can
//     be reconstructed by replaying events up to that timestamp
type TimelineEvent struct {
	// ID is the unique identifier for this event.
	ID uuid.UUID `json:"id"`

	// Type mirrors the event bus event type (e.g., "entity.created",
	// "observation.created", "hypothesis.updated").
	Type string `json:"type"`

	// SubjectType identifies what kind of object changed
	// (e.g., "entity", "observation", "hypothesis").
	SubjectType string `json:"subject_type"`

	// SubjectID is the identifier of the object that changed.
	SubjectID uuid.UUID `json:"subject_id"`

	// Action describes what happened to the subject
	// (e.g., "created", "changed", "deleted", "resolved", "merged").
	Action string `json:"action"`

	// Before is the state before the change. Nil for creation events.
	Before map[string]any `json:"before,omitempty"`

	// After is the state after the change. Nil for deletion events.
	After map[string]any `json:"after,omitempty"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// OccurredAt is when this event happened.
	OccurredAt time.Time `json:"occurred_at"`
}

// TimelineFilter specifies criteria for querying timeline events.
type TimelineFilter struct {
	ProjectID   *uuid.UUID `json:"project_id,omitempty"`
	SubjectType *string    `json:"subject_type,omitempty"`
	SubjectID   *uuid.UUID `json:"subject_id,omitempty"`
	Action      *string    `json:"action,omitempty"`
	From        *time.Time `json:"from,omitempty"`
	To          *time.Time `json:"to,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
}

// Snapshot is a point-in-time marker of the Knowledge Graph state.
// Snapshots enable diffing: comparing two snapshots reveals exactly
// what changed between them.
type Snapshot struct {
	// ID is the unique identifier for this snapshot.
	ID uuid.UUID `json:"id"`

	// Label is an optional human-readable label for this snapshot
	// (e.g., "before-retest", "end-of-day-2").
	Label *string `json:"label,omitempty"`

	// EntityCount is the total number of entities at snapshot time.
	EntityCount int `json:"entity_count"`

	// RelationshipCount is the total number of relationships at snapshot time.
	RelationshipCount int `json:"relationship_count"`

	// ObservationCount is the total number of observations at snapshot time.
	ObservationCount int `json:"observation_count"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// CreatedAt is when this snapshot was taken.
	CreatedAt time.Time `json:"created_at"`

	// EntityHashes maps entity IDs to content hashes at snapshot time.
	// Used by the Diff Engine to detect which entities changed.
	EntityHashes map[uuid.UUID]string `json:"entity_hashes"`
}

// Diff is a structural comparison between two snapshots, computed
// by the Diff Engine. Diffs answer the question "what changed?"
// without requiring the AI to re-read everything.
type Diff struct {
	// ID is the unique identifier for this diff.
	ID uuid.UUID `json:"id"`

	// SnapshotAID is the "before" snapshot.
	SnapshotAID uuid.UUID `json:"snapshot_a_id"`

	// SnapshotBID is the "after" snapshot.
	SnapshotBID uuid.UUID `json:"snapshot_b_id"`

	// EntitiesAdded lists entity IDs present in B but not in A.
	EntitiesAdded []uuid.UUID `json:"entities_added"`

	// EntitiesRemoved lists entity IDs present in A but not in B.
	EntitiesRemoved []uuid.UUID `json:"entities_removed"`

	// EntitiesChanged lists entities whose content hash differs
	// between A and B, with details of what changed.
	EntitiesChanged []EntityDiff `json:"entities_changed"`

	// RelationshipsAdded lists relationship IDs present in B but not in A.
	RelationshipsAdded []uuid.UUID `json:"relationships_added"`

	// RelationshipsRemoved lists relationship IDs present in A but not in B.
	RelationshipsRemoved []uuid.UUID `json:"relationships_removed"`

	// Summary is a human-readable summary of the changes.
	Summary string `json:"summary"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// ComputedAt is when this diff was calculated.
	ComputedAt time.Time `json:"computed_at"`
}

// EntityDiff describes what changed for a single entity between
// two snapshots.
type EntityDiff struct {
	// EntityID is the entity that changed.
	EntityID uuid.UUID `json:"entity_id"`

	// ChangedFields lists the field names that differ between snapshots.
	ChangedFields []string `json:"changed_fields"`

	// Before holds the field values before the change.
	Before map[string]any `json:"before,omitempty"`

	// After holds the field values after the change.
	After map[string]any `json:"after,omitempty"`
}
