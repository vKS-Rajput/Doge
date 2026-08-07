// Package events defines all event types that flow through the Event Bus.
//
// Events are the communication mechanism on the async write path:
// File Watcher → Parser → Observation Engine → Knowledge Graph →
// Timeline / Diff / Insight / Memory.
//
// Every event is a typed struct with a fixed payload. The Event Bus
// dispatches events to subscribers filtered by topic. Events are
// immutable once published.
//
// Event naming convention: "<subject>.<action>"
// Examples: "file.created", "entity.enriched", "hypothesis.updated"
package events

import (
	"time"

	"github.com/google/uuid"
)

// Topic is a string identifier for event routing.
// Subscribers register interest in specific topics.
type Topic string

// Event topics. Each constant corresponds to one event type.
const (
	// File events (Producer: File Watcher)
	TopicFileCreated Topic = "file.created"
	TopicFileChanged Topic = "file.changed"
	TopicFileDeleted Topic = "file.deleted"

	// Artifact events (Producer: Artifact Store)
	TopicArtifactStored    Topic = "artifact.stored"
	TopicArtifactDuplicate Topic = "artifact.duplicate"

	// Observation events (Producer: Observation Engine)
	TopicObservationCreated   Topic = "observation.created"
	TopicObservationBatch     Topic = "observation.batch"
	TopicObservationDuplicate Topic = "observation.duplicate"

	// Entity events (Producer: Knowledge Graph)
	TopicEntityCreated  Topic = "entity.created"
	TopicEntityEnriched Topic = "entity.enriched"
	TopicEntityMerged   Topic = "entity.merged"

	// Relationship events (Producer: Knowledge Graph)
	TopicRelationshipCreated Topic = "relationship.created"
	TopicRelationshipUpdated Topic = "relationship.updated"

	// Correlation events (Producer: Correlation Engine)
	TopicCorrelationDiscovered Topic = "correlation.discovered"

	// Insight events (Producer: Rule Engine, Insight Engine)
	TopicInsightDetected Topic = "insight.detected"

	// Hypothesis events (Producer: Hypothesis Engine)
	TopicHypothesisCreated Topic = "hypothesis.created"
	TopicHypothesisUpdated Topic = "hypothesis.updated"

	// Task events (Producer: Task Engine)
	TopicTaskCreated   Topic = "task.created"
	TopicTaskCompleted Topic = "task.completed"

	// Session events (Producer: Session Manager)
	TopicSessionStarted   Topic = "session.started"
	TopicSessionCompleted Topic = "session.completed"

	// Snapshot & Diff events
	TopicSnapshotCreated Topic = "snapshot.created"
	TopicDiffComputed    Topic = "diff.computed"

	// System events
	TopicModuleHealthChanged Topic = "module.health_changed"
	TopicCacheInvalidated    Topic = "cache.invalidated"
)

// Event is the interface that all events must implement.
type Event interface {
	// EventTopic returns the topic string for routing.
	EventTopic() Topic

	// EventTime returns when the event occurred.
	EventTime() time.Time

	// EventID returns a unique identifier for this event instance.
	EventID() uuid.UUID
}

// BaseEvent provides common fields shared by all events.
// Embed this in concrete event types.
type BaseEvent struct {
	ID        uuid.UUID `json:"id"`
	Timestamp time.Time `json:"timestamp"`
}

// EventID returns the unique identifier for this event.
func (e BaseEvent) EventID() uuid.UUID { return e.ID }

// EventTime returns when this event occurred.
func (e BaseEvent) EventTime() time.Time { return e.Timestamp }

// NewBaseEvent creates a BaseEvent with a new UUID and current timestamp.
func NewBaseEvent() BaseEvent {
	return BaseEvent{
		ID:        uuid.New(),
		Timestamp: time.Now().UTC(),
	}
}

// --- File Events ---

// FileCreated is emitted when a new file appears in a watched directory.
type FileCreated struct {
	BaseEvent
	Path      string    `json:"path"`
	ProjectID uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e FileCreated) EventTopic() Topic { return TopicFileCreated }

// FileChanged is emitted when an existing watched file is modified.
type FileChanged struct {
	BaseEvent
	Path      string    `json:"path"`
	ProjectID uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e FileChanged) EventTopic() Topic { return TopicFileChanged }

// FileDeleted is emitted when a watched file is removed.
type FileDeleted struct {
	BaseEvent
	Path      string    `json:"path"`
	ProjectID uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e FileDeleted) EventTopic() Topic { return TopicFileDeleted }

// --- Artifact Events ---

// ArtifactStored is emitted when a file is successfully indexed
// in the Artifact Store.
type ArtifactStored struct {
	BaseEvent
	ArtifactID uuid.UUID `json:"artifact_id"`
	SHA256     string    `json:"sha256"`
	Path       string    `json:"path"`
	ProjectID  uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e ArtifactStored) EventTopic() Topic { return TopicArtifactStored }

// ArtifactDuplicate is emitted when an imported file matches an
// existing artifact by content hash.
type ArtifactDuplicate struct {
	BaseEvent
	ArtifactID         uuid.UUID `json:"artifact_id"`
	ExistingArtifactID uuid.UUID `json:"existing_artifact_id"`
	SHA256             string    `json:"sha256"`
}

// EventTopic returns the routing topic.
func (e ArtifactDuplicate) EventTopic() Topic { return TopicArtifactDuplicate }

// --- Observation Events ---

// ObservationCreated is emitted when a single observation is ingested.
type ObservationCreated struct {
	BaseEvent
	ObservationID uuid.UUID `json:"observation_id"`
	Type          string    `json:"type"`
	ArtifactID    uuid.UUID `json:"artifact_id"`
	ProjectID     uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e ObservationCreated) EventTopic() Topic { return TopicObservationCreated }

// ObservationBatch is emitted when multiple observations are ingested
// from a single artifact.
type ObservationBatch struct {
	BaseEvent
	ObservationIDs []uuid.UUID `json:"observation_ids"`
	Type           string      `json:"type"`
	ArtifactID     uuid.UUID   `json:"artifact_id"`
	ProjectID      uuid.UUID   `json:"project_id"`
	Count          int         `json:"count"`
}

// EventTopic returns the routing topic.
func (e ObservationBatch) EventTopic() Topic { return TopicObservationBatch }

// ObservationDuplicate is emitted when an observation is skipped
// because an identical one already exists (same checksum + project).
type ObservationDuplicate struct {
	BaseEvent
	ObservationID         uuid.UUID `json:"observation_id"`
	ExistingObservationID uuid.UUID `json:"existing_observation_id"`
	Checksum              string    `json:"checksum"`
}

// EventTopic returns the routing topic.
func (e ObservationDuplicate) EventTopic() Topic { return TopicObservationDuplicate }

// --- Entity Events ---

// EntityCreated is emitted when a new entity is added to the Knowledge Graph.
type EntityCreated struct {
	BaseEvent
	EntityID  uuid.UUID `json:"entity_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	ProjectID uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e EntityCreated) EventTopic() Topic { return TopicEntityCreated }

// EntityEnriched is emitted when an existing entity receives new
// attributes from a new observation.
type EntityEnriched struct {
	BaseEvent
	EntityID      uuid.UUID      `json:"entity_id"`
	NewAttributes map[string]any `json:"new_attributes"`
	ObservationID uuid.UUID      `json:"observation_id"`
}

// EventTopic returns the routing topic.
func (e EntityEnriched) EventTopic() Topic { return TopicEntityEnriched }

// EntityMerged is emitted when the Entity Resolver merges a duplicate
// entity into a canonical one.
type EntityMerged struct {
	BaseEvent
	CanonicalID uuid.UUID `json:"canonical_id"`
	MergedID    uuid.UUID `json:"merged_id"`
	Reason      string    `json:"reason"`
}

// EventTopic returns the routing topic.
func (e EntityMerged) EventTopic() Topic { return TopicEntityMerged }

// --- Relationship Events ---

// RelationshipCreated is emitted when a new relationship is added
// to the Knowledge Graph.
type RelationshipCreated struct {
	BaseEvent
	RelationshipID uuid.UUID `json:"relationship_id"`
	SourceEntityID uuid.UUID `json:"source_entity_id"`
	TargetEntityID uuid.UUID `json:"target_entity_id"`
	Type           string    `json:"type"`
	ProjectID      uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e RelationshipCreated) EventTopic() Topic { return TopicRelationshipCreated }

// RelationshipUpdated is emitted when an existing relationship's
// attributes change.
type RelationshipUpdated struct {
	BaseEvent
	RelationshipID    uuid.UUID      `json:"relationship_id"`
	ChangedAttributes map[string]any `json:"changed_attributes"`
}

// EventTopic returns the routing topic.
func (e RelationshipUpdated) EventTopic() Topic { return TopicRelationshipUpdated }

// --- Correlation Events ---

// CorrelationDiscovered is emitted when the Correlation Engine
// identifies a link between related entities.
type CorrelationDiscovered struct {
	BaseEvent
	CorrelationID uuid.UUID   `json:"correlation_id"`
	EntityIDs     []uuid.UUID `json:"entity_ids"`
	Type          string      `json:"type"`
	Confidence    float64     `json:"confidence"`
}

// EventTopic returns the routing topic.
func (e CorrelationDiscovered) EventTopic() Topic { return TopicCorrelationDiscovered }

// --- Insight Events ---

// InsightDetected is emitted when the Rule Engine or Insight Engine
// detects a pattern.
type InsightDetected struct {
	BaseEvent
	InsightID uuid.UUID   `json:"insight_id"`
	Type      string      `json:"type"`
	Severity  string      `json:"severity"`
	EntityIDs []uuid.UUID `json:"entity_ids"`
	RuleID    *string     `json:"rule_id,omitempty"`
}

// EventTopic returns the routing topic.
func (e InsightDetected) EventTopic() Topic { return TopicInsightDetected }

// --- Hypothesis Events ---

// HypothesisCreated is emitted when a new hypothesis is proposed.
type HypothesisCreated struct {
	BaseEvent
	HypothesisID uuid.UUID `json:"hypothesis_id"`
	Title        string    `json:"title"`
	Confidence   float64   `json:"confidence"`
	Status       string    `json:"status"`
}

// EventTopic returns the routing topic.
func (e HypothesisCreated) EventTopic() Topic { return TopicHypothesisCreated }

// HypothesisUpdated is emitted when a hypothesis's confidence or status changes.
type HypothesisUpdated struct {
	BaseEvent
	HypothesisID  uuid.UUID `json:"hypothesis_id"`
	OldConfidence float64   `json:"old_confidence"`
	NewConfidence float64   `json:"new_confidence"`
	OldStatus     string    `json:"old_status"`
	NewStatus     string    `json:"new_status"`
}

// EventTopic returns the routing topic.
func (e HypothesisUpdated) EventTopic() Topic { return TopicHypothesisUpdated }

// --- Task Events ---

// TaskCreated is emitted when the Task Engine surfaces a new actionable item.
type TaskCreated struct {
	BaseEvent
	TaskID    uuid.UUID   `json:"task_id"`
	Type      string      `json:"type"`
	Priority  string      `json:"priority"`
	EntityIDs []uuid.UUID `json:"entity_ids"`
}

// EventTopic returns the routing topic.
func (e TaskCreated) EventTopic() Topic { return TopicTaskCreated }

// TaskCompleted is emitted when a task is completed or skipped.
type TaskCompleted struct {
	BaseEvent
	TaskID      uuid.UUID `json:"task_id"`
	CompletedAt time.Time `json:"completed_at"`
}

// EventTopic returns the routing topic.
func (e TaskCompleted) EventTopic() Topic { return TopicTaskCompleted }

// --- Session Events ---

// SessionStarted is emitted when an AI invocation begins.
type SessionStarted struct {
	BaseEvent
	SessionID uuid.UUID `json:"session_id"`
	Type      string    `json:"type"`
	Question  string    `json:"question"`
}

// EventTopic returns the routing topic.
func (e SessionStarted) EventTopic() Topic { return TopicSessionStarted }

// SessionCompleted is emitted when an AI invocation finishes.
type SessionCompleted struct {
	BaseEvent
	SessionID  uuid.UUID `json:"session_id"`
	Rejected   bool      `json:"rejected"`
	DurationMs int64     `json:"duration_ms"`
	TokensUsed int       `json:"tokens_used"`
}

// EventTopic returns the routing topic.
func (e SessionCompleted) EventTopic() Topic { return TopicSessionCompleted }

// --- Snapshot & Diff Events ---

// SnapshotCreated is emitted when a new point-in-time snapshot is taken.
type SnapshotCreated struct {
	BaseEvent
	SnapshotID  uuid.UUID `json:"snapshot_id"`
	EntityCount int       `json:"entity_count"`
	ProjectID   uuid.UUID `json:"project_id"`
}

// EventTopic returns the routing topic.
func (e SnapshotCreated) EventTopic() Topic { return TopicSnapshotCreated }

// DiffComputed is emitted when a structural diff between two snapshots
// is calculated.
type DiffComputed struct {
	BaseEvent
	DiffID       uuid.UUID `json:"diff_id"`
	SnapshotAID  uuid.UUID `json:"snapshot_a_id"`
	SnapshotBID  uuid.UUID `json:"snapshot_b_id"`
	AddedCount   int       `json:"added_count"`
	RemovedCount int       `json:"removed_count"`
	ChangedCount int       `json:"changed_count"`
}

// EventTopic returns the routing topic.
func (e DiffComputed) EventTopic() Topic { return TopicDiffComputed }

// --- System Events ---

// ModuleHealthChanged is emitted when a module's health status transitions.
type ModuleHealthChanged struct {
	BaseEvent
	Module    string `json:"module"`
	OldHealth string `json:"old_health"`
	NewHealth string `json:"new_health"`
	Reason    string `json:"reason"`
}

// EventTopic returns the routing topic.
func (e ModuleHealthChanged) EventTopic() Topic { return TopicModuleHealthChanged }

// CacheInvalidated is emitted when a cache entry is invalidated due
// to upstream data changes.
type CacheInvalidated struct {
	BaseEvent
	CacheType string `json:"cache_type"`
	Key       string `json:"key"`
	Reason    string `json:"reason"`
}

// EventTopic returns the routing topic.
func (e CacheInvalidated) EventTopic() Topic { return TopicCacheInvalidated }
