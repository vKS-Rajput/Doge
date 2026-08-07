// Package observation provides observation validation and persistence.
//
// The observation layer sits between parsers and the knowledge graph.
// Its job is to ensure that only valid, well-formed observations enter
// the system. Bad observations are rejected before they can corrupt
// the graph.
//
// Two components:
//   - Validate: checks required fields, enum values, timestamps, provenance
//   - Store: persists validated observations, deduplicates by checksum
package observation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// knownTypes is the set of valid ObservationTypes.
var knownTypes = map[domain.ObservationType]bool{
	domain.ObservationSubdomainDiscovery: true,
	domain.ObservationHTTPProbe:          true,
	domain.ObservationEndpointDiscovery:  true,
	domain.ObservationVulnerabilityScan:  true,
	domain.ObservationJavaScriptAnalysis: true,
	domain.ObservationScreenshotCapture:  true,
	domain.ObservationDNSLookup:          true,
	domain.ObservationPortScan:           true,
	domain.ObservationTechnologyDetect:   true,
	domain.ObservationCertificateInfo:    true,
	domain.ObservationHARCapture:         true,
	domain.ObservationResearcherNote:     true,
	domain.ObservationCrawlResult:        true,
	domain.ObservationAPIDiscovery:       true,
	domain.ObservationAuthProbe:          true,
}

// ValidateRaw checks a RawObservation for required fields and valid values.
// Returns an error describing the first violation found.
// Bad observations never enter the graph.
func ValidateRaw(obs domain.RawObservation) error {
	if obs.Type == "" {
		return fmt.Errorf("observation validation: Type is empty")
	}
	if !knownTypes[obs.Type] {
		return fmt.Errorf("observation validation: unknown Type %q", obs.Type)
	}
	if obs.SourceTool == "" {
		return fmt.Errorf("observation validation: SourceTool is empty")
	}
	if obs.Data == nil {
		return fmt.Errorf("observation validation: Data is nil")
	}
	if obs.ObservedAt.IsZero() {
		return fmt.Errorf("observation validation: ObservedAt is zero")
	}
	if obs.ObservedAt.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("observation validation: ObservedAt is in the future")
	}
	if obs.RawValue == "" {
		return fmt.Errorf("observation validation: RawValue is empty")
	}
	return nil
}

// Validate checks a canonical Observation for all required fields,
// including provenance (ArtifactID, ProjectID) and checksum.
func Validate(obs domain.Observation) error {
	if obs.ID == uuid.Nil {
		return fmt.Errorf("observation validation: ID is nil")
	}
	if obs.Type == "" {
		return fmt.Errorf("observation validation: Type is empty")
	}
	if !knownTypes[obs.Type] {
		return fmt.Errorf("observation validation: unknown Type %q", obs.Type)
	}
	if obs.ArtifactID == uuid.Nil {
		return fmt.Errorf("observation validation: ArtifactID is nil (missing provenance)")
	}
	if obs.ProjectID == uuid.Nil {
		return fmt.Errorf("observation validation: ProjectID is nil")
	}
	if obs.SourceTool == "" {
		return fmt.Errorf("observation validation: SourceTool is empty")
	}
	if obs.Data == nil {
		return fmt.Errorf("observation validation: Data is nil")
	}
	if obs.Checksum == "" {
		return fmt.Errorf("observation validation: Checksum is empty")
	}
	if obs.ObservedAt.IsZero() {
		return fmt.Errorf("observation validation: ObservedAt is zero")
	}
	return nil
}

// ComputeChecksum computes a deterministic hash of an observation's Data
// for deduplication. Two observations with the same checksum and project
// are considered duplicates.
func ComputeChecksum(data map[string]any) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshaling data for checksum: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Normalize converts a RawObservation into a canonical Observation
// with full provenance and checksum.
func Normalize(raw domain.RawObservation, artifactID, projectID uuid.UUID, parserVersion string) (domain.Observation, error) {
	checksum, err := ComputeChecksum(raw.Data)
	if err != nil {
		return domain.Observation{}, err
	}

	obs := domain.Observation{
		ID:            uuid.New(),
		Type:          raw.Type,
		ArtifactID:    artifactID,
		SourceTool:    raw.SourceTool,
		ProjectID:     projectID,
		Data:          raw.Data,
		RawValue:      raw.RawValue,
		Checksum:      checksum,
		ObservedAt:    raw.ObservedAt,
		IngestedAt:    time.Now().UTC(),
		ParserVersion: parserVersion,
	}

	if err := Validate(obs); err != nil {
		return domain.Observation{}, err
	}

	return obs, nil
}

// Store persists validated observations to the database with
// deduplication by checksum+project.
type Store struct {
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// NewStore creates a new observation store.
func NewStore(db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Store {
	return &Store{
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// IngestResult describes the outcome of ingesting observations.
type IngestResult struct {
	Created    int
	Duplicates int
	Rejected   int
}

// IngestBatch validates, normalizes, and persists a batch of raw observations
// from a single artifact. Returns counts of created, duplicate, and rejected.
func (s *Store) IngestBatch(ctx context.Context, rawObs []domain.RawObservation, artifactID, projectID uuid.UUID, parserVersion string) (*IngestResult, error) {
	result := &IngestResult{}
	var createdIDs []uuid.UUID

	for i, raw := range rawObs {
		// Validate raw observation.
		if err := ValidateRaw(raw); err != nil {
			s.logger.Warn("observation rejected",
				"index", i,
				"error", err.Error(),
			)
			result.Rejected++
			continue
		}

		// Normalize to canonical observation.
		obs, err := Normalize(raw, artifactID, projectID, parserVersion)
		if err != nil {
			s.logger.Warn("observation normalization failed",
				"index", i,
				"error", err.Error(),
			)
			result.Rejected++
			continue
		}

		// Persist with deduplication.
		created, err := s.insert(ctx, obs)
		if err != nil {
			return nil, fmt.Errorf("inserting observation %d: %w", i, err)
		}

		if created {
			result.Created++
			createdIDs = append(createdIDs, obs.ID)
		} else {
			result.Duplicates++
		}
	}

	// Emit batch event if any observations were created.
	if len(createdIDs) > 0 {
		s.bus.Publish(ctx, events.ObservationBatch{
			BaseEvent:      events.NewBaseEvent(),
			ObservationIDs: createdIDs,
			Type:           string(rawObs[0].Type),
			ArtifactID:     artifactID,
			ProjectID:      projectID,
			Count:          len(createdIDs),
		})
	}

	s.logger.Info("batch ingestion complete",
		"artifact_id", artifactID.String(),
		"created", result.Created,
		"duplicates", result.Duplicates,
		"rejected", result.Rejected,
	)

	return result, nil
}

// insert persists a single observation. Returns true if created,
// false if duplicate (same checksum+project already exists).
func (s *Store) insert(ctx context.Context, obs domain.Observation) (bool, error) {
	dataJSON, err := json.Marshal(obs.Data)
	if err != nil {
		return false, fmt.Errorf("marshaling observation data: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO observations
		 (id, type, artifact_id, source_tool, project_id, data, raw_value,
		  checksum, observed_at, ingested_at, parser_version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		obs.ID.String(), string(obs.Type), obs.ArtifactID.String(),
		obs.SourceTool, obs.ProjectID.String(), string(dataJSON),
		obs.RawValue, obs.Checksum,
		obs.ObservedAt.Format(time.RFC3339), obs.IngestedAt.Format(time.RFC3339),
		obs.ParserVersion)

	if err != nil {
		return false, err
	}

	// Check if this was actually inserted (OR IGNORE swallows duplicates).
	var count int
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM observations WHERE id = ?`, obs.ID.String()).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
