package entity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Materializer subscribes to observation events and materializes
// entities and relationships into the Knowledge Graph.
//
// The Knowledge Graph is a projection of immutable observations.
// The Materializer is the only component that writes to the entity
// and relationship tables. It runs as an event handler on the Bus.
//
// Pipeline:
//
//	observation.batch event
//	    ↓
//	Load observations from DB
//	    ↓
//	Extract entities (resolver normalizes)
//	    ↓
//	Extract relationships
//	    ↓
//	Ingest into Entity Store
type Materializer struct {
	store  *Store
	db     *sql.DB
	bus    *bus.Bus
	logger *slog.Logger
}

// NewMaterializer creates a new entity materializer.
func NewMaterializer(store *Store, db *sql.DB, eventBus *bus.Bus, logger *slog.Logger) *Materializer {
	return &Materializer{
		store:  store,
		db:     db,
		bus:    eventBus,
		logger: logger,
	}
}

// Subscribe registers the materializer as a handler for observation events.
// Call this once during app startup.
func (m *Materializer) Subscribe() {
	m.bus.Subscribe(events.TopicObservationBatch, m.handleObservationBatch)
	m.logger.Info("materializer subscribed to observation events")
}

// handleObservationBatch processes a batch of observations, materializing
// entities and relationships from each one.
func (m *Materializer) handleObservationBatch(ctx context.Context, event events.Event) error {
	batch, ok := event.(events.ObservationBatch)
	if !ok {
		return fmt.Errorf("unexpected event type: %T", event)
	}

	m.logger.Info("materializing observation batch",
		"observation_count", batch.Count,
		"artifact_id", batch.ArtifactID.String(),
	)

	var totalEntities, totalRelationships int

	for _, obsID := range batch.ObservationIDs {
		obs, err := m.loadObservation(ctx, obsID)
		if err != nil {
			m.logger.Warn("failed to load observation",
				"observation_id", obsID.String(),
				"error", err,
			)
			continue
		}

		entities, rels := m.extractFromObservation(obs)

		// Ingest entities.
		entityMap := make(map[string]uuid.UUID) // key → entity ID (for relationship wiring)
		for _, extraction := range entities {
			result, err := m.store.Ingest(ctx, extraction.entityType, extraction.value,
				extraction.attributes, obsID, obs.ProjectID, obs.ObservedAt)
			if err != nil {
				m.logger.Warn("failed to ingest entity",
					"type", string(extraction.entityType),
					"value", extraction.value,
					"error", err,
				)
				continue
			}
			entityMap[extraction.key] = result.Entity.ID
			totalEntities++
		}

		// Ingest relationships.
		for _, relExtraction := range rels {
			sourceID, sourceOK := entityMap[relExtraction.sourceKey]
			targetID, targetOK := entityMap[relExtraction.targetKey]
			if !sourceOK || !targetOK {
				continue
			}

			rel := domain.Relationship{
				SourceEntityID: sourceID,
				TargetEntityID: targetID,
				Type:           relExtraction.relType,
				Attributes:     relExtraction.attributes,
				ObservationID:  &obsID,
				ProjectID:      obs.ProjectID,
				FirstSeenAt:    obs.ObservedAt,
				LastSeenAt:     obs.ObservedAt,
			}

			_, _, err := m.store.IngestRelationship(ctx, rel)
			if err != nil {
				m.logger.Warn("failed to ingest relationship",
					"type", string(relExtraction.relType),
					"error", err,
				)
				continue
			}
			totalRelationships++
		}
	}

	m.logger.Info("materialization complete",
		"entities", totalEntities,
		"relationships", totalRelationships,
	)

	return nil
}

// entityExtraction holds data needed to create an entity.
type entityExtraction struct {
	key        string // lookup key for relationship wiring
	entityType domain.EntityType
	value      string
	attributes map[string]any
}

// relationshipExtraction holds data needed to create a relationship.
type relationshipExtraction struct {
	sourceKey  string
	targetKey  string
	relType    domain.RelationshipType
	attributes map[string]any
}

// extractFromObservation extracts entities and relationships from a single
// observation based on its type.
func (m *Materializer) extractFromObservation(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	switch obs.Type {
	case domain.ObservationHTTPProbe:
		return m.extractHTTPProbe(obs)
	case domain.ObservationSubdomainDiscovery:
		return m.extractSubdomainDiscovery(obs)
	default:
		// For unsupported observation types, extract nothing.
		// As we add more parsers, we'll add more extractors here.
		return nil, nil
	}
}

// extractHTTPProbe extracts entities from an HTTP probe observation.
//
// From a single httpx observation we can extract:
//   - URL entity
//   - Host/Subdomain entity
//   - Technology entities (one per detected tech)
//   - Relationships: host → serves → url, url → uses_technology → tech
func (m *Materializer) extractHTTPProbe(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	rawURL, _ := obs.Data["url"].(string)
	host, _ := obs.Data["host"].(string)

	if rawURL == "" {
		return nil, nil
	}

	// Extract URL entity.
	urlAttrs := map[string]any{}
	if sc, ok := obs.Data["status_code"]; ok {
		urlAttrs["status_code"] = sc
	}
	if title, ok := obs.Data["title"].(string); ok && title != "" {
		urlAttrs["title"] = title
	}
	if ct, ok := obs.Data["content_type"].(string); ok && ct != "" {
		urlAttrs["content_type"] = ct
	}
	if ws, ok := obs.Data["webserver"].(string); ok && ws != "" {
		urlAttrs["webserver"] = ws
	}
	if method, ok := obs.Data["method"].(string); ok && method != "" {
		urlAttrs["method"] = method
	}

	entities = append(entities, entityExtraction{
		key:        "url:" + rawURL,
		entityType: domain.EntityURL,
		value:      rawURL,
		attributes: urlAttrs,
	})

	// Extract host entity.
	if host == "" {
		// Try to extract from URL.
		if u, err := url.Parse(rawURL); err == nil {
			host = u.Hostname()
		}
	}

	if host != "" {
		hostType := domain.EntitySubdomain
		// Simple heuristic: if it's a bare domain (one dot), use EntityDomain.
		if strings.Count(host, ".") <= 1 {
			hostType = domain.EntityDomain
		}

		hostAttrs := map[string]any{}
		if port, ok := obs.Data["port"].(string); ok && port != "" {
			hostAttrs["port"] = port
		}
		if scheme, ok := obs.Data["scheme"].(string); ok && scheme != "" {
			hostAttrs["scheme"] = scheme
		}

		entities = append(entities, entityExtraction{
			key:        "host:" + host,
			entityType: hostType,
			value:      host,
			attributes: hostAttrs,
		})

		// Relationship: host → serves → url
		rels = append(rels, relationshipExtraction{
			sourceKey:  "host:" + host,
			targetKey:  "url:" + rawURL,
			relType:    domain.RelServes,
			attributes: map[string]any{},
		})
	}

	// Extract technology entities.
	if techList, ok := obs.Data["technologies"]; ok {
		var techs []string

		switch v := techList.(type) {
		case []string:
			techs = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					techs = append(techs, s)
				}
			}
		}

		for _, tech := range techs {
			if tech == "" {
				continue
			}
			techKey := "tech:" + tech
			entities = append(entities, entityExtraction{
				key:        techKey,
				entityType: domain.EntityTechnology,
				value:      tech,
				attributes: map[string]any{},
			})

			// Relationship: url → uses_technology → tech
			rels = append(rels, relationshipExtraction{
				sourceKey:  "url:" + rawURL,
				targetKey:  techKey,
				relType:    domain.RelUsesTechnology,
				attributes: map[string]any{},
			})
		}
	}

	// Handle redirects: url → redirects_to → final_url
	if finalURL, ok := obs.Data["final_url"].(string); ok && finalURL != "" && finalURL != rawURL {
		finalKey := "url:" + finalURL
		entities = append(entities, entityExtraction{
			key:        finalKey,
			entityType: domain.EntityURL,
			value:      finalURL,
			attributes: map[string]any{},
		})

		rels = append(rels, relationshipExtraction{
			sourceKey:  "url:" + rawURL,
			targetKey:  finalKey,
			relType:    domain.RelRedirectsTo,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// extractSubdomainDiscovery extracts entities from a subdomain discovery
// observation.
func (m *Materializer) extractSubdomainDiscovery(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	subdomain, _ := obs.Data["subdomain"].(string)
	if subdomain == "" {
		return nil, nil
	}

	entities = append(entities, entityExtraction{
		key:        "subdomain:" + subdomain,
		entityType: domain.EntitySubdomain,
		value:      subdomain,
		attributes: map[string]any{},
	})

	// Try to extract parent domain.
	parts := strings.SplitN(subdomain, ".", 2)
	if len(parts) == 2 && strings.Contains(parts[1], ".") {
		parentDomain := parts[1]
		entities = append(entities, entityExtraction{
			key:        "domain:" + parentDomain,
			entityType: domain.EntityDomain,
			value:      parentDomain,
			attributes: map[string]any{},
		})

		rels = append(rels, relationshipExtraction{
			sourceKey:  "domain:" + parentDomain,
			targetKey:  "subdomain:" + subdomain,
			relType:    domain.RelHasSubdomain,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// loadObservation loads a single observation from the database.
func (m *Materializer) loadObservation(ctx context.Context, id uuid.UUID) (domain.Observation, error) {
	var obs domain.Observation
	var obsID, obsType, artifactID, sourceTool, projectID string
	var dataJSON, rawValue, checksum string
	var observedAt, ingestedAt, parserVersion string

	err := m.db.QueryRowContext(ctx,
		`SELECT id, type, artifact_id, source_tool, project_id, data, raw_value,
		        checksum, observed_at, ingested_at, parser_version
		 FROM observations WHERE id = ?`, id.String()).Scan(
		&obsID, &obsType, &artifactID, &sourceTool, &projectID,
		&dataJSON, &rawValue, &checksum, &observedAt, &ingestedAt, &parserVersion)
	if err != nil {
		return obs, err
	}

	obs.ID = uuid.MustParse(obsID)
	obs.Type = domain.ObservationType(obsType)
	obs.ArtifactID = uuid.MustParse(artifactID)
	obs.SourceTool = sourceTool
	obs.ProjectID = uuid.MustParse(projectID)
	obs.RawValue = rawValue
	obs.Checksum = checksum
	obs.ParserVersion = parserVersion
	obs.ObservedAt, _ = time.Parse(time.RFC3339, observedAt)
	obs.IngestedAt, _ = time.Parse(time.RFC3339, ingestedAt)
	_ = json.Unmarshal([]byte(dataJSON), &obs.Data)

	return obs, nil
}
