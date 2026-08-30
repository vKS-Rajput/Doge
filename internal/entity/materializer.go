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
	case domain.ObservationPortScan:
		return m.extractPortScan(obs)
	case domain.ObservationTechnologyDetect:
		return m.extractTechnologyDetect(obs)
	case domain.ObservationEndpointDiscovery:
		return m.extractEndpointDiscovery(obs)
	case domain.ObservationCrawlResult:
		return m.extractCrawlResult(obs)
	case domain.ObservationDNSLookup:
		return m.extractDNSLookup(obs)
	case domain.ObservationVulnerabilityScan:
		return m.extractVulnerabilityScan(obs)
	case domain.ObservationCertificateInfo:
		return m.extractCertificateInfo(obs)
	case domain.ObservationJavaScriptAnalysis:
		return m.extractJavaScriptAnalysis(obs)
	case domain.ObservationAPIDiscovery:
		return m.extractAPIDiscovery(obs)
	case domain.ObservationAuthProbe:
		return m.extractAuthProbe(obs)
	default:
		return nil, nil
	}
}

// extractPortScan creates entities from nmap port_scan observations.
//
// Entities: IPAddress/Host, Port, Service, Technology
// Relationships: host → listens_on → port, port → runs_service → service
func (m *Materializer) extractPortScan(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	host, _ := obs.Data["host"].(string)
	if host == "" {
		return nil, nil
	}
	hostname, _ := obs.Data["hostname"].(string)

	// Host entity.
	hostKey := "host:" + host
	hostAttrs := map[string]any{}
	if hostname != "" {
		hostAttrs["hostname"] = hostname
	}
	entities = append(entities, entityExtraction{
		key:        hostKey,
		entityType: domain.EntityIPAddress,
		value:      host,
		attributes: hostAttrs,
	})

	// Port entity.
	portNum := toInt(obs.Data["port"])
	protocol, _ := obs.Data["protocol"].(string)
	state, _ := obs.Data["state"].(string)
	if portNum > 0 {
		portVal := fmt.Sprintf("%d/%s", portNum, protocol)
		portKey := "port:" + host + ":" + portVal
		portAttrs := map[string]any{
			"port":     portNum,
			"protocol": protocol,
			"state":    state,
		}
		entities = append(entities, entityExtraction{
			key:        portKey,
			entityType: domain.EntityPort,
			value:      portVal,
			attributes: portAttrs,
		})

		rels = append(rels, relationshipExtraction{
			sourceKey:  hostKey,
			targetKey:  portKey,
			relType:    domain.RelListensOn,
			attributes: map[string]any{},
		})

		// Service entity.
		service, _ := obs.Data["service"].(string)
		if service != "" {
			serviceKey := "service:" + host + ":" + service
			serviceAttrs := map[string]any{"port": portNum}
			entities = append(entities, entityExtraction{
				key:        serviceKey,
				entityType: domain.EntityService,
				value:      service,
				attributes: serviceAttrs,
			})

			rels = append(rels, relationshipExtraction{
				sourceKey:  portKey,
				targetKey:  serviceKey,
				relType:    domain.RelRunsService,
				attributes: map[string]any{},
			})
		}

		// Technology entity (product/version).
		product, _ := obs.Data["product"].(string)
		version, _ := obs.Data["version"].(string)
		if product != "" {
			techVal := product
			if version != "" {
				techVal += " " + version
			}
			techKey := "tech:" + techVal
			entities = append(entities, entityExtraction{
				key:        techKey,
				entityType: domain.EntityTechnology,
				value:      techVal,
				attributes: map[string]any{},
			})

			rels = append(rels, relationshipExtraction{
				sourceKey:  hostKey,
				targetKey:  techKey,
				relType:    domain.RelUsesTechnology,
				attributes: map[string]any{},
			})
		}
	}

	// Hostname as subdomain entity.
	if hostname != "" && strings.Contains(hostname, ".") {
		entities = append(entities, entityExtraction{
			key:        "subdomain:" + hostname,
			entityType: domain.EntitySubdomain,
			value:      hostname,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  "subdomain:" + hostname,
			targetKey:  hostKey,
			relType:    domain.RelResolvesTo,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// extractTechnologyDetect creates entities from technology_detection observations.
func (m *Materializer) extractTechnologyDetect(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	tech, _ := obs.Data["technology"].(string)
	if tech == "" {
		// Try name field.
		tech, _ = obs.Data["name"].(string)
	}
	if tech == "" {
		return nil, nil
	}

	techKey := "tech:" + tech
	techAttrs := map[string]any{}
	if cat, ok := obs.Data["category"].(string); ok {
		techAttrs["category"] = cat
	}
	if ver, ok := obs.Data["version"].(string); ok {
		techAttrs["version"] = ver
	}

	entities = append(entities, entityExtraction{
		key:        techKey,
		entityType: domain.EntityTechnology,
		value:      tech,
		attributes: techAttrs,
	})

	// Link to URL or host if present.
	rawURL, _ := obs.Data["url"].(string)
	host, _ := obs.Data["host"].(string)

	if rawURL != "" {
		urlKey := "url:" + rawURL
		entities = append(entities, entityExtraction{
			key:        urlKey,
			entityType: domain.EntityURL,
			value:      rawURL,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  urlKey,
			targetKey:  techKey,
			relType:    domain.RelUsesTechnology,
			attributes: map[string]any{},
		})
	} else if host != "" {
		hostKey := "host:" + host
		hostType := domain.EntitySubdomain
		if strings.Count(host, ".") <= 1 {
			hostType = domain.EntityDomain
		}
		entities = append(entities, entityExtraction{
			key:        hostKey,
			entityType: hostType,
			value:      host,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  hostKey,
			targetKey:  techKey,
			relType:    domain.RelUsesTechnology,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// extractEndpointDiscovery creates entities from ffuf/dirsearch endpoint_discovery observations.
func (m *Materializer) extractEndpointDiscovery(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	rawURL, _ := obs.Data["url"].(string)
	if rawURL == "" {
		return nil, nil
	}

	// URL entity.
	urlAttrs := map[string]any{}
	if sc, ok := obs.Data["status_code"]; ok {
		urlAttrs["status_code"] = sc
	}
	if ct, ok := obs.Data["content_type"].(string); ok && ct != "" {
		urlAttrs["content_type"] = ct
	}
	if cl, ok := obs.Data["content_length"]; ok {
		urlAttrs["content_length"] = cl
	}

	entities = append(entities, entityExtraction{
		key:        "url:" + rawURL,
		entityType: domain.EntityURL,
		value:      rawURL,
		attributes: urlAttrs,
	})

	// Extract endpoint path.
	if u, err := url.Parse(rawURL); err == nil {
		path := u.Path
		if path != "" && path != "/" {
			endpointKey := "endpoint:" + u.Host + path
			entities = append(entities, entityExtraction{
				key:        endpointKey,
				entityType: domain.EntityEndpoint,
				value:      path,
				attributes: map[string]any{},
			})
		}

		// Host entity.
		host := u.Hostname()
		if host != "" {
			hostType := domain.EntitySubdomain
			if strings.Count(host, ".") <= 1 {
				hostType = domain.EntityDomain
			}
			hostKey := "host:" + host
			entities = append(entities, entityExtraction{
				key:        hostKey,
				entityType: hostType,
				value:      host,
				attributes: map[string]any{},
			})
			rels = append(rels, relationshipExtraction{
				sourceKey:  hostKey,
				targetKey:  "url:" + rawURL,
				relType:    domain.RelServes,
				attributes: map[string]any{},
			})
		}
	}

	return entities, rels
}

// extractCrawlResult creates entities from katana crawl_result observations.
func (m *Materializer) extractCrawlResult(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	rawURL, _ := obs.Data["url"].(string)
	if rawURL == "" {
		return nil, nil
	}

	// URL entity.
	urlAttrs := map[string]any{}
	if sc, ok := obs.Data["status_code"]; ok {
		urlAttrs["status_code"] = sc
	}
	if method, ok := obs.Data["method"].(string); ok {
		urlAttrs["method"] = method
	}
	entities = append(entities, entityExtraction{
		key:        "url:" + rawURL,
		entityType: domain.EntityURL,
		value:      rawURL,
		attributes: urlAttrs,
	})

	// Endpoint from path.
	if u, err := url.Parse(rawURL); err == nil {
		if u.Path != "" && u.Path != "/" {
			endpointKey := "endpoint:" + u.Host + u.Path
			entities = append(entities, entityExtraction{
				key:        endpointKey,
				entityType: domain.EntityEndpoint,
				value:      u.Path,
				attributes: map[string]any{},
			})
		}

		host := u.Hostname()
		if host != "" {
			hostType := domain.EntitySubdomain
			if strings.Count(host, ".") <= 1 {
				hostType = domain.EntityDomain
			}
			entities = append(entities, entityExtraction{
				key:        "host:" + host,
				entityType: hostType,
				value:      host,
				attributes: map[string]any{},
			})
			rels = append(rels, relationshipExtraction{
				sourceKey:  "host:" + host,
				targetKey:  "url:" + rawURL,
				relType:    domain.RelServes,
				attributes: map[string]any{},
			})
		}
	}

	// Technologies from katana.
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
			rels = append(rels, relationshipExtraction{
				sourceKey:  "url:" + rawURL,
				targetKey:  techKey,
				relType:    domain.RelUsesTechnology,
				attributes: map[string]any{},
			})
		}
	}

	return entities, rels
}

// extractDNSLookup creates entities from dnsx dns_lookup observations.
func (m *Materializer) extractDNSLookup(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	host, _ := obs.Data["host"].(string)
	if host == "" {
		return nil, nil
	}

	// Domain/subdomain entity.
	hostType := domain.EntitySubdomain
	if strings.Count(host, ".") <= 1 {
		hostType = domain.EntityDomain
	}
	hostKey := "host:" + host
	entities = append(entities, entityExtraction{
		key:        hostKey,
		entityType: hostType,
		value:      host,
		attributes: map[string]any{},
	})

	// A records → IP entities.
	addIPs := func(records any, recordType string) {
		switch v := records.(type) {
		case []string:
			for _, ip := range v {
				ipKey := "ip:" + ip
				entities = append(entities, entityExtraction{
					key:        ipKey,
					entityType: domain.EntityIPAddress,
					value:      ip,
					attributes: map[string]any{"record_type": recordType},
				})
				rels = append(rels, relationshipExtraction{
					sourceKey:  hostKey,
					targetKey:  ipKey,
					relType:    domain.RelResolvesTo,
					attributes: map[string]any{"record_type": recordType},
				})
			}
		case []any:
			for _, item := range v {
				if ip, ok := item.(string); ok {
					ipKey := "ip:" + ip
					entities = append(entities, entityExtraction{
						key:        ipKey,
						entityType: domain.EntityIPAddress,
						value:      ip,
						attributes: map[string]any{"record_type": recordType},
					})
					rels = append(rels, relationshipExtraction{
						sourceKey:  hostKey,
						targetKey:  ipKey,
						relType:    domain.RelResolvesTo,
						attributes: map[string]any{"record_type": recordType},
					})
				}
			}
		}
	}

	if a, ok := obs.Data["a"]; ok {
		addIPs(a, "A")
	}
	if aaaa, ok := obs.Data["aaaa"]; ok {
		addIPs(aaaa, "AAAA")
	}

	// CNAME records → DNS record + subdomain entities.
	addStringRecords := func(records any, recordType string) {
		switch v := records.(type) {
		case []string:
			for _, val := range v {
				recKey := "dns:" + host + ":" + recordType + ":" + val
				entities = append(entities, entityExtraction{
					key:        recKey,
					entityType: domain.EntityDNSRecord,
					value:      val,
					attributes: map[string]any{"record_type": recordType},
				})
				rels = append(rels, relationshipExtraction{
					sourceKey:  hostKey,
					targetKey:  recKey,
					relType:    domain.RelHasDNSRecord,
					attributes: map[string]any{},
				})
			}
		case []any:
			for _, item := range v {
				if val, ok := item.(string); ok {
					recKey := "dns:" + host + ":" + recordType + ":" + val
					entities = append(entities, entityExtraction{
						key:        recKey,
						entityType: domain.EntityDNSRecord,
						value:      val,
						attributes: map[string]any{"record_type": recordType},
					})
					rels = append(rels, relationshipExtraction{
						sourceKey:  hostKey,
						targetKey:  recKey,
						relType:    domain.RelHasDNSRecord,
						attributes: map[string]any{},
					})
				}
			}
		}
	}

	if cname, ok := obs.Data["cname"]; ok {
		addStringRecords(cname, "CNAME")
	}
	if mx, ok := obs.Data["mx"]; ok {
		addStringRecords(mx, "MX")
	}
	if ns, ok := obs.Data["ns"]; ok {
		addStringRecords(ns, "NS")
	}
	if txt, ok := obs.Data["txt"]; ok {
		addStringRecords(txt, "TXT")
	}

	return entities, rels
}

// extractVulnerabilityScan creates entities from nuclei vulnerability_scan observations.
// NOTE: Nuclei findings are CANDIDATES, not confirmed vulnerabilities.
func (m *Materializer) extractVulnerabilityScan(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	templateID, _ := obs.Data["template_id"].(string)
	host, _ := obs.Data["host"].(string)
	if templateID == "" || host == "" {
		return nil, nil
	}

	// Finding reference entity (CANDIDATE, not confirmed).
	name, _ := obs.Data["name"].(string)
	severity, _ := obs.Data["scanner_severity"].(string)
	findingKey := "finding:" + templateID + ":" + host
	findingAttrs := map[string]any{
		"template_id":      templateID,
		"scanner_severity": severity,
		"status":           "candidate", // Never auto-confirm.
	}
	if name != "" {
		findingAttrs["name"] = name
	}

	entities = append(entities, entityExtraction{
		key:        findingKey,
		entityType: domain.EntityFindingRef,
		value:      templateID,
		attributes: findingAttrs,
	})

	// Host entity.
	hostType := domain.EntitySubdomain
	if strings.Count(host, ".") <= 1 {
		hostType = domain.EntityDomain
	}
	// Check if host looks like an IP.
	if isIPAddress(host) {
		hostType = domain.EntityIPAddress
	}
	hostKey := "host:" + host
	entities = append(entities, entityExtraction{
		key:        hostKey,
		entityType: hostType,
		value:      host,
		attributes: map[string]any{},
	})

	rels = append(rels, relationshipExtraction{
		sourceKey:  hostKey,
		targetKey:  findingKey,
		relType:    domain.RelRelatedTo,
		attributes: map[string]any{},
	})

	// Matched URL as endpoint.
	matchedAt, _ := obs.Data["matched_at"].(string)
	if matchedAt != "" {
		if u, err := url.Parse(matchedAt); err == nil && u.Path != "" && u.Path != "/" {
			endpointKey := "endpoint:" + u.Host + u.Path
			entities = append(entities, entityExtraction{
				key:        endpointKey,
				entityType: domain.EntityEndpoint,
				value:      u.Path,
				attributes: map[string]any{},
			})
			rels = append(rels, relationshipExtraction{
				sourceKey:  endpointKey,
				targetKey:  findingKey,
				relType:    domain.RelRelatedTo,
				attributes: map[string]any{},
			})
		}
	}

	return entities, rels
}

// extractCertificateInfo creates entities from certificate_info observations.
func (m *Materializer) extractCertificateInfo(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	host, _ := obs.Data["host"].(string)
	if host == "" {
		return nil, nil
	}

	hostKey := "host:" + host
	entities = append(entities, entityExtraction{
		key:        hostKey,
		entityType: domain.EntitySubdomain,
		value:      host,
		attributes: map[string]any{},
	})

	// Certificate entity.
	issuer, _ := obs.Data["issuer"].(string)
	subject, _ := obs.Data["subject"].(string)
	certVal := subject
	if certVal == "" {
		certVal = host
	}
	certKey := "cert:" + host
	certAttrs := map[string]any{}
	if issuer != "" {
		certAttrs["issuer"] = issuer
	}
	if subject != "" {
		certAttrs["subject"] = subject
	}
	if notBefore, ok := obs.Data["not_before"].(string); ok {
		certAttrs["not_before"] = notBefore
	}
	if notAfter, ok := obs.Data["not_after"].(string); ok {
		certAttrs["not_after"] = notAfter
	}

	entities = append(entities, entityExtraction{
		key:        certKey,
		entityType: domain.EntityCertificate,
		value:      certVal,
		attributes: certAttrs,
	})

	rels = append(rels, relationshipExtraction{
		sourceKey:  hostKey,
		targetKey:  certKey,
		relType:    domain.RelHasCertificate,
		attributes: map[string]any{},
	})

	// SANs as additional subdomains.
	if sans, ok := obs.Data["san"]; ok {
		switch v := sans.(type) {
		case []string:
			for _, san := range v {
				sanKey := "subdomain:" + san
				entities = append(entities, entityExtraction{
					key:        sanKey,
					entityType: domain.EntitySubdomain,
					value:      san,
					attributes: map[string]any{"source": "certificate_san"},
				})
			}
		case []any:
			for _, item := range v {
				if san, ok := item.(string); ok {
					sanKey := "subdomain:" + san
					entities = append(entities, entityExtraction{
						key:        sanKey,
						entityType: domain.EntitySubdomain,
						value:      san,
						attributes: map[string]any{"source": "certificate_san"},
					})
				}
			}
		}
	}

	return entities, rels
}

// extractJavaScriptAnalysis creates entities from javascript_analysis observations.
func (m *Materializer) extractJavaScriptAnalysis(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	jsURL, _ := obs.Data["url"].(string)
	if jsURL == "" {
		return nil, nil
	}

	jsKey := "js:" + jsURL
	entities = append(entities, entityExtraction{
		key:        jsKey,
		entityType: domain.EntityJavaScriptFile,
		value:      jsURL,
		attributes: map[string]any{},
	})

	// Page that includes this script.
	if pageURL, ok := obs.Data["page_url"].(string); ok && pageURL != "" {
		pageKey := "url:" + pageURL
		entities = append(entities, entityExtraction{
			key:        pageKey,
			entityType: domain.EntityURL,
			value:      pageURL,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  pageKey,
			targetKey:  jsKey,
			relType:    domain.RelIncludesScript,
			attributes: map[string]any{},
		})
	}

	// Discovered endpoints from JS analysis.
	if endpoints, ok := obs.Data["endpoints"]; ok {
		switch v := endpoints.(type) {
		case []string:
			for _, ep := range v {
				epKey := "endpoint:js:" + ep
				entities = append(entities, entityExtraction{
					key:        epKey,
					entityType: domain.EntityEndpoint,
					value:      ep,
					attributes: map[string]any{"source": "javascript_analysis"},
				})
			}
		case []any:
			for _, item := range v {
				if ep, ok := item.(string); ok {
					epKey := "endpoint:js:" + ep
					entities = append(entities, entityExtraction{
						key:        epKey,
						entityType: domain.EntityEndpoint,
						value:      ep,
						attributes: map[string]any{"source": "javascript_analysis"},
					})
				}
			}
		}
	}

	return entities, rels
}

// extractAPIDiscovery creates entities from api_discovery observations.
func (m *Materializer) extractAPIDiscovery(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	endpoint, _ := obs.Data["endpoint"].(string)
	if endpoint == "" {
		endpoint, _ = obs.Data["url"].(string)
	}
	if endpoint == "" {
		return nil, nil
	}

	epKey := "endpoint:" + endpoint
	epAttrs := map[string]any{}
	if method, ok := obs.Data["method"].(string); ok {
		epAttrs["method"] = method
	}
	if ct, ok := obs.Data["content_type"].(string); ok {
		epAttrs["content_type"] = ct
	}

	entities = append(entities, entityExtraction{
		key:        epKey,
		entityType: domain.EntityEndpoint,
		value:      endpoint,
		attributes: epAttrs,
	})

	// Host.
	host, _ := obs.Data["host"].(string)
	if host == "" {
		if u, err := url.Parse(endpoint); err == nil {
			host = u.Hostname()
		}
	}
	if host != "" {
		hostType := domain.EntitySubdomain
		if strings.Count(host, ".") <= 1 {
			hostType = domain.EntityDomain
		}
		hostKey := "host:" + host
		entities = append(entities, entityExtraction{
			key:        hostKey,
			entityType: hostType,
			value:      host,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  hostKey,
			targetKey:  epKey,
			relType:    domain.RelHasEndpoint,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// extractAuthProbe creates entities from authentication_probe observations.
func (m *Materializer) extractAuthProbe(obs domain.Observation) ([]entityExtraction, []relationshipExtraction) {
	var entities []entityExtraction
	var rels []relationshipExtraction

	mechanism, _ := obs.Data["mechanism"].(string)
	if mechanism == "" {
		mechanism, _ = obs.Data["type"].(string)
	}
	if mechanism == "" {
		return nil, nil
	}

	authKey := "auth:" + mechanism
	authAttrs := map[string]any{}
	if details, ok := obs.Data["details"].(string); ok {
		authAttrs["details"] = details
	}

	entities = append(entities, entityExtraction{
		key:        authKey,
		entityType: domain.EntityAuthMechanism,
		value:      mechanism,
		attributes: authAttrs,
	})

	// Link to endpoint/URL.
	rawURL, _ := obs.Data["url"].(string)
	if rawURL != "" {
		urlKey := "url:" + rawURL
		entities = append(entities, entityExtraction{
			key:        urlKey,
			entityType: domain.EntityURL,
			value:      rawURL,
			attributes: map[string]any{},
		})
		rels = append(rels, relationshipExtraction{
			sourceKey:  urlKey,
			targetKey:  authKey,
			relType:    domain.RelUsesAuth,
			attributes: map[string]any{},
		})
	}

	return entities, rels
}

// --- Helpers ---

// toInt extracts an integer from interface{} (handles float64 from JSON).
func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	default:
		return 0
	}
}

// isIPAddress returns true if s looks like an IP address.
func isIPAddress(s string) bool {
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return strings.Contains(s, ".")
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
