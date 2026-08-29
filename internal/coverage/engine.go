package coverage

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Engine computes evidence-derived coverage from the observation store.
type Engine struct {
	db *sql.DB
}

// NewEngine creates a coverage engine backed by the workspace database.
func NewEngine(db *sql.DB) *Engine {
	return &Engine{db: db}
}

// Analyze computes the full coverage report for a project.
func (e *Engine) Analyze(projectID uuid.UUID) (*Report, error) {
	report := &Report{
		GeneratedAt: time.Now(),
	}

	// Count total observations and entities.
	report.TotalObservations = e.countObservations(projectID)
	report.TotalEntities = e.countEntities(projectID)

	// Compute each coverage category.
	for _, cat := range AllCategories() {
		cc := e.analyzeCategory(projectID, cat)
		report.Categories = append(report.Categories, cc)
	}

	// Compute weighted total score.
	report.TotalScore = e.weightedScore(report.Categories)

	return report, nil
}

// analyzeCategory computes coverage for a single dimension.
func (e *Engine) analyzeCategory(projectID uuid.UUID, cat Category) CategoryCoverage {
	cc := CategoryCoverage{
		Category:    cat,
		LastUpdated: time.Now(),
	}

	switch cat {
	case CategoryDiscovery:
		cc = e.analyzeDiscovery(projectID)
	case CategoryWebMapping:
		cc = e.analyzeWebMapping(projectID)
	case CategoryAuthentication:
		cc = e.analyzeAuthentication(projectID)
	case CategoryAuthorization:
		cc = e.analyzeAuthorization(projectID)
	case CategoryAPISurface:
		cc = e.analyzeAPISurface(projectID)
	case CategoryBusinessLogic:
		cc = e.analyzeBusinessLogic(projectID)
	case CategoryFileHandling:
		cc = e.analyzeFileHandling(projectID)
	case CategoryTechnology:
		cc = e.analyzeTechnology(projectID)
	}

	cc.Category = cat
	return cc
}

// analyzeDiscovery: hosts, ports, services discovered.
func (e *Engine) analyzeDiscovery(projectID uuid.UUID) CategoryCoverage {
	portScans := e.countByType(projectID, domain.ObservationPortScan)
	dnsLookups := e.countByType(projectID, domain.ObservationDNSLookup)
	subdomains := e.countByType(projectID, domain.ObservationSubdomainDiscovery)
	total := portScans + dnsLookups + subdomains

	// Discovery is binary: have we done any recon at all?
	var score float64
	if portScans > 0 {
		score += 0.4
	}
	if dnsLookups > 0 || subdomains > 0 {
		score += 0.3
	}
	if total > 10 {
		score += 0.3
	} else if total > 0 {
		score += 0.15
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
	}
}

// analyzeWebMapping: endpoints, URLs discovered.
func (e *Engine) analyzeWebMapping(projectID uuid.UUID) CategoryCoverage {
	httpProbes := e.countByType(projectID, domain.ObservationHTTPProbe)
	endpoints := e.countByType(projectID, domain.ObservationEndpointDiscovery)
	crawls := e.countByType(projectID, domain.ObservationCrawlResult)
	total := httpProbes + endpoints + crawls

	totalEndpoints := e.countEntitiesByType(projectID, domain.EntityEndpoint) +
		e.countEntitiesByType(projectID, domain.EntityURL)

	var score float64
	if httpProbes > 0 {
		score += 0.3
	}
	if endpoints > 0 || crawls > 0 {
		score += 0.3
	}
	if totalEndpoints > 50 {
		score += 0.4
	} else if totalEndpoints > 20 {
		score += 0.3
	} else if totalEndpoints > 5 {
		score += 0.2
	} else if totalEndpoints > 0 {
		score += 0.1
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:        score,
		Evidence:     total,
		Total:        totalEndpoints,
		Investigated: totalEndpoints, // all discovered endpoints are "investigated" by discovery tools
	}
}

// analyzeAuthentication: auth mechanisms observed.
func (e *Engine) analyzeAuthentication(projectID uuid.UUID) CategoryCoverage {
	authProbes := e.countByType(projectID, domain.ObservationAuthProbe)
	authEntities := e.countEntitiesByType(projectID, domain.EntityAuthMechanism)
	notes := e.countNotesByCategory(projectID, "auth")

	total := authProbes + notes
	var score float64
	if authEntities > 0 {
		score += 0.4
	}
	if authProbes > 0 {
		score += 0.3
	}
	if notes > 0 {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
	}
}

// analyzeAuthorization: access-control boundaries observed.
func (e *Engine) analyzeAuthorization(projectID uuid.UUID) CategoryCoverage {
	// Authorization is evidence-derived from notes and auth probes with role context.
	notes := e.countNotesByCategory(projectID, "authorization")
	authNotes := e.countNotesByCategory(projectID, "auth")

	total := notes + authNotes
	var score float64
	if notes > 5 {
		score = 0.6
	} else if notes > 2 {
		score = 0.4
	} else if notes > 0 || authNotes > 0 {
		score = 0.2
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
	}
}

// analyzeAPISurface: API endpoints, parameters discovered.
func (e *Engine) analyzeAPISurface(projectID uuid.UUID) CategoryCoverage {
	apiDiscovery := e.countByType(projectID, domain.ObservationAPIDiscovery)
	endpoints := e.countEntitiesByType(projectID, domain.EntityEndpoint)
	params := e.countEntitiesByType(projectID, domain.EntityParameter)
	graphql := e.countEntitiesByType(projectID, domain.EntityGraphQLOp)

	evidence := apiDiscovery + graphql
	var score float64
	if endpoints > 0 {
		score += 0.3
	}
	if params > 10 {
		score += 0.4
	} else if params > 0 {
		score += 0.2
	}
	if graphql > 0 {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: evidence,
		Total:    endpoints + params,
	}
}

// analyzeBusinessLogic: workflow relationships.
func (e *Engine) analyzeBusinessLogic(projectID uuid.UUID) CategoryCoverage {
	notes := e.countNotesByCategory(projectID, "business")
	workflowNotes := e.countNotesByCategory(projectID, "workflow")
	total := notes + workflowNotes

	var score float64
	if total > 5 {
		score = 0.6
	} else if total > 2 {
		score = 0.4
	} else if total > 0 {
		score = 0.2
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
	}
}

// analyzeFileHandling: upload/download endpoints.
func (e *Engine) analyzeFileHandling(projectID uuid.UUID) CategoryCoverage {
	notes := e.countNotesByCategory(projectID, "upload")
	fileNotes := e.countNotesByCategory(projectID, "file")

	// Check for upload-related endpoints in the entity store.
	uploadEndpoints := e.countUploadEndpoints(projectID)

	total := notes + fileNotes + uploadEndpoints
	var score float64
	if uploadEndpoints > 0 {
		score += 0.3
	}
	if notes > 0 || fileNotes > 0 {
		score += 0.4
	}
	if total > 5 {
		score += 0.3
	}
	if score > 1.0 {
		score = 1.0
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
	}
}

// analyzeTechnology: stack identification.
func (e *Engine) analyzeTechnology(projectID uuid.UUID) CategoryCoverage {
	techDetect := e.countByType(projectID, domain.ObservationTechnologyDetect)
	techEntities := e.countEntitiesByType(projectID, domain.EntityTechnology)

	total := techDetect
	var score float64
	if techEntities > 5 {
		score = 1.0
	} else if techEntities > 2 {
		score = 0.8
	} else if techEntities > 0 {
		score = 0.5
	}
	if techDetect > 0 && score < 0.5 {
		score = 0.5
	}

	return CategoryCoverage{
		Score:    score,
		Evidence: total,
		Total:    techEntities,
	}
}

// weightedScore computes a weighted average across categories.
func (e *Engine) weightedScore(cats []CategoryCoverage) float64 {
	// Weights reflect investigation importance for bug bounty.
	weights := map[Category]float64{
		CategoryDiscovery:      0.15,
		CategoryWebMapping:     0.15,
		CategoryAuthentication: 0.15,
		CategoryAuthorization:  0.20,
		CategoryAPISurface:     0.10,
		CategoryBusinessLogic:  0.10,
		CategoryFileHandling:   0.05,
		CategoryTechnology:     0.10,
	}

	var totalWeight float64
	var weightedSum float64
	for _, cc := range cats {
		w := weights[cc.Category]
		if w == 0 {
			w = 0.1
		}
		weightedSum += cc.Score * w
		totalWeight += w
	}

	if totalWeight == 0 {
		return 0
	}
	return weightedSum / totalWeight
}

// --- Database queries ---

func (e *Engine) countObservations(projectID uuid.UUID) int {
	var count int
	e.db.QueryRow(`
		SELECT COUNT(*) FROM observations WHERE project_id = ?
	`, projectID.String()).Scan(&count)
	return count
}

func (e *Engine) countEntities(projectID uuid.UUID) int {
	var count int
	e.db.QueryRow(`
		SELECT COUNT(*) FROM entities WHERE project_id = ?
	`, projectID.String()).Scan(&count)
	return count
}

func (e *Engine) countByType(projectID uuid.UUID, obsType domain.ObservationType) int {
	var count int
	e.db.QueryRow(`
		SELECT COUNT(*) FROM observations WHERE project_id = ? AND type = ?
	`, projectID.String(), string(obsType)).Scan(&count)
	return count
}

func (e *Engine) countEntitiesByType(projectID uuid.UUID, entType domain.EntityType) int {
	var count int
	e.db.QueryRow(`
		SELECT COUNT(*) FROM entities WHERE project_id = ? AND type = ?
	`, projectID.String(), string(entType)).Scan(&count)
	return count
}

func (e *Engine) countNotesByCategory(projectID uuid.UUID, category string) int {
	var count int
	// Notes are stored as observations of type researcher_note with category in data JSON.
	e.db.QueryRow(`
		SELECT COUNT(*) FROM observations
		WHERE project_id = ? AND type = 'researcher_note'
		AND data LIKE ?
	`, projectID.String(), "%"+category+"%").Scan(&count)
	return count
}

func (e *Engine) countUploadEndpoints(projectID uuid.UUID) int {
	var count int
	e.db.QueryRow(`
		SELECT COUNT(*) FROM entities
		WHERE project_id = ? AND type = 'endpoint'
		AND (value LIKE '%upload%' OR value LIKE '%file%' OR value LIKE '%attach%')
	`, projectID.String()).Scan(&count)
	return count
}
