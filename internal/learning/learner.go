package learning

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Learner extracts research patterns from observations and evidence.
//
// The learner does NOT create facts or modify observations.
// It only identifies recurring patterns and records learning events.
type Learner struct {
	memory *Memory
}

// NewLearner creates a learner backed by the learning memory.
func NewLearner(memory *Memory) *Learner {
	return &Learner{memory: memory}
}

// LearnFromObservations analyzes a batch of observations and extracts patterns.
func (l *Learner) LearnFromObservations(observations []domain.Observation) error {
	for _, obs := range observations {
		if err := l.processObservation(obs); err != nil {
			continue // Don't let one bad observation kill learning.
		}
	}
	return nil
}

// processObservation extracts patterns from a single observation.
func (l *Learner) processObservation(obs domain.Observation) error {
	// Extract patterns based on observation type.
	switch obs.Type {
	case domain.ObservationEndpointDiscovery:
		return l.learnEndpointPattern(obs)
	case domain.ObservationHTTPProbe:
		return l.learnResponsePattern(obs)
	case domain.ObservationAuthProbe:
		return l.learnAuthPattern(obs)
	case domain.ObservationTechnologyDetect:
		return l.learnTechPattern(obs)
	case domain.ObservationPortScan:
		return l.learnServicePattern(obs)
	}
	return nil
}

// learnEndpointPattern identifies recurring endpoint structures.
func (l *Learner) learnEndpointPattern(obs domain.Observation) error {
	endpoint, _ := obs.Data["url"].(string)
	if endpoint == "" {
		endpoint, _ = obs.Data["path"].(string)
	}
	if endpoint == "" {
		return nil
	}

	// Detect object-ID patterns: /api/something?id=, /api/something/123
	patternName := ""
	description := ""

	if containsObjectID(endpoint) {
		patternName = "endpoint_with_object_id"
		description = "Resource endpoint with object identifier — historically requires authorization testing"
	} else if strings.Contains(endpoint, "/api/") {
		patternName = "api_endpoint"
		description = "API endpoint — may expose structured data"
	} else if strings.Contains(endpoint, "/admin") || strings.Contains(endpoint, "/manage") {
		patternName = "admin_endpoint"
		description = "Administrative endpoint — user/admin boundary should be tested"
	} else if strings.Contains(endpoint, "/upload") || strings.Contains(endpoint, "/file") {
		patternName = "file_endpoint"
		description = "File handling endpoint — upload/download restrictions should be tested"
	}

	if patternName == "" {
		return nil
	}

	return l.observePattern(patternName, description, PatternEndpoint, obs.ID)
}

// learnResponsePattern learns from HTTP response behaviors.
func (l *Learner) learnResponsePattern(obs domain.Observation) error {
	statusCode, _ := obs.Data["status_code"].(float64)
	if statusCode == 0 {
		return nil
	}

	if statusCode == 403 || statusCode == 401 {
		return l.observePattern(
			"auth_boundary_response",
			"Endpoint returns authorization error — access control boundary detected",
			PatternAuthz,
			obs.ID,
		)
	}

	return nil
}

// learnAuthPattern learns from authentication probes.
func (l *Learner) learnAuthPattern(obs domain.Observation) error {
	return l.observePattern(
		"auth_mechanism_observed",
		"Authentication mechanism detected — multi-context testing valuable",
		PatternAuth,
		obs.ID,
	)
}

// learnTechPattern learns from technology detections.
func (l *Learner) learnTechPattern(obs domain.Observation) error {
	tech, _ := obs.Data["technology"].(string)
	if tech == "" {
		return nil
	}

	// Common technologies that don't need repeated attention.
	noise := map[string]bool{
		"nginx": true, "apache": true, "ubuntu": true,
		"debian": true, "openssh": true,
	}
	if noise[strings.ToLower(tech)] {
		return l.observePattern(
			"common_technology_"+strings.ToLower(tech),
			"Common technology fingerprint — usually low investigation value",
			PatternNoise,
			obs.ID,
		)
	}

	return nil
}

// learnServicePattern learns from port scan results.
func (l *Learner) learnServicePattern(obs domain.Observation) error {
	service, _ := obs.Data["service"].(string)
	if service == "" {
		return nil
	}

	// Standard SSH/HTTP are noise after first observation.
	if strings.ToLower(service) == "ssh" || strings.ToLower(service) == "http" {
		return nil // Too common to be a useful pattern.
	}

	return l.observePattern(
		"service_"+strings.ToLower(service),
		"Service "+service+" detected — investigate for non-standard behavior",
		PatternEndpoint,
		obs.ID,
	)
}

// observePattern records a pattern observation, creating or updating the pattern.
func (l *Learner) observePattern(name, description string, category PatternCategory, evidenceID uuid.UUID) error {
	now := time.Now()

	existing, err := l.memory.GetPattern(name)
	if err != nil {
		// New pattern.
		pattern := &ResearchPattern{
			ID:            uuid.New(),
			Name:          name,
			Description:   description,
			Category:      category,
			Confidence:    0.3, // Start cautious.
			Occurrences:   1,
			EvidenceIDs:   []uuid.UUID{evidenceID},
			PriorityBoost: 0.1,
			FirstSeen:     now,
			LastSeen:      now,
			DecayFactor:   1.0,
		}
		if err := l.memory.StorePattern(pattern); err != nil {
			return err
		}

		return l.memory.RecordEvent(&LearningEvent{
			ID:              uuid.New(),
			Type:            EventNewPattern,
			PatternName:     name,
			Context:         description,
			EvidenceIDs:     []uuid.UUID{evidenceID},
			ConfidenceDelta: 0.3,
			RecordedAt:      now,
		})
	}

	// Existing pattern: increase confidence and occurrences.
	existing.Occurrences++
	existing.LastSeen = now
	existing.EvidenceIDs = append(existing.EvidenceIDs, evidenceID)

	// Confidence increases logarithmically with occurrences.
	confidenceGain := 0.05
	if existing.Occurrences > 10 {
		confidenceGain = 0.02
	}
	if existing.Occurrences > 50 {
		confidenceGain = 0.01
	}
	existing.Confidence += confidenceGain
	if existing.Confidence > 0.95 {
		existing.Confidence = 0.95 // Never reach 1.0 — always room for doubt.
	}

	// Priority boost increases with confidence.
	existing.PriorityBoost = existing.Confidence * 0.15

	if err := l.memory.StorePattern(existing); err != nil {
		return err
	}

	return l.memory.RecordEvent(&LearningEvent{
		ID:              uuid.New(),
		Type:            EventPatternObserved,
		PatternName:     name,
		Context:         description,
		EvidenceIDs:     []uuid.UUID{evidenceID},
		ConfidenceDelta: confidenceGain,
		RecordedAt:      now,
	})
}

// containsObjectID checks if a URL/path contains numeric object identifiers.
func containsObjectID(s string) bool {
	// Check for query parameter patterns: ?id=, ?user_id=, etc.
	idParams := []string{"?id=", "&id=", "?user_id=", "&user_id=",
		"?file_id=", "&file_id=", "?report_id=", "&report_id=",
		"?order_id=", "&order_id=", "?doc_id=", "&doc_id="}
	lower := strings.ToLower(s)
	for _, p := range idParams {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Check for path-based IDs: /resource/123
	parts := strings.Split(s, "/")
	for _, part := range parts {
		if len(part) > 0 && isNumeric(part) {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
