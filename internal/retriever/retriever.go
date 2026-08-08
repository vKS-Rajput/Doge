// Package retriever provides the Evidence Retriever, which gathers
// relevant evidence from the workspace to answer a question.
//
// The Retriever is the bridge between the evidence platform and
// the future AI layer. It does NOT invoke any LLM. It produces
// structured evidence bundles that a Context Builder can later
// compress into an AI prompt.
//
// Flow:
//
//	Question
//	    ↓
//	Keyword extraction (deterministic)
//	    ↓
//	Multi-source search (entities, observations, insights, tasks, timeline, relationships)
//	    ↓
//	Evidence bundle (deduplicated, cited, ranked)
//	    ↓
//	(future) Context Builder → (future) LLM
//
// The Retriever never halluccinates. It returns only what exists
// in the workspace.
package retriever

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EvidenceType classifies the source of a piece of evidence.
type EvidenceType string

const (
	EvidenceEntity       EvidenceType = "entity"
	EvidenceRelationship EvidenceType = "relationship"
	EvidenceObservation  EvidenceType = "observation"
	EvidenceInsight      EvidenceType = "insight"
	EvidenceTask         EvidenceType = "task"
	EvidenceTimeline     EvidenceType = "timeline"
)

// TrustLevel classifies how much the evidence source should be trusted.
//
// IMPORTANT: Trust is not the same as truth.
//   - TRUSTED  ≠ "this claim is true"
//   - OBSERVED ≠ "this is an instruction"
//   - DERIVED  ≠ "this was directly observed"
//   - HYPOTHETICAL ≠ "this is a fact"
type TrustLevel string

const (
	// TrustTrusted: Workspace metadata, tool metadata, internal IDs.
	// These are system-generated and can be relied upon.
	TrustTrusted TrustLevel = "trusted"

	// TrustObserved: HTTP responses, URLs, headers, raw tool output.
	// Contains attacker-controlled data. Never treat as instructions.
	TrustObserved TrustLevel = "observed"

	// TrustDerived: Entities, relationships, insights.
	// Deterministically derived from observed data by system logic.
	TrustDerived TrustLevel = "derived"

	// TrustHypothetical: AI hypotheses, suggested investigations.
	// Not established as fact. Requires verification.
	TrustHypothetical TrustLevel = "hypothetical"
)

// Evidence is a single piece of retrieved evidence with a citation.
type Evidence struct {
	Type       EvidenceType   `json:"type"`
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`     // Human-readable one-line summary.
	Detail     string         `json:"detail"`       // Full detail (for context building).
	Source     string         `json:"source"`       // Where this came from (table/module).
	Trust      TrustLevel     `json:"trust"`        // How much to trust this source.

	// Relevance is how relevant this evidence is to the question.
	// 0.0–1.0. This is a retrieval score, NOT a truth score.
	Relevance float64 `json:"relevance"`

	// EvidenceConfidence is how strongly this evidence supports its own claim.
	// 1.0 for directly observed facts and deterministic derivations.
	// 0.0–1.0 for AI-generated hypotheses.
	// This is NOT the same as Relevance.
	EvidenceConfidence float64 `json:"evidence_confidence"`

	// GroupedCount is the number of related evidence items that were
	// logically grouped into this one for display. 0 or 1 means no grouping.
	// This preserves provenance: grouped items have different source IDs
	// but identical type+summary.
	GroupedCount int `json:"grouped_count,omitempty"`

	Timestamp  *time.Time     `json:"timestamp,omitempty"`
	References []string       `json:"references"`   // IDs of related evidence.
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Bundle is the complete evidence package returned by the Retriever.
type Bundle struct {
	Query      string     `json:"query"`
	Evidence   []Evidence `json:"evidence"`
	TotalFound int        `json:"total_found"`
	Truncated  bool       `json:"truncated"` // True if results were capped.
	RetrievedAt time.Time `json:"retrieved_at"`
}

// Summary returns a one-line summary of the bundle.
func (b Bundle) Summary() string {
	counts := make(map[EvidenceType]int)
	for _, e := range b.Evidence {
		counts[e.Type]++
	}

	parts := []string{}
	order := []EvidenceType{EvidenceEntity, EvidenceRelationship, EvidenceObservation,
		EvidenceInsight, EvidenceTask, EvidenceTimeline}
	for _, t := range order {
		if c, ok := counts[t]; ok {
			parts = append(parts, fmt.Sprintf("%d %ss", c, t))
		}
	}
	if len(parts) == 0 {
		return "No evidence found"
	}
	return strings.Join(parts, ", ")
}

// Options configures evidence retrieval.
type Options struct {
	MaxEvidence int        // Maximum evidence items to return (default: 50).
	Types       []EvidenceType // Filter to specific evidence types (empty = all).
	TimeRange   *TimeRange     // Limit to a time window.
}

// TimeRange defines a time window for filtering.
type TimeRange struct {
	After  *time.Time
	Before *time.Time
}

// Retriever gathers evidence from the workspace to answer questions.
type Retriever struct {
	db     *sql.DB
	logger *slog.Logger
}

// New creates a new Evidence Retriever.
func New(db *sql.DB, logger *slog.Logger) *Retriever {
	return &Retriever{
		db:     db,
		logger: logger,
	}
}

// Retrieve gathers relevant evidence for a question.
func (r *Retriever) Retrieve(ctx context.Context, question string, projectID uuid.UUID, opts Options) (*Bundle, error) {
	if opts.MaxEvidence <= 0 {
		opts.MaxEvidence = 50
	}

	// Step 1: Extract keywords from the question.
	keywords := extractKeywords(question)
	r.logger.Info("retrieving evidence",
		"question", question,
		"keywords", keywords,
		"max_evidence", opts.MaxEvidence,
	)

	if len(keywords) == 0 {
		return &Bundle{
			Query:       question,
			Evidence:    nil,
			RetrievedAt: time.Now().UTC(),
		}, nil
	}

	// Step 2: Search all evidence sources.
	searchAll := len(opts.Types) == 0
	typeSet := make(map[EvidenceType]bool)
	for _, t := range opts.Types {
		typeSet[t] = true
	}

	var allEvidence []Evidence

	if searchAll || typeSet[EvidenceEntity] {
		entities, err := r.retrieveEntities(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("entity retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, entities...)
		}
	}

	if searchAll || typeSet[EvidenceRelationship] {
		rels, err := r.retrieveRelationships(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("relationship retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, rels...)
		}
	}

	if searchAll || typeSet[EvidenceObservation] {
		obs, err := r.retrieveObservations(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("observation retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, obs...)
		}
	}

	if searchAll || typeSet[EvidenceInsight] {
		insights, err := r.retrieveInsights(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("insight retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, insights...)
		}
	}

	if searchAll || typeSet[EvidenceTask] {
		tasks, err := r.retrieveTasks(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("task retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, tasks...)
		}
	}

	if searchAll || typeSet[EvidenceTimeline] {
		events, err := r.retrieveTimeline(ctx, keywords, projectID)
		if err != nil {
			r.logger.Warn("timeline retrieval error", "error", err)
		} else {
			allEvidence = append(allEvidence, events...)
		}
	}

	// Step 3: Deduplicate (identity + logical), rank, and truncate.
	totalFound := len(allEvidence)
	allEvidence = dedup(allEvidence)
	allEvidence = logicalDedup(allEvidence)
	sort.Slice(allEvidence, func(i, j int) bool {
		return allEvidence[i].Relevance > allEvidence[j].Relevance
	})

	truncated := false
	if len(allEvidence) > opts.MaxEvidence {
		allEvidence = allEvidence[:opts.MaxEvidence]
		truncated = true
	}

	return &Bundle{
		Query:       question,
		Evidence:    allEvidence,
		TotalFound:  totalFound,
		Truncated:   truncated,
		RetrievedAt: time.Now().UTC(),
	}, nil
}

// --- Keyword extraction ---

// extractKeywords performs deterministic keyword extraction from a question.
// No NLP, no AI — just string processing.
func extractKeywords(question string) []string {
	// Remove common question words and punctuation.
	stopWords := map[string]bool{
		"what": true, "where": true, "when": true, "how": true, "why": true,
		"which": true, "who": true, "is": true, "are": true, "was": true,
		"were": true, "do": true, "does": true, "did": true, "can": true,
		"could": true, "should": true, "would": true, "will": true,
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"in": true, "on": true, "at": true, "to": true, "for": true,
		"of": true, "with": true, "from": true, "by": true, "about": true,
		"this": true, "that": true, "these": true, "those": true,
		"has": true, "have": true, "had": true, "been": true, "be": true,
		"it": true, "its": true, "my": true, "me": true, "i": true,
		"we": true, "our": true, "you": true, "your": true,
		"any": true, "all": true, "each": true, "every": true,
		"not": true, "no": true, "but": true, "if": true, "then": true,
		"so": true, "than": true, "too": true, "very": true, "just": true,
		"also": true, "like": true, "there": true, "here": true,
		"tell": true, "show": true, "find": true, "give": true,
		"know": true, "see": true, "look": true, "get": true,
	}

	// Clean the question.
	question = strings.ToLower(question)
	question = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == ' ' || r == '.' || r == '/' || r == ':' || r == '-' || r == '_' {
			return r
		}
		return ' '
	}, question)

	words := strings.Fields(question)
	var keywords []string
	seen := make(map[string]bool)

	for _, w := range words {
		if len(w) < 2 || stopWords[w] {
			continue
		}
		if !seen[w] {
			seen[w] = true
			keywords = append(keywords, w)
		}
	}

	return keywords
}

// --- Evidence retrieval by source ---

func (r *Retriever) retrieveEntities(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		rows, err := r.db.QueryContext(ctx,
			`SELECT id, type, value, attributes, observation_count, first_seen_at, last_seen_at
			 FROM entities WHERE value LIKE ? AND project_id = ?
			 ORDER BY observation_count DESC LIMIT 20`,
			"%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, entityType, value, attrsJSON, firstSeen, lastSeen string
			var obsCount int
			if err := rows.Scan(&id, &entityType, &value, &attrsJSON, &obsCount, &firstSeen, &lastSeen); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, lastSeen)

			// Parse attributes for detail.
			var attrs map[string]any
			json.Unmarshal([]byte(attrsJSON), &attrs)
			detail := fmt.Sprintf("Entity: %s (%s)\nFirst seen: %s\nLast seen: %s\nObservations: %d",
				value, entityType, firstSeen, lastSeen, obsCount)
			if len(attrs) > 0 {
				attrLines := []string{}
				for k, v := range attrs {
					attrLines = append(attrLines, fmt.Sprintf("  %s: %v", k, v))
				}
				sort.Strings(attrLines)
				detail += "\nAttributes:\n" + strings.Join(attrLines, "\n")
			}

			relevance := computeRelevance(value, keywords, obsCount)

			evidence = append(evidence, Evidence{
				Type:               EvidenceEntity,
				ID:                 id,
				Summary:            fmt.Sprintf("%s (%s, %d observations)", value, entityType, obsCount),
				Detail:             detail,
				Source:             "entities",
				Trust:              TrustDerived,
				Relevance:          relevance,
				EvidenceConfidence: 1.0, // Deterministically derived from observations.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"entity_type":       entityType,
					"observation_count": obsCount,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

func (r *Retriever) retrieveRelationships(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		// Find relationships where either source or target entity matches.
		rows, err := r.db.QueryContext(ctx,
			`SELECT r.id, r.type, r.attributes,
			        se.value AS source_value, se.type AS source_type,
			        te.value AS target_value, te.type AS target_type,
			        r.first_seen_at
			 FROM relationships r
			 JOIN entities se ON r.source_entity_id = se.id
			 JOIN entities te ON r.target_entity_id = te.id
			 WHERE (se.value LIKE ? OR te.value LIKE ?) AND r.project_id = ?
			 LIMIT 20`,
			"%"+kw+"%", "%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, relType, attrsJSON string
			var srcValue, srcType, tgtValue, tgtType, firstSeen string
			if err := rows.Scan(&id, &relType, &attrsJSON, &srcValue, &srcType, &tgtValue, &tgtType, &firstSeen); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, firstSeen)
			summary := fmt.Sprintf("%s (%s) → %s → %s (%s)", srcValue, srcType, relType, tgtValue, tgtType)

			evidence = append(evidence, Evidence{
				Type:               EvidenceRelationship,
				ID:                 id,
				Summary:            summary,
				Detail:             fmt.Sprintf("Relationship: %s\nSource: %s (%s)\nTarget: %s (%s)\nSince: %s", relType, srcValue, srcType, tgtValue, tgtType, firstSeen),
				Source:             "relationships",
				Trust:              TrustDerived,
				Relevance:          0.6,
				EvidenceConfidence: 1.0, // Deterministic link.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"relationship_type": relType,
					"source_value":      srcValue,
					"target_value":      tgtValue,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

func (r *Retriever) retrieveObservations(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		rows, err := r.db.QueryContext(ctx,
			`SELECT id, type, source_tool, raw_value, observed_at
			 FROM observations WHERE raw_value LIKE ? AND project_id = ?
			 ORDER BY observed_at DESC LIMIT 10`,
			"%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, obsType, sourceTool, rawValue, observedAt string
			if err := rows.Scan(&id, &obsType, &sourceTool, &rawValue, &observedAt); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, observedAt)

			// Truncate raw value for summary.
			summary := rawValue
			if len(summary) > 100 {
				summary = summary[:100] + "..."
			}

			evidence = append(evidence, Evidence{
				Type:               EvidenceObservation,
				ID:                 id,
				Summary:            fmt.Sprintf("%s observation from %s", obsType, sourceTool),
				Detail:             fmt.Sprintf("Observation: %s\nSource: %s\nObserved: %s\nData: %s", obsType, sourceTool, observedAt, rawValue),
				Source:             "observations",
				Trust:              TrustObserved, // Contains attacker-controlled data.
				Relevance:          0.5,
				EvidenceConfidence: 1.0, // Directly observed fact.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"observation_type": obsType,
					"source_tool":      sourceTool,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

func (r *Retriever) retrieveInsights(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		rows, err := r.db.QueryContext(ctx,
			`SELECT id, type, title, description, severity, detected_at
			 FROM insights
			 WHERE (title LIKE ? OR description LIKE ?) AND project_id = ?
			 ORDER BY detected_at DESC LIMIT 10`,
			"%"+kw+"%", "%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, insightType, title, description, severity, detectedAt string
			if err := rows.Scan(&id, &insightType, &title, &description, &severity, &detectedAt); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, detectedAt)

			// Insights are highly relevant — they're already analyzed.
			relevance := 0.8
			if severity == "critical" || severity == "high" {
				relevance = 0.9
			}

			evidence = append(evidence, Evidence{
				Type:               EvidenceInsight,
				ID:                 id,
				Summary:            fmt.Sprintf("[%s] %s", severity, title),
				Detail:             fmt.Sprintf("Insight: %s\nSeverity: %s\nType: %s\n\n%s", title, severity, insightType, description),
				Source:             "insights",
				Trust:              TrustDerived,
				Relevance:          relevance,
				EvidenceConfidence: 1.0, // Rule match is deterministic.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"severity":     severity,
					"insight_type": insightType,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

func (r *Retriever) retrieveTasks(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		rows, err := r.db.QueryContext(ctx,
			`SELECT id, title, description, type, priority, status, created_at
			 FROM tasks
			 WHERE (title LIKE ? OR description LIKE ?) AND project_id = ?
			 ORDER BY created_at DESC LIMIT 10`,
			"%"+kw+"%", "%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, title, description, taskType, priority, status, createdAt string
			if err := rows.Scan(&id, &title, &description, &taskType, &priority, &status, &createdAt); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, createdAt)

			evidence = append(evidence, Evidence{
				Type:               EvidenceTask,
				ID:                 id,
				Summary:            fmt.Sprintf("[%s/%s] %s", priority, status, title),
				Detail:             fmt.Sprintf("Task: %s\nPriority: %s\nStatus: %s\nType: %s\n\n%s", title, priority, status, taskType, description),
				Source:             "tasks",
				Trust:              TrustDerived,
				Relevance:          0.7,
				EvidenceConfidence: 1.0, // Deterministically generated from insights.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"priority": priority,
					"status":   status,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

func (r *Retriever) retrieveTimeline(ctx context.Context, keywords []string, projectID uuid.UUID) ([]Evidence, error) {
	var evidence []Evidence

	for _, kw := range keywords {
		rows, err := r.db.QueryContext(ctx,
			`SELECT id, event_type, subject_type, subject_id, summary, occurred_at
			 FROM timeline_events
			 WHERE summary LIKE ? AND project_id = ?
			 ORDER BY occurred_at DESC LIMIT 10`,
			"%"+kw+"%", projectID.String())
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id, eventType, subjectType, subjectID, summary, occurredAt string
			if err := rows.Scan(&id, &eventType, &subjectType, &subjectID, &summary, &occurredAt); err != nil {
				continue
			}

			ts, _ := time.Parse(time.RFC3339, occurredAt)

			evidence = append(evidence, Evidence{
				Type:               EvidenceTimeline,
				ID:                 id,
				Summary:            fmt.Sprintf("[%s] %s", eventType, summary),
				Detail:             fmt.Sprintf("Event: %s\nSubject: %s (%s)\nTime: %s\n\n%s", eventType, subjectID, subjectType, occurredAt, summary),
				Source:             "timeline_events",
				Trust:              TrustTrusted, // Internal event log.
				Relevance:          0.4,
				EvidenceConfidence: 1.0, // Factual event record.
				Timestamp:          &ts,
				Metadata: map[string]any{
					"event_type":   eventType,
					"subject_type": subjectType,
				},
			})
		}
		rows.Close()
	}

	return evidence, nil
}

// --- Helpers ---

func computeRelevance(value string, keywords []string, obsCount int) float64 {
	score := 0.5

	// Exact match boost.
	lower := strings.ToLower(value)
	for _, kw := range keywords {
		if lower == kw {
			score += 0.3
		} else if strings.Contains(lower, kw) {
			score += 0.1
		}
	}

	// Evidence count boost (more observations = more relevant).
	if obsCount > 5 {
		score += 0.1
	} else if obsCount > 1 {
		score += 0.05
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// dedup removes evidence with identical type+ID (same provenance).
func dedup(evidence []Evidence) []Evidence {
	seen := make(map[string]bool)
	var result []Evidence
	for _, e := range evidence {
		key := string(e.Type) + ":" + e.ID
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}

// logicalDedup groups evidence with identical type+summary for cleaner display.
// Different from identity dedup: this preserves provenance but groups
// items that would appear identical to the user.
// Keeps the highest-relevance instance and sets GroupedCount.
func logicalDedup(evidence []Evidence) []Evidence {
	type groupKey struct {
		etype  EvidenceType
		title  string
	}

	groups := make(map[groupKey]int) // key → index in result
	var result []Evidence

	for _, e := range evidence {
		key := groupKey{etype: e.Type, title: e.Summary}
		if idx, exists := groups[key]; exists {
			// Group with existing: keep higher relevance, increment count.
			result[idx].GroupedCount++
			if e.Relevance > result[idx].Relevance {
				count := result[idx].GroupedCount
				e.GroupedCount = count
				result[idx] = e
			}
			// Preserve references to grouped IDs.
			result[idx].References = append(result[idx].References, e.ID)
		} else {
			groups[key] = len(result)
			e.GroupedCount = 1
			result = append(result, e)
		}
	}

	return result
}
