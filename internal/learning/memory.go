package learning

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Memory persists and queries learned research patterns.
type Memory struct {
	db *sql.DB
}

// NewMemory creates a learning memory backed by SQLite.
func NewMemory(db *sql.DB) *Memory {
	return &Memory{db: db}
}

// EnsureTable creates the learning tables.
func (m *Memory) EnsureTable() error {
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS research_patterns (
			id               TEXT PRIMARY KEY,
			name             TEXT NOT NULL,
			description      TEXT DEFAULT '',
			category         TEXT NOT NULL,
			confidence       REAL DEFAULT 0.0,
			occurrences      INTEGER DEFAULT 1,
			historical_outcome TEXT DEFAULT '',
			evidence_ids     TEXT DEFAULT '[]',
			investigation_ids TEXT DEFAULT '[]',
			priority_boost   REAL DEFAULT 0.0,
			first_seen       DATETIME NOT NULL,
			last_seen        DATETIME NOT NULL,
			decay_factor     REAL DEFAULT 1.0
		);

		CREATE TABLE IF NOT EXISTS research_outcomes (
			id                    TEXT PRIMARY KEY,
			pattern_id            TEXT NOT NULL,
			investigation_id      TEXT NOT NULL,
			productive            INTEGER DEFAULT 0,
			findings_produced     INTEGER DEFAULT 0,
			observations_produced INTEGER DEFAULT 0,
			notes                 TEXT DEFAULT '',
			recorded_at           DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS learning_events (
			id               TEXT PRIMARY KEY,
			type             TEXT NOT NULL,
			pattern_name     TEXT NOT NULL,
			context          TEXT DEFAULT '',
			evidence_ids     TEXT DEFAULT '[]',
			confidence_delta REAL DEFAULT 0.0,
			recorded_at      DATETIME NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_patterns_name ON research_patterns(name);
		CREATE INDEX IF NOT EXISTS idx_patterns_category ON research_patterns(category);
		CREATE INDEX IF NOT EXISTS idx_outcomes_pattern ON research_outcomes(pattern_id);
		CREATE INDEX IF NOT EXISTS idx_events_pattern ON learning_events(pattern_name);
	`)
	return err
}

// StorePattern saves or updates a research pattern.
func (m *Memory) StorePattern(p *ResearchPattern) error {
	evidenceJSON, _ := json.Marshal(p.EvidenceIDs)
	investJSON, _ := json.Marshal(p.InvestigationIDs)

	_, err := m.db.Exec(`
		INSERT INTO research_patterns
			(id, name, description, category, confidence, occurrences,
			 historical_outcome, evidence_ids, investigation_ids,
			 priority_boost, first_seen, last_seen, decay_factor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			confidence = excluded.confidence,
			occurrences = excluded.occurrences,
			historical_outcome = excluded.historical_outcome,
			evidence_ids = excluded.evidence_ids,
			investigation_ids = excluded.investigation_ids,
			priority_boost = excluded.priority_boost,
			last_seen = excluded.last_seen,
			decay_factor = excluded.decay_factor
	`,
		p.ID.String(), p.Name, p.Description, string(p.Category),
		p.Confidence, p.Occurrences, p.HistoricalOutcome,
		string(evidenceJSON), string(investJSON),
		p.PriorityBoost, p.FirstSeen.Format(time.RFC3339),
		p.LastSeen.Format(time.RFC3339), p.DecayFactor,
	)
	return err
}

// GetPattern retrieves a pattern by name.
func (m *Memory) GetPattern(name string) (*ResearchPattern, error) {
	row := m.db.QueryRow(`
		SELECT id, name, description, category, confidence, occurrences,
			historical_outcome, evidence_ids, investigation_ids,
			priority_boost, first_seen, last_seen, decay_factor
		FROM research_patterns WHERE name = ?
	`, name)

	return scanPattern(row)
}

// AllPatterns returns all learned patterns ordered by confidence.
func (m *Memory) AllPatterns() ([]ResearchPattern, error) {
	rows, err := m.db.Query(`
		SELECT id, name, description, category, confidence, occurrences,
			historical_outcome, evidence_ids, investigation_ids,
			priority_boost, first_seen, last_seen, decay_factor
		FROM research_patterns
		ORDER BY confidence DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []ResearchPattern
	for rows.Next() {
		p, err := scanPatternRow(rows)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, *p)
	}
	return patterns, rows.Err()
}

// PatternCount returns the total number of learned patterns.
func (m *Memory) PatternCount() int {
	var count int
	m.db.QueryRow(`SELECT COUNT(*) FROM research_patterns`).Scan(&count)
	return count
}

// OutcomeCount returns the total number of recorded outcomes.
func (m *Memory) OutcomeCount() int {
	var count int
	m.db.QueryRow(`SELECT COUNT(*) FROM research_outcomes`).Scan(&count)
	return count
}

// EventCount returns the total number of learning events.
func (m *Memory) EventCount() int {
	var count int
	m.db.QueryRow(`SELECT COUNT(*) FROM learning_events`).Scan(&count)
	return count
}

// RecordOutcome saves a research outcome.
func (m *Memory) RecordOutcome(o *ResearchOutcome) error {
	productive := 0
	if o.Productive {
		productive = 1
	}
	_, err := m.db.Exec(`
		INSERT INTO research_outcomes
			(id, pattern_id, investigation_id, productive,
			 findings_produced, observations_produced, notes, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		o.ID.String(), o.PatternID.String(), o.InvestigationID.String(),
		productive, o.FindingsProduced, o.ObservationsProduced,
		o.Notes, o.RecordedAt.Format(time.RFC3339),
	)
	return err
}

// RecordEvent saves a learning event.
func (m *Memory) RecordEvent(e *LearningEvent) error {
	evidenceJSON, _ := json.Marshal(e.EvidenceIDs)
	_, err := m.db.Exec(`
		INSERT INTO learning_events
			(id, type, pattern_name, context, evidence_ids,
			 confidence_delta, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		e.ID.String(), string(e.Type), e.PatternName, e.Context,
		string(evidenceJSON), e.ConfidenceDelta,
		e.RecordedAt.Format(time.RFC3339),
	)
	return err
}

// RecentEvents returns the N most recent learning events.
func (m *Memory) RecentEvents(limit int) ([]LearningEvent, error) {
	rows, err := m.db.Query(`
		SELECT id, type, pattern_name, context, evidence_ids,
			confidence_delta, recorded_at
		FROM learning_events
		ORDER BY recorded_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []LearningEvent
	for rows.Next() {
		var e LearningEvent
		var id, evidenceJSON, recordedAt string
		err := rows.Scan(
			&id, (*string)(&e.Type), &e.PatternName, &e.Context,
			&evidenceJSON, &e.ConfidenceDelta, &recordedAt,
		)
		if err != nil {
			return nil, err
		}
		e.ID, _ = uuid.Parse(id)
		json.Unmarshal([]byte(evidenceJSON), &e.EvidenceIDs)
		e.RecordedAt, _ = time.Parse(time.RFC3339, recordedAt)
		events = append(events, e)
	}
	return events, rows.Err()
}

func scanPattern(row *sql.Row) (*ResearchPattern, error) {
	var p ResearchPattern
	var id, evidenceJSON, investJSON, firstSeen, lastSeen string

	err := row.Scan(
		&id, &p.Name, &p.Description, (*string)(&p.Category),
		&p.Confidence, &p.Occurrences, &p.HistoricalOutcome,
		&evidenceJSON, &investJSON,
		&p.PriorityBoost, &firstSeen, &lastSeen, &p.DecayFactor,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning pattern: %w", err)
	}

	p.ID, _ = uuid.Parse(id)
	json.Unmarshal([]byte(evidenceJSON), &p.EvidenceIDs)
	json.Unmarshal([]byte(investJSON), &p.InvestigationIDs)
	p.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	p.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)

	return &p, nil
}

func scanPatternRow(rows *sql.Rows) (*ResearchPattern, error) {
	var p ResearchPattern
	var id, evidenceJSON, investJSON, firstSeen, lastSeen string

	err := rows.Scan(
		&id, &p.Name, &p.Description, (*string)(&p.Category),
		&p.Confidence, &p.Occurrences, &p.HistoricalOutcome,
		&evidenceJSON, &investJSON,
		&p.PriorityBoost, &firstSeen, &lastSeen, &p.DecayFactor,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning pattern row: %w", err)
	}

	p.ID, _ = uuid.Parse(id)
	json.Unmarshal([]byte(evidenceJSON), &p.EvidenceIDs)
	json.Unmarshal([]byte(investJSON), &p.InvestigationIDs)
	p.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	p.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)

	return &p, nil
}
