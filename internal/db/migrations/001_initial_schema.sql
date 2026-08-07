-- Migration 001: Initial Schema
-- Creates all core tables for the workspace database.
-- This migration corresponds to the domain design (Phase -1).

-- Schema version tracking
CREATE TABLE IF NOT EXISTS migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    slug         TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',
    target_scope TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    archived_at  TEXT
);

-- Content-addressable artifact store
CREATE TABLE IF NOT EXISTS artifacts (
    id            TEXT PRIMARY KEY,
    sha256        TEXT NOT NULL UNIQUE,
    original_path TEXT NOT NULL,
    stored_path   TEXT NOT NULL,
    file_name     TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
    parser_used   TEXT NOT NULL DEFAULT '',
    imported_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    project_id    TEXT NOT NULL REFERENCES projects(id),
    version       INTEGER NOT NULL DEFAULT 1,
    metadata      TEXT NOT NULL DEFAULT '{}',
    UNIQUE(original_path, project_id, version)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_project ON artifacts(project_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);

-- Immutable observations (Pillar #1)
CREATE TABLE IF NOT EXISTS observations (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
    source_tool     TEXT NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    data            TEXT NOT NULL DEFAULT '{}',
    raw_value       TEXT NOT NULL DEFAULT '',
    checksum        TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    ingested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    parser_version  TEXT NOT NULL DEFAULT '1.0.0',
    UNIQUE(checksum, project_id)
);
CREATE INDEX IF NOT EXISTS idx_observations_type ON observations(type);
CREATE INDEX IF NOT EXISTS idx_observations_artifact ON observations(artifact_id);
CREATE INDEX IF NOT EXISTS idx_observations_project ON observations(project_id);

-- Entities (Knowledge Graph nodes, Pillar #3)
CREATE TABLE IF NOT EXISTS entities (
    id                TEXT PRIMARY KEY,
    canonical_id      TEXT NOT NULL,
    type              TEXT NOT NULL,
    value             TEXT NOT NULL,
    attributes        TEXT NOT NULL DEFAULT '{}',
    project_id        TEXT NOT NULL REFERENCES projects(id),
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(type, value, project_id)
);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
CREATE INDEX IF NOT EXISTS idx_entities_project ON entities(project_id);
CREATE INDEX IF NOT EXISTS idx_entities_canonical ON entities(canonical_id);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);

-- Entity-to-Observation provenance link (many-to-many)
CREATE TABLE IF NOT EXISTS entity_observations (
    entity_id      TEXT NOT NULL REFERENCES entities(id),
    observation_id TEXT NOT NULL REFERENCES observations(id),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (entity_id, observation_id)
);

-- Relationships (Knowledge Graph edges)
CREATE TABLE IF NOT EXISTS relationships (
    id               TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES entities(id),
    target_entity_id TEXT NOT NULL REFERENCES entities(id),
    type             TEXT NOT NULL,
    attributes       TEXT NOT NULL DEFAULT '{}',
    observation_id   TEXT REFERENCES observations(id),
    project_id       TEXT NOT NULL REFERENCES projects(id),
    first_seen_at    TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(source_entity_id, target_entity_id, type, project_id)
);
CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(type);

-- Evidence (immutable provenance links, Pillar #2)
CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,
    observation_id  TEXT NOT NULL REFERENCES observations(id),
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
    entity_id       TEXT REFERENCES entities(id),
    claim_type      TEXT NOT NULL,
    claim_id        TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'supports',
    description     TEXT NOT NULL DEFAULT '',
    source_location TEXT NOT NULL DEFAULT '',
    strength        REAL NOT NULL DEFAULT 0.5,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_claim ON evidence(claim_type, claim_id);
CREATE INDEX IF NOT EXISTS idx_evidence_observation ON evidence(observation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence(entity_id);

-- Correlations
CREATE TABLE IF NOT EXISTS correlations (
    id              TEXT PRIMARY KEY,
    entity_ids      TEXT NOT NULL DEFAULT '[]',
    type            TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    description     TEXT NOT NULL DEFAULT '',
    observation_ids TEXT NOT NULL DEFAULT '[]',
    project_id      TEXT NOT NULL REFERENCES projects(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Insights
CREATE TABLE IF NOT EXISTS insights (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'info',
    entity_ids   TEXT NOT NULL DEFAULT '[]',
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    rule_id      TEXT,
    diff_id      TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    project_id   TEXT NOT NULL REFERENCES projects(id),
    detected_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_insights_project ON insights(project_id);
CREATE INDEX IF NOT EXISTS idx_insights_type ON insights(type);

-- Findings (researcher-confirmed)
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'info',
    status        TEXT NOT NULL DEFAULT 'draft',
    entity_ids    TEXT NOT NULL DEFAULT '[]',
    evidence_ids  TEXT NOT NULL DEFAULT '[]',
    hypothesis_id TEXT,
    notes         TEXT NOT NULL DEFAULT '',
    project_id    TEXT NOT NULL REFERENCES projects(id),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    confirmed_at  TEXT
);

-- Hypotheses
CREATE TABLE IF NOT EXISTS hypotheses (
    id                   TEXT PRIMARY KEY,
    title                TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    type                 TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'proposed',
    confidence           REAL NOT NULL DEFAULT 0.0,
    entity_ids           TEXT NOT NULL DEFAULT '[]',
    supporting_evidence  TEXT NOT NULL DEFAULT '[]',
    refuting_evidence    TEXT NOT NULL DEFAULT '[]',
    notes                TEXT NOT NULL DEFAULT '',
    project_id           TEXT NOT NULL REFERENCES projects(id),
    proposed_by          TEXT NOT NULL DEFAULT 'system',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    resolved_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_project ON hypotheses(project_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    type             TEXT NOT NULL,
    priority         TEXT NOT NULL DEFAULT 'medium',
    risk             REAL NOT NULL DEFAULT 0.0,
    confidence       REAL NOT NULL DEFAULT 0.0,
    evidence_count   INTEGER NOT NULL DEFAULT 0,
    estimated_effort TEXT NOT NULL DEFAULT 'moderate',
    status           TEXT NOT NULL DEFAULT 'pending',
    entity_ids       TEXT NOT NULL DEFAULT '[]',
    insight_id       TEXT,
    hypothesis_id    TEXT,
    project_id       TEXT NOT NULL REFERENCES projects(id),
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority);

-- Timeline events (append-only)
CREATE TABLE IF NOT EXISTS timeline_events (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    action       TEXT NOT NULL,
    before_state TEXT,
    after_state  TEXT,
    project_id   TEXT NOT NULL REFERENCES projects(id),
    occurred_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_timeline_project ON timeline_events(project_id);
CREATE INDEX IF NOT EXISTS idx_timeline_occurred ON timeline_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_timeline_subject ON timeline_events(subject_type, subject_id);

-- Snapshots
CREATE TABLE IF NOT EXISTS snapshots (
    id                 TEXT PRIMARY KEY,
    label              TEXT,
    entity_count       INTEGER NOT NULL DEFAULT 0,
    relationship_count INTEGER NOT NULL DEFAULT 0,
    observation_count  INTEGER NOT NULL DEFAULT 0,
    entity_hashes      TEXT NOT NULL DEFAULT '{}',
    project_id         TEXT NOT NULL REFERENCES projects(id),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Diffs
CREATE TABLE IF NOT EXISTS diffs (
    id                    TEXT PRIMARY KEY,
    snapshot_a_id         TEXT NOT NULL REFERENCES snapshots(id),
    snapshot_b_id         TEXT NOT NULL REFERENCES snapshots(id),
    entities_added        TEXT NOT NULL DEFAULT '[]',
    entities_removed      TEXT NOT NULL DEFAULT '[]',
    entities_changed      TEXT NOT NULL DEFAULT '[]',
    relationships_added   TEXT NOT NULL DEFAULT '[]',
    relationships_removed TEXT NOT NULL DEFAULT '[]',
    summary               TEXT NOT NULL DEFAULT '',
    project_id            TEXT NOT NULL REFERENCES projects(id),
    computed_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Sessions (AI invocations)
CREATE TABLE IF NOT EXISTS sessions (
    id                TEXT PRIMARY KEY,
    type              TEXT NOT NULL,
    question          TEXT NOT NULL,
    context_snapshot  TEXT NOT NULL DEFAULT '[]',
    tokens_used       INTEGER NOT NULL DEFAULT 0,
    model_used        TEXT NOT NULL DEFAULT '',
    raw_response      TEXT NOT NULL DEFAULT '',
    verified_response TEXT,
    rejected          INTEGER NOT NULL DEFAULT 0,
    rejection_reason  TEXT,
    project_id        TEXT NOT NULL REFERENCES projects(id),
    duration_ms       INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_id);

-- Reasoning steps
CREATE TABLE IF NOT EXISTS reasoning_steps (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    step_index   INTEGER NOT NULL,
    type         TEXT NOT NULL,
    input        TEXT NOT NULL DEFAULT '',
    output       TEXT NOT NULL DEFAULT '',
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    confidence   REAL NOT NULL DEFAULT 0.0,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_reasoning_session ON reasoning_steps(session_id);

-- Citations
CREATE TABLE IF NOT EXISTS citations (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    entity_id   TEXT NOT NULL REFERENCES entities(id),
    claim_text  TEXT NOT NULL DEFAULT '',
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_citations_session ON citations(session_id);

-- Rule definitions
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    condition   TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action      TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Cache entries
CREATE TABLE IF NOT EXISTS cache_entries (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    cache_type  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at  TEXT,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    last_hit_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cache_type ON cache_entries(cache_type);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries(expires_at);

-- Embedding metadata (vector table created separately when sqlite-vec is available)
CREATE TABLE IF NOT EXISTS embedding_metadata (
    id          TEXT PRIMARY KEY,
    entity_id   TEXT REFERENCES entities(id),
    entity_type TEXT NOT NULL,
    text_hash   TEXT NOT NULL,
    model_used  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
