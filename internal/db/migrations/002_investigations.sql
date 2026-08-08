-- Migration 002: Research Memory
-- Adds investigation tracking, tested surfaces, and links
-- existing tables (hypotheses, tasks, findings, sessions) to investigations.
--
-- Investigations are the research journey wrapper:
--   Investigation → Hypotheses → Tasks → Findings → Conclusions
--
-- Key rules enforced by the application layer:
--   1. Findings require evidence (cannot exist without evidence_ids)
--   2. AI can create Hypotheses but NOT Findings
--   3. Concluded investigations are effectively immutable
--   4. Conclusions carry provenance (evidence + finding IDs)

-- Investigations (research journeys)
CREATE TABLE IF NOT EXISTS investigations (
    id             TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    objective      TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'active',
    target_ids     TEXT NOT NULL DEFAULT '[]',
    conclusions    TEXT NOT NULL DEFAULT '[]',
    notes          TEXT NOT NULL DEFAULT '',
    project_id     TEXT NOT NULL REFERENCES projects(id),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    concluded_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_investigations_project ON investigations(project_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);

-- Tested surfaces (what has been checked in an investigation)
CREATE TABLE IF NOT EXISTS tested_surfaces (
    id                TEXT PRIMARY KEY,
    investigation_id  TEXT NOT NULL REFERENCES investigations(id),
    entity_id         TEXT REFERENCES entities(id),
    category          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'untested',
    evidence_ids      TEXT NOT NULL DEFAULT '[]',
    notes             TEXT NOT NULL DEFAULT '',
    project_id        TEXT NOT NULL REFERENCES projects(id),
    tested_at         TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(investigation_id, entity_id, category)
);
CREATE INDEX IF NOT EXISTS idx_tested_surfaces_investigation ON tested_surfaces(investigation_id);
CREATE INDEX IF NOT EXISTS idx_tested_surfaces_status ON tested_surfaces(status);

-- Link existing tables to investigations
-- SQLite ALTER TABLE only supports ADD COLUMN, which is fine.
ALTER TABLE hypotheses ADD COLUMN investigation_id TEXT REFERENCES investigations(id);
ALTER TABLE tasks ADD COLUMN investigation_id TEXT REFERENCES investigations(id);
ALTER TABLE findings ADD COLUMN investigation_id TEXT REFERENCES investigations(id);
ALTER TABLE sessions ADD COLUMN investigation_id TEXT REFERENCES investigations(id);

CREATE INDEX IF NOT EXISTS idx_hypotheses_investigation ON hypotheses(investigation_id);
CREATE INDEX IF NOT EXISTS idx_tasks_investigation ON tasks(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_sessions_investigation ON sessions(investigation_id);
