-- Test schema for entity package tests.
-- Minimal tables needed for entity store + materializer testing.

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id            TEXT PRIMARY KEY,
    sha256        TEXT NOT NULL,
    original_path TEXT NOT NULL,
    stored_path   TEXT NOT NULL,
    file_name     TEXT NOT NULL,
    file_size     INTEGER NOT NULL DEFAULT 0,
    mime_type     TEXT NOT NULL DEFAULT '',
    parser_used   TEXT NOT NULL DEFAULT '',
    imported_at   TEXT NOT NULL,
    project_id    TEXT NOT NULL REFERENCES projects(id),
    version       INTEGER NOT NULL DEFAULT 1,
    metadata      TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS observations (
    id             TEXT PRIMARY KEY,
    type           TEXT NOT NULL,
    artifact_id    TEXT NOT NULL REFERENCES artifacts(id),
    source_tool    TEXT NOT NULL,
    project_id     TEXT NOT NULL REFERENCES projects(id),
    data           TEXT NOT NULL DEFAULT '{}',
    raw_value      TEXT NOT NULL DEFAULT '',
    checksum       TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    ingested_at    TEXT NOT NULL,
    parser_version TEXT NOT NULL DEFAULT '',
    UNIQUE(checksum, project_id)
);

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
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE(type, value, project_id)
);

CREATE TABLE IF NOT EXISTS entity_observations (
    entity_id      TEXT NOT NULL REFERENCES entities(id),
    observation_id TEXT NOT NULL REFERENCES observations(id),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (entity_id, observation_id)
);

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
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE(source_entity_id, target_entity_id, type, project_id)
);
