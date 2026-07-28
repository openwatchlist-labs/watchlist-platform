BEGIN;

CREATE TABLE IF NOT EXISTS catalog_registry_namespaces (
    namespace TEXT PRIMARY KEY,
    registry_id TEXT NOT NULL UNIQUE,
    engine_version TEXT NOT NULL,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    audit_head CHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS catalog_components (
    component_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL REFERENCES catalog_registry_namespaces(namespace),
    component_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    catalog_mode TEXT NOT NULL CHECK (catalog_mode IN ('official_list', 'provider')),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    description TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    component_checksum CHAR(64) NOT NULL,
    UNIQUE(namespace, component_key)
);

CREATE TABLE IF NOT EXISTS catalog_component_versions (
    version_id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES catalog_components(component_id),
    catalog_id TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    catalog_checksum CHAR(64) NOT NULL,
    catalog_schema TEXT NOT NULL,
    artifact_uri TEXT NOT NULL,
    artifact_sha256 CHAR(64) NOT NULL,
    source_manifest_id TEXT NOT NULL,
    source_manifest_checksum CHAR(64),
    record_count BIGINT NOT NULL CHECK (record_count > 0),
    producer_version TEXT NOT NULL,
    source_descriptor JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    registered_at TIMESTAMPTZ NOT NULL,
    registered_by TEXT NOT NULL,
    version_checksum CHAR(64) NOT NULL,
    UNIQUE(component_id, catalog_id, catalog_version, catalog_checksum, artifact_sha256)
);

CREATE TABLE IF NOT EXISTS catalog_component_activations (
    activation_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL REFERENCES catalog_registry_namespaces(namespace),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    component_id TEXT NOT NULL REFERENCES catalog_components(component_id),
    action TEXT NOT NULL CHECK (action IN ('activate', 'rollback')),
    target_version_id TEXT NOT NULL REFERENCES catalog_component_versions(version_id),
    previous_version_id TEXT REFERENCES catalog_component_versions(version_id),
    component_epoch BIGINT NOT NULL CHECK (component_epoch > 0),
    reason TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL,
    activated_by TEXT NOT NULL,
    previous_event_hash CHAR(64) NOT NULL DEFAULT '',
    event_hash CHAR(64) NOT NULL,
    UNIQUE(namespace, sequence),
    UNIQUE(component_id, component_epoch)
);

CREATE TABLE IF NOT EXISTS active_catalog_component_versions (
    component_id TEXT PRIMARY KEY REFERENCES catalog_components(component_id),
    version_id TEXT NOT NULL REFERENCES catalog_component_versions(version_id),
    activation_id TEXT NOT NULL REFERENCES catalog_component_activations(activation_id),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    activated_at TIMESTAMPTZ NOT NULL,
    activated_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS catalog_component_versions_component_idx
    ON catalog_component_versions(component_id, registered_at DESC);

CREATE INDEX IF NOT EXISTS catalog_component_activations_component_idx
    ON catalog_component_activations(component_id, component_epoch DESC);

COMMIT;
