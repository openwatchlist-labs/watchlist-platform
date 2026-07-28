-- Phase 7C-D provider refresh governance control-plane metadata only.
CREATE TABLE IF NOT EXISTS provider_refresh_registries (
    registry_id text PRIMARY KEY,
    namespace text NOT NULL UNIQUE,
    engine_version text NOT NULL,
    last_sequence bigint NOT NULL DEFAULT 0,
    audit_head text NOT NULL DEFAULT '',
    registry_checksum text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS provider_refresh_candidates (
    candidate_id text PRIMARY KEY,
    registry_id text NOT NULL REFERENCES provider_refresh_registries(registry_id),
    target_component_id text NOT NULL REFERENCES catalog_components(component_id),
    status text NOT NULL CHECK (status IN ('ready','blocked')),
    expected_current_version_id text NOT NULL REFERENCES catalog_component_versions(version_id),
    previous_inventory_checksum text NOT NULL,
    candidate_inventory_checksum text NOT NULL,
    policy jsonb NOT NULL,
    component_changes jsonb NOT NULL,
    mapping_impacts jsonb NOT NULL,
    policy_violations jsonb NOT NULL,
    candidate_version_metadata jsonb NOT NULL,
    analyzed_at timestamptz NOT NULL,
    analyzed_by text NOT NULL,
    reason text NOT NULL,
    candidate_checksum text NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_refresh_decisions (
    decision_id text PRIMARY KEY,
    registry_id text NOT NULL REFERENCES provider_refresh_registries(registry_id),
    sequence bigint NOT NULL,
    candidate_id text NOT NULL REFERENCES provider_refresh_candidates(candidate_id),
    action text NOT NULL CHECK (action IN ('approve','reject')),
    reason text NOT NULL,
    decided_at timestamptz NOT NULL,
    decided_by text NOT NULL,
    previous_event_hash text NOT NULL,
    event_hash text NOT NULL,
    decision_checksum text NOT NULL,
    UNIQUE (registry_id, sequence)
);

CREATE TABLE IF NOT EXISTS provider_refresh_executions (
    execution_id text PRIMARY KEY,
    registry_id text NOT NULL REFERENCES provider_refresh_registries(registry_id),
    sequence bigint NOT NULL,
    action text NOT NULL CHECK (action IN ('promote','rollback')),
    candidate_id text REFERENCES provider_refresh_candidates(candidate_id),
    decision_id text REFERENCES provider_refresh_decisions(decision_id),
    component_id text NOT NULL REFERENCES catalog_components(component_id),
    previous_version_id text NOT NULL REFERENCES catalog_component_versions(version_id),
    target_version_id text NOT NULL REFERENCES catalog_component_versions(version_id),
    catalog_activation_id text NOT NULL REFERENCES catalog_component_activations(activation_id),
    reason text NOT NULL,
    executed_at timestamptz NOT NULL,
    executed_by text NOT NULL,
    previous_event_hash text NOT NULL,
    event_hash text NOT NULL,
    execution_checksum text NOT NULL,
    UNIQUE (registry_id, sequence)
);

-- Deliberately absent: provider entities, names, aliases, addresses, identifiers,
-- and relationships. Those remain immutable catalog artifacts.
