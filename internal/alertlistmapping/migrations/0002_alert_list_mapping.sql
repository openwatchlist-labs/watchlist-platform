-- Phase 7C-C exact alert-list mapping control-plane schema.
-- Raw list names use the C collation so equality is exact and case-sensitive.
-- Full watchlist entities, aliases, addresses, and identifiers remain immutable artifacts.

CREATE TABLE IF NOT EXISTS alert_list_mapping_namespaces (
  namespace TEXT COLLATE "C" PRIMARY KEY,
  mapping_registry_id TEXT COLLATE "C" NOT NULL UNIQUE,
  engine_version TEXT COLLATE "C" NOT NULL,
  last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  audit_head CHAR(64) COLLATE "C" NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_list_mapping_keys (
  mapping_id TEXT COLLATE "C" PRIMARY KEY,
  mapping_registry_id TEXT COLLATE "C" NOT NULL,
  namespace TEXT COLLATE "C" NOT NULL REFERENCES alert_list_mapping_namespaces(namespace),
  source_system_id TEXT COLLATE "C" NOT NULL,
  raw_list_name TEXT COLLATE "C" NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  created_by TEXT COLLATE "C" NOT NULL,
  key_checksum CHAR(64) COLLATE "C" NOT NULL,
  UNIQUE(namespace, source_system_id, raw_list_name)
);

CREATE TABLE IF NOT EXISTS alert_list_mapping_versions (
  mapping_version_id TEXT COLLATE "C" PRIMARY KEY,
  mapping_id TEXT COLLATE "C" NOT NULL REFERENCES alert_list_mapping_keys(mapping_id),
  mapping_registry_id TEXT COLLATE "C" NOT NULL,
  namespace TEXT COLLATE "C" NOT NULL REFERENCES alert_list_mapping_namespaces(namespace),
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  source_system_id TEXT COLLATE "C" NOT NULL,
  raw_list_name TEXT COLLATE "C" NOT NULL,
  action TEXT COLLATE "C" NOT NULL CHECK (action IN ('bind', 'retire')),
  component_id TEXT COLLATE "C" REFERENCES catalog_components(component_id),
  effective_from TIMESTAMPTZ NOT NULL,
  effective_to TIMESTAMPTZ,
  supersedes_version_id TEXT COLLATE "C" REFERENCES alert_list_mapping_versions(mapping_version_id),
  reason TEXT COLLATE "C" NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  created_by TEXT COLLATE "C" NOT NULL,
  previous_event_hash CHAR(64) COLLATE "C" NOT NULL DEFAULT '',
  event_hash CHAR(64) COLLATE "C" NOT NULL,
  version_checksum CHAR(64) COLLATE "C" NOT NULL,
  UNIQUE(namespace, sequence),
  UNIQUE(mapping_id, effective_from),
  CHECK ((action = 'bind' AND component_id IS NOT NULL) OR (action = 'retire' AND component_id IS NULL)),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE INDEX IF NOT EXISTS alert_list_mapping_versions_exact_lookup
  ON alert_list_mapping_versions(namespace, source_system_id, raw_list_name, effective_from DESC);
