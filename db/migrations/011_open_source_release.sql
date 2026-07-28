BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('openwatchlist.schema.phase11', 0));

CREATE TABLE IF NOT EXISTS release_artifact_record (
  artifact_id text PRIMARY KEY,
  version text NOT NULL,
  vcs_ref text NOT NULL,
  artifact_type text NOT NULL,
  artifact_name text NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS release_qualification_evidence (
  evidence_id text PRIMARY KEY,
  version text NOT NULL,
  evidence_type text NOT NULL,
  tool_name text NOT NULL,
  tool_version text NOT NULL,
  result text NOT NULL CHECK (result IN ('pass','fail','informational')),
  artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS release_deployment_audit (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id text UNIQUE NOT NULL,
  version text NOT NULL,
  action text NOT NULL,
  outcome text NOT NULL,
  previous_event_sha256 text NOT NULL,
  event_sha256 text UNIQUE NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE OR REPLACE FUNCTION openwatchlist_phase11_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'release qualification records are immutable'; END $$;
DROP TRIGGER IF EXISTS release_artifact_record_immutable ON release_artifact_record;
CREATE TRIGGER release_artifact_record_immutable BEFORE UPDATE OR DELETE ON release_artifact_record FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase11_immutable();
DROP TRIGGER IF EXISTS release_qualification_evidence_immutable ON release_qualification_evidence;
CREATE TRIGGER release_qualification_evidence_immutable BEFORE UPDATE OR DELETE ON release_qualification_evidence FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase11_immutable();
DROP TRIGGER IF EXISTS release_deployment_audit_immutable ON release_deployment_audit;
CREATE TRIGGER release_deployment_audit_immutable BEFORE UPDATE OR DELETE ON release_deployment_audit FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase11_immutable();

COMMIT;
