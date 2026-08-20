-- SEC-7 Addendum 2 D27 (F-D, MEDIUM): screening_ledger_purge_snapshots
-- becomes SECURITY DEFINER, so a party holding owl_migrator -- which
-- currently both owns screening_ledger_retention_tombstone and holds
-- unrestricted INSERT on it -- can no longer forge a tombstone directly.
-- The predicate deciding which snapshots may be tombstoned is enforced by
-- code owl_migrator cannot alter, owned by owl_ledger_ddl (the role D17
-- already introduced -- no fifth role).
--
-- Fail-closed preamble, per CLAUDE.md's trap on 009g's silent-skip style,
-- matching 015/017's own style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 Addendum 2 D27: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 Addendum 2 D27: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

-- SET search_path is not boilerplate (D27's own text): without it, this
-- definer function would resolve screening_ledger_retention_tombstone
-- and screening_ledger_snapshot against the CALLER's search_path, which
-- would hand the caller (owl_migrator) exactly the control this definer
-- boundary exists to take away -- a caller-controlled schema earlier in
-- their own search_path could intercept the unqualified names.
--
-- Existing time-floor form, unchanged in behavior from 008g's version
-- (still the exact same predicate: expires_at < p_before AND purged_at
-- IS NULL) -- now SECURITY DEFINER so INSERT/UPDATE run as the owner
-- (owl_ledger_ddl) regardless of caller, and the caller needs only
-- EXECUTE, never table-level DML.
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE affected bigint;
BEGIN
  INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
    SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason
    FROM screening_ledger_snapshot
    WHERE expires_at < p_before AND purged_at IS NULL
    ON CONFLICT (snapshot_sha256) DO NOTHING;
  UPDATE screening_ledger_snapshot
    SET purged_at = clock_timestamp(), purge_reason = p_reason,
        envelope_json = (envelope_json - 'nonce_base64' - 'ciphertext_base64')
          || jsonb_build_object('purged_at', clock_timestamp(), 'purge_reason', p_reason)
    WHERE expires_at < p_before AND purged_at IS NULL;
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected;
END;
$$;

-- D28's local-narrows/server-floors form. p_snapshot_sha256 is the set
-- Store.PurgeExpired's local path already determined eligible under
-- ADR-0007's legal-holds rule (holds/, which this function does not and
-- should not learn about -- it has no filesystem to consult). The floor
-- (expires_at < p_before, not yet purged) is re-checked here regardless
-- of what the caller claims, so the caller cannot record a purge for a
-- snapshot that is not actually expired even through this sanctioned
-- path. Returns exactly the subset of p_snapshot_sha256 this call
-- actually tombstoned -- the only set the caller may then mark purged in
-- its own local envelopes.
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_before timestamptz, p_operator text, p_reason text)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE recorded text[];
BEGIN
  WITH eligible AS (
    SELECT snapshot_sha256 FROM screening_ledger_snapshot
    WHERE snapshot_sha256 = ANY(p_snapshot_sha256) AND expires_at < p_before AND purged_at IS NULL
  ), inserted AS (
    INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
      SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM eligible
      ON CONFLICT (snapshot_sha256) DO NOTHING
  ), updated AS (
    UPDATE screening_ledger_snapshot
      SET purged_at = clock_timestamp(), purge_reason = p_reason,
          envelope_json = (envelope_json - 'nonce_base64' - 'ciphertext_base64')
            || jsonb_build_object('purged_at', clock_timestamp(), 'purge_reason', p_reason)
      WHERE snapshot_sha256 IN (SELECT snapshot_sha256 FROM eligible)
      RETURNING snapshot_sha256
  )
  SELECT array_agg(snapshot_sha256) INTO recorded FROM updated;
  RETURN COALESCE(recorded, ARRAY[]::text[]);
END;
$$;

-- Ownership of these two functions and of screening_ledger_retention_
-- tombstone itself moves to owl_ledger_ddl in
-- scripts/ci/provision_test_roles.sh's (renamed) grant-ddl-ownership
-- step, not here -- ADR-0001:208's "no migration contains CREATE ROLE or
-- GRANT" rule, exactly as §3.4 already reconciled the anchor role and as
-- 015/017 already follow for screening_ledger_anchor. This migration
-- runs as owl_migrator, which still owns both functions and the table at
-- this point; the ownership transfer is a deliberate, separate,
-- provisioning-time action.

COMMIT;
