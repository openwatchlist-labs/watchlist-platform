-- SEC-7 Addendum 3 D32 (G-C, CRITICAL): "hardening that rides along,"
-- explicitly labelled as hardening and not as the fix -- the actual fix
-- is VerifyAnchored's purge-claim adjudication against the anchored audit
-- chain (internal/screeningledger/anchor.go, adjudicatePurgeClaims).
--
-- CAP #2 §7.3 executed both halves of the defect this migration narrows:
-- `p_before => 'infinity'` tombstoned snapshots that were not expired
-- (the caller controls p_before), and a fabricated
-- screening_ledger_snapshot row with a past expires_at was tombstoned
-- under a perfectly sane p_before (the caller, owl_migrator, also owns
-- and writes screening_ledger_snapshot.expires_at). D8's class applies:
-- the verified data must not choose its own acceptance criteria.
-- Tightening the predicate does not remove that class -- it raises the
-- cost of the forgery without eliminating it, which is precisely why
-- this is not the fix (ADR-0007 Addendum 3 D32's own text).
--
-- Two changes, both to both overloads' predicate, signatures UNCHANGED
-- (p_before stays a parameter but is no longer consulted, so existing Go
-- call sites -- postgres.go's PurgeExpired/RecordPurge -- need no change):
--   1. The caller-supplied p_before is ignored; clock_timestamp() is used
--      instead. A caller cannot choose the present.
--   2. The expiry floor reads screening_ledger_event.expires_at -- a
--      column on a relation carrying a row-immutability trigger and whose
--      value is inside the chain-MACed Event -- joined through
--      request_snapshot_sha256/response_snapshot_sha256, rather than
--      screening_ledger_snapshot.expires_at. owl_migrator still owns
--      screening_ledger_event too, so this does not eliminate the
--      forgery (a fabricated event row alongside a fabricated snapshot
--      row still passes); it means a single fabricated snapshot row no
--      longer suffices alone.
--
-- Fail-closed preamble, matching 015/017/019's style, per CLAUDE.md's
-- trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 Addendum 3 D32: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 Addendum 3 D32: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 Addendum 3 D32: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE affected bigint;
BEGIN
  INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
    SELECT s.snapshot_sha256, clock_timestamp(), p_operator, p_reason
    FROM screening_ledger_snapshot s
    WHERE s.purged_at IS NULL
      AND EXISTS (
        SELECT 1 FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
          AND e.expires_at < clock_timestamp()
      )
    ON CONFLICT (snapshot_sha256) DO NOTHING;
  UPDATE screening_ledger_snapshot s
    SET purged_at = clock_timestamp(), purge_reason = p_reason,
        envelope_json = (envelope_json - 'nonce_base64' - 'ciphertext_base64')
          || jsonb_build_object('purged_at', clock_timestamp(), 'purge_reason', p_reason)
    WHERE s.purged_at IS NULL
      AND EXISTS (
        SELECT 1 FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
          AND e.expires_at < clock_timestamp()
      );
  GET DIAGNOSTICS affected = ROW_COUNT;
  RETURN affected;
END;
$$;

CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_before timestamptz, p_operator text, p_reason text)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE recorded text[];
BEGIN
  WITH eligible AS (
    SELECT s.snapshot_sha256
    FROM screening_ledger_snapshot s
    WHERE s.snapshot_sha256 = ANY(p_snapshot_sha256) AND s.purged_at IS NULL
      AND EXISTS (
        SELECT 1 FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
          AND e.expires_at < clock_timestamp()
      )
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

-- This migration runs as owl_migrator, in db/migrations/ order, which
-- always precedes scripts/ci/provision_test_roles.sh grant-ddl-ownership
-- (the step that transfers these two functions' ownership to
-- owl_ledger_ddl) -- so owl_migrator still owns both overloads at this
-- point and CREATE OR REPLACE FUNCTION succeeds without a preceding
-- ownership check, exactly as 019 already assumed. It does not change
-- ownership itself; grant-ddl-ownership's later ALTER FUNCTION ... OWNER
-- TO is still what moves it.

COMMIT;
