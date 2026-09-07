-- ADR-0007 Addendum 11 D98 (O-A's other half, HIGH): both
-- screening_ledger_purge_snapshots overloads move from ANY-expired (a
-- bare EXISTS on an unexpired event) to ALL-expired (EXISTS a
-- referencing event AND NOT EXISTS an unexpired one). D97's floor is
-- MAX(Event.ExpiresAt) over every event referencing a snapshot; D89's
-- own justification for that floor -- "purged_at > expires_at holds by
-- construction for every legitimate purge" -- is true of MIN(expires_at)
-- under the shipped ANY-expired predicate and false of MAX(expires_at),
-- so shipping D97 without this migration would make the new floor's own
-- by-construction argument false (CLAUDE.md rule 5.1/D13: an existing
-- weakness that would make the new guarantee false is in scope by
-- definition). D97 and D98 ship together; neither is complete alone
-- (ADR-0007 Addendum 11 D103's first withdrawal condition).
--
-- The first EXISTS in each predicate is not decoration: without it a
-- snapshot referenced by NO event at all would satisfy NOT EXISTS
-- vacuously and become newly eligible, a strictly wider population than
-- the shipped predicate has. Both are asserted by D103's own required
-- positive control.
--
-- The eligibility population stays deliberately UNSCOPED by ledger_id
-- (global), unlike D97's floor (per-ledger) -- the two are opposite on
-- purpose. screening_ledger_snapshot carries no ledger_id column, so the
-- bytes genuinely belong to every ledger that ever screened them; a
-- purge must satisfy every ledger's obligation, and scoping eligibility
-- to one ledger would let ledger A destroy evidence ledger B is still
-- holding. R43 records the residual this leaves (the floor is only ever
-- as strong as what THIS ledger's own chain can authenticate) and why it
-- is conservative rather than a hole.
--
-- Signatures UNCHANGED from 019/020, same reason 020's own header states:
-- existing Go call sites (postgres.go's PurgeExpired/RecordPurge) need no
-- change.
--
-- This IS a re-provisioning event on an already-provisioned database:
-- both overloads are requiredProtectedObjects members (postgres.go), so
-- this CREATE OR REPLACE FUNCTION is refused by D34 on a database that
-- has already run grant-ddl-ownership, exactly as 020 already was for
-- D87's own change (docs/operations/sec7-database-copies.md's documented
-- recovery window covers this migration by the same procedure, one
-- migration later). On a fresh database this cost does not apply: this
-- migration runs, in db/migrations/ order, before grant-ddl-ownership
-- ever installs the event triggers.
--
-- Fail-closed preamble, matching 015/017/019/020's style, per CLAUDE.md's
-- trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 11 D98: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 11 D98: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 11 D98: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE affected bigint;
DECLARE conflict_sha256 text;
DECLARE conflict_purged_at timestamptz;
DECLARE conflict_operator text;
BEGIN
  BEGIN
    INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
      SELECT s.snapshot_sha256, clock_timestamp(), p_operator, p_reason
      FROM screening_ledger_snapshot s
      WHERE s.purged_at IS NULL
        AND EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
        )
        AND NOT EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
            AND e.expires_at >= clock_timestamp()
        );
  EXCEPTION WHEN unique_violation THEN
    SELECT s.snapshot_sha256, t.purged_at, t.operator INTO conflict_sha256, conflict_purged_at, conflict_operator
      FROM screening_ledger_snapshot s
      JOIN screening_ledger_retention_tombstone t ON t.snapshot_sha256 = s.snapshot_sha256
      WHERE s.purged_at IS NULL
        AND EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
        )
        AND NOT EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
            AND e.expires_at >= clock_timestamp()
        )
      LIMIT 1;
    RAISE EXCEPTION 'ADR-0007 Addendum 10 D87: a retention tombstone already exists for snapshot % (purged_at=%, operator=%), but the mirror still records it unpurged -- refusing rather than adopting the pre-existing row (SQLSTATE 23505)', conflict_sha256, conflict_purged_at, conflict_operator;
  END;
  UPDATE screening_ledger_snapshot s
    SET purged_at = clock_timestamp(), purge_reason = p_reason,
        envelope_json = (envelope_json - 'nonce_base64' - 'ciphertext_base64')
          || jsonb_build_object('purged_at', clock_timestamp(), 'purge_reason', p_reason)
    WHERE s.purged_at IS NULL
      AND EXISTS (
        SELECT 1 FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
      )
      AND NOT EXISTS (
        SELECT 1 FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
          AND e.expires_at >= clock_timestamp()
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
DECLARE conflict_sha256 text;
DECLARE conflict_purged_at timestamptz;
DECLARE conflict_operator text;
BEGIN
  BEGIN
    WITH eligible AS (
      SELECT s.snapshot_sha256
      FROM screening_ledger_snapshot s
      WHERE s.snapshot_sha256 = ANY(p_snapshot_sha256) AND s.purged_at IS NULL
        AND EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
        )
        AND NOT EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
            AND e.expires_at >= clock_timestamp()
        )
    ), inserted AS (
      INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
        SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM eligible
    ), updated AS (
      UPDATE screening_ledger_snapshot
        SET purged_at = clock_timestamp(), purge_reason = p_reason,
            envelope_json = (envelope_json - 'nonce_base64' - 'ciphertext_base64')
              || jsonb_build_object('purged_at', clock_timestamp(), 'purge_reason', p_reason)
        WHERE snapshot_sha256 IN (SELECT snapshot_sha256 FROM eligible)
        RETURNING snapshot_sha256
    )
    SELECT array_agg(snapshot_sha256) INTO recorded FROM updated;
  EXCEPTION WHEN unique_violation THEN
    SELECT s.snapshot_sha256, t.purged_at, t.operator INTO conflict_sha256, conflict_purged_at, conflict_operator
      FROM screening_ledger_snapshot s
      JOIN screening_ledger_retention_tombstone t ON t.snapshot_sha256 = s.snapshot_sha256
      WHERE s.snapshot_sha256 = ANY(p_snapshot_sha256) AND s.purged_at IS NULL
        AND EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
        )
        AND NOT EXISTS (
          SELECT 1 FROM screening_ledger_event e
          WHERE (e.request_snapshot_sha256 = s.snapshot_sha256 OR e.response_snapshot_sha256 = s.snapshot_sha256)
            AND e.expires_at >= clock_timestamp()
        )
      LIMIT 1;
    RAISE EXCEPTION 'ADR-0007 Addendum 10 D87: a retention tombstone already exists for snapshot % (purged_at=%, operator=%), but the mirror still records it unpurged -- refusing rather than adopting the pre-existing row (SQLSTATE 23505)', conflict_sha256, conflict_purged_at, conflict_operator;
  END;
  RETURN COALESCE(recorded, ARRAY[]::text[]);
END;
$$;

-- This migration runs as owl_migrator, in db/migrations/ order, on a
-- FRESH database -- always before scripts/ci/provision_test_roles.sh
-- grant-ddl-ownership transfers ownership to owl_ledger_ddl, exactly as
-- 019/020 already established. On an already-provisioned database it
-- must instead run as the bootstrap superuser inside the documented
-- event-trigger disable window (docs/operations/sec7-database-copies.md),
-- since owl_migrator no longer owns these functions once
-- grant-ddl-ownership has run once (D87's own precedent, one migration
-- later).

COMMIT;
