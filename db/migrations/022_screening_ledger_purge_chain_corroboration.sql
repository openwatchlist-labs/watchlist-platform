-- ADR-0007 Addendum 12 D107 (P-E, MEDIUM): D98 moved both
-- screening_ledger_purge_snapshots overloads from ANY-expired to
-- ALL-expired, but left the quantifier ranging over the MIRROR
-- (screening_ledger_event) rather than the chain-authenticated
-- obligation D89/D97 already established as the authority. A snapshot
-- with a live, chain-authenticated retention obligation that has simply
-- not been mirrored yet (a sync backlog, not an adversary) is destroyed
-- by the shipped server floor, which the Go pass -- reading its own
-- local chain -- correctly refuses over the same instant. See
-- ADR-0007 Addendum 12 D107 for the full finding and reproduction.
--
-- The server cannot read the chain (Event.ExpiresAt lives in the ledger
-- directory under K_chain, not in this database), so the fix is a
-- caller-supplied, server-verified corroboration: the caller passes the
-- (count, max) its own local chain computes -- D97's own
-- snapshotObligation, already computed for this exact purpose -- and
-- the function refuses UNLESS its own mirror aggregate agrees exactly.
-- A caller can only make the check MORE restrictive (supplying a true,
-- larger obligation than the mirror alone would show) and can never
-- widen it, because eligibility itself is UNCHANGED: still D98's
-- ALL-expired-over-the-mirror predicate, with its leading EXISTS intact.
-- This is not G-C's refuted shape (a permissive predicate over
-- caller-chosen data) -- the supplied value is a constraint the caller
-- imposes on ITSELF, not a floor it can loosen (ADR-0007 Addendum 12
-- D107's own text argues this at length; not repeated here).
--
-- p_before -- a parameter every caller has bound since 008g but which
-- has been consulted by NEITHER overload since 020 replaced the
-- caller-supplied floor with clock_timestamp() -- is removed from both
-- signatures in this same change (CAP #11 drift note 2).
--
-- Array-form overload: the caller supplies one (count, max) pair PER
-- SNAPSHOT SHA, matched by array position to p_snapshot_sha256, scoped
-- to p_ledger_id (the same scoping D97(b)'s mirror corroboration
-- already uses -- a caller's own chain can only ever describe its own
-- obligations). ANY element's disagreement refuses the WHOLE call
-- (nothing partially recorded on the strength of a caller shown wrong
-- about one of its own claims).
--
-- Time-floor overload: has NO non-test Go caller today (D107's own
-- measurement: PostgresSink.PurgeExpired's only callers are two tests).
-- It is kept rather than deleted (D22's reason: a diagnostic backstop
-- for a database reached by some other path) but must be no weaker than
-- the array form beside it (D76). Since it has no caller-nominated
-- snapshot list to corroborate per-element, it gains the coarsest
-- version of the SAME corroboration instead: a single (count, max) pair
-- describing this ledger's ENTIRE chain-authenticated obligation across
-- every screening_ledger_event row for p_ledger_id, refused unless it
-- equals the mirror's own total for that ledger. This is a real,
-- caller-supplied constraint (not vacuously satisfiable) and is
-- distinguishable from the array form by Postgres's own overload
-- resolution on argument TYPES (scalar bigint/timestamptz vs.
-- int[]/timestamptz[] plus the leading text[]), not merely by name --
-- the two signatures could not otherwise coexist. See ADR-0007 Addendum
-- 12 D107's own text for why a per-snapshot shape is not reachable here
-- without either duplicating the array form's exact type signature
-- (which Postgres refuses to coexist with it) or renaming the function.
--
-- Fail-closed preamble, matching 015/017/019/020/021's style, per
-- CLAUDE.md's trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

-- Both signatures change their ARGUMENT TYPE LISTS (p_before dropped,
-- new parameters added), so CREATE OR REPLACE FUNCTION against the NEW
-- signature does not replace the OLD one -- Postgres resolves overloads
-- by argument types, and a different type list is a DIFFERENT function.
-- The old two-and-four-argument forms must be dropped explicitly, or
-- this migration leaves FOUR overloads live instead of two.
DROP FUNCTION IF EXISTS screening_ledger_purge_snapshots(timestamptz, text, text);
DROP FUNCTION IF EXISTS screening_ledger_purge_snapshots(text[], timestamptz, text, text);

-- p_before is DROPPED (CAP #11 drift note 2). p_ledger_id, p_expected_count,
-- p_expected_max are NEW: the caller-supplied, per-snapshot chain
-- obligation this overload now refuses to disagree with.
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE recorded text[];
DECLARE conflict_sha256 text;
DECLARE conflict_purged_at timestamptz;
DECLARE conflict_operator text;
DECLARE i int;
DECLARE mirror_count int;
DECLARE mirror_max timestamptz;
BEGIN
  IF array_length(p_snapshot_sha256, 1) IS DISTINCT FROM array_length(p_expected_count, 1)
     OR array_length(p_snapshot_sha256, 1) IS DISTINCT FROM array_length(p_expected_max, 1) THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: p_snapshot_sha256, p_expected_count and p_expected_max must be arrays of the same length';
  END IF;
  -- Leading refusal (D107): every caller-supplied (count, max) pair must
  -- agree EXACTLY with this ledger's own mirror aggregate for that sha,
  -- before any row is touched. One disagreement refuses the whole call.
  IF array_length(p_snapshot_sha256, 1) IS NOT NULL THEN
    FOR i IN 1 .. array_length(p_snapshot_sha256, 1) LOOP
      SELECT count(*), max(e.expires_at) INTO mirror_count, mirror_max
        FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = p_snapshot_sha256[i] OR e.response_snapshot_sha256 = p_snapshot_sha256[i])
          AND e.ledger_id = p_ledger_id;
      IF mirror_count IS DISTINCT FROM p_expected_count[i] OR mirror_max IS DISTINCT FROM p_expected_max[i] THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: snapshot %''s mirror screening_ledger_event aggregate (count=%, max=%, ledger=%) disagrees with the caller-supplied chain-authenticated obligation (count=%, max=%): refusing rather than purging under an unverified claim', p_snapshot_sha256[i], mirror_count, mirror_max, p_ledger_id, p_expected_count[i], p_expected_max[i];
      END IF;
    END LOOP;
  END IF;
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

-- Time-floor overload: p_before DROPPED; p_ledger_id, p_expected_count
-- (scalar), p_expected_max (scalar) are NEW -- see this file's header
-- for why a scalar, whole-ledger aggregate rather than a per-snapshot
-- array is what keeps this a DISTINCT, coexisting overload.
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_ledger_id text, p_expected_count bigint, p_expected_max timestamptz, p_operator text, p_reason text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE affected bigint;
DECLARE conflict_sha256 text;
DECLARE conflict_purged_at timestamptz;
DECLARE conflict_operator text;
DECLARE mirror_count bigint;
DECLARE mirror_max timestamptz;
BEGIN
  SELECT count(*), max(e.expires_at) INTO mirror_count, mirror_max
    FROM screening_ledger_event e WHERE e.ledger_id = p_ledger_id;
  IF mirror_count IS DISTINCT FROM p_expected_count OR mirror_max IS DISTINCT FROM p_expected_max THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 12 D107: ledger %''s TOTAL mirror screening_ledger_event aggregate (count=%, max=%) disagrees with the caller-supplied chain-authenticated obligation (count=%, max=%): refusing rather than purging under an unverified claim', p_ledger_id, mirror_count, mirror_max, p_expected_count, p_expected_max;
  END IF;
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

-- This IS a re-provisioning event on an already-provisioned database,
-- same as 020's own change was for D87's and 021's for D98's -- both
-- overloads are requiredProtectedObjects members, so this CREATE OR
-- REPLACE FUNCTION is refused by D34 on a database that has already run
-- grant-ddl-ownership; the documented recovery window
-- (docs/operations/sec7-database-copies.md) covers this migration by the
-- same procedure, one migration later (D111 updates that document's own
-- pointer). On a fresh database this cost does not apply.
--
-- This migration runs as owl_migrator, in db/migrations/ order, on a
-- FRESH database -- before grant-ddl-ownership ever installs the event
-- triggers, exactly as 019/020/021 already established.

COMMIT;
