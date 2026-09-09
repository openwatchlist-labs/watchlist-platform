-- ADR-0007 Addendum 13 D116 (F-B, HIGH): D107's own corroboration
-- scoped its mirror aggregate to a caller-supplied p_ledger_id
-- (022:114, 022:185) while the eligibility predicate it is supposed to
-- constrain is global and unscoped (022:126-133, 022:194-206). A caller
-- who supplies a foreign, NON-EXISTENT ledger_id together with the
-- vacuous claim (0, NULL) satisfies the scoped leading refusal for
-- every element -- (0, NULL) truthfully describes what that ledger_id's
-- own slice of the mirror holds, which is nothing, because no such
-- ledger has ever written a row. The corroboration then adjudicates
-- nothing and the unscoped eligibility predicate purges snapshots a
-- real, honest ledger's chain still holds a live obligation for. See
-- ADR-0007 Addendum 13 D116 for the full finding and reproduction.
--
-- The fix moves the corroboration's population OUTWARD to meet
-- eligibility (never eligibility's inward to meet the corroboration,
-- D103's third condition, restated by D112 and again here): both
-- overloads' mirror aggregates drop their `AND e.ledger_id = ...`
-- scoping entirely, so there is no ledger-scoped slice for a caller to
-- pick and thereby weaken. p_ledger_id is retained -- it is what makes
-- D107's refusal message name whose claim was adjudicated -- but stops
-- being a population selector and becomes a checked claim: it must
-- resolve to a ledger that has rows, refused by name otherwise (the
-- non-vacuity this migration's own header sentence claims but does not
-- yet enforce, made a property of the function rather than of its
-- comment).
--
-- The global form is only honest under a tenancy declaration that is
-- both asserted over every relation carrying ledger_id (ADR-0007
-- Addendum 13 D119, ForeignLedgerIDs) and true of the environment it
-- runs in. Under TenancyExclusive the global population IS this
-- ledger's, so an honest caller's own chain aggregate still matches and
-- a legitimate purge succeeds exactly as it does today. Under
-- TenancyShared a single ledger structurally cannot supply the global
-- aggregate -- this database-side function has no policy to consult, so
-- that refusal is enforced at the caller (Store.PurgeExpired,
-- internal/screeningledger/replay.go), before RecordPurge is ever
-- called; R49's own honest limit, stated at purge time instead of
-- discovered at verification time.
--
-- Fail-closed preamble, matching 015/017/019/020/021/022's style, per
-- CLAUDE.md's trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

-- Array-form overload: the per-sha mirror aggregate is now GLOBAL (no
-- ledger_id filter), matching the eligibility predicate's own
-- unscoped population. p_ledger_id gains a checked meaning: it must
-- resolve to a ledger with at least one screening_ledger_event row, or
-- the whole call is refused before any per-sha comparison runs.
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
  -- ADR-0007 Addendum 13 D116(b): p_ledger_id is a checked claim, not a
  -- population selector -- it must resolve to a ledger this mirror
  -- actually knows about, refused by name otherwise. Checked once,
  -- before any per-sha comparison, so a caller cannot satisfy the
  -- corroboration below by naming a ledger that never wrote a row.
  -- Leading refusal (D107, D116): every caller-supplied (count, max)
  -- pair must agree EXACTLY with this sha's GLOBAL mirror aggregate --
  -- the population the eligibility predicate below already ranges
  -- over -- before any row is touched. One disagreement refuses the
  -- whole call. The ledger-has-rows check (D116(b)/(c)) applies only
  -- when there is at least one sha to adjudicate -- an empty array is a
  -- legitimate no-op (a fresh ledger with nothing yet to purge calling
  -- this with zero eligible snapshots), not a claim to corroborate, and
  -- must not be refused merely because the ledger itself has no rows
  -- yet.
  IF array_length(p_snapshot_sha256, 1) IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM screening_ledger_event WHERE ledger_id = p_ledger_id) THEN
      RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: ledger % has no rows in this mirror: refusing rather than adjudicating a claim against a ledger that does not exist here', p_ledger_id;
    END IF;
    FOR i IN 1 .. array_length(p_snapshot_sha256, 1) LOOP
      SELECT count(*), max(e.expires_at) INTO mirror_count, mirror_max
        FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = p_snapshot_sha256[i] OR e.response_snapshot_sha256 = p_snapshot_sha256[i]);
      IF mirror_count IS DISTINCT FROM p_expected_count[i] OR mirror_max IS DISTINCT FROM p_expected_max[i] THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: snapshot %''s GLOBAL mirror screening_ledger_event aggregate (count=%, max=%) disagrees with the caller-supplied chain-authenticated obligation (count=%, max=%, claimed ledger=%): refusing rather than purging under an unverified claim', p_snapshot_sha256[i], mirror_count, mirror_max, p_expected_count[i], p_expected_max[i], p_ledger_id;
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

-- Time-floor overload: the whole-mirror aggregate is now GLOBAL (no
-- ledger_id filter) -- matching this overload's own eligibility
-- predicate, which was already fully unscoped. p_ledger_id gains the
-- same checked meaning as the array form.
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
  IF NOT EXISTS (SELECT 1 FROM screening_ledger_event WHERE ledger_id = p_ledger_id) THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: ledger % has no rows in this mirror: refusing rather than adjudicating a claim against a ledger that does not exist here', p_ledger_id;
  END IF;
  SELECT count(*), max(e.expires_at) INTO mirror_count, mirror_max
    FROM screening_ledger_event e;
  IF mirror_count IS DISTINCT FROM p_expected_count OR mirror_max IS DISTINCT FROM p_expected_max THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: the GLOBAL mirror screening_ledger_event aggregate (count=%, max=%) disagrees with the caller-supplied chain-authenticated obligation (count=%, max=%, claimed ledger=%): refusing rather than purging under an unverified claim', mirror_count, mirror_max, p_expected_count, p_expected_max, p_ledger_id;
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
-- same as 020's, 021's and 022's own change was. Both overloads are
-- requiredProtectedObjects members, so this CREATE OR REPLACE FUNCTION
-- is refused by D34 on a database that has already run
-- grant-ddl-ownership; the documented recovery window
-- (docs/operations/sec7-database-copies.md) covers this migration by
-- the same procedure. On a fresh database this cost does not apply.
--
-- This migration runs as owl_migrator, in db/migrations/ order, on a
-- FRESH database -- before grant-ddl-ownership ever installs the event
-- triggers, exactly as 019/020/021/022 already established.

COMMIT;
