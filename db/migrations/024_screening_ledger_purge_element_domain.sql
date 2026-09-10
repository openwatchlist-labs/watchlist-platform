-- ADR-0007 Addendum 14 D123/D124 (F-A, CRITICAL): migration 023's
-- array-form overload reads its arguments through two descriptions that
-- do not denote the same elements. `array_length(p_snapshot_sha256, 1)`
-- and the `FOR i IN 1 .. array_length(...)` loop it drives range over
-- "the length of dimension 1" and "the element at subscript i, i in
-- 1..array_length" -- while `s.snapshot_sha256 = ANY(p_snapshot_sha256)`
-- (the destructive expression, in the eligible/updated CTE below) ranges
-- over EVERY element, at any subscript, in any dimension. Measured
-- directly: those two descriptions disagree in five of six array shapes
-- (a shifted lower bound, a second dimension, and the two combined), and
-- a caller who can issue one SELECT as owl_migrator -- section 2's own
-- identity, which holds EXECUTE on this function and cannot write a
-- retention tombstone any other way -- can construct a p_snapshot_sha256
-- whose shape defeats the leading corroboration entirely while the
-- destructive CTE below still purges every element `= ANY` matches. A
-- two-element multidimensional array against a one-element count array
-- goes further: `array_length(...,1)` reports 1 on BOTH sides (so even
-- the leading LENGTH PRECHECK agrees), and the loop still runs once
-- against a NULL subscript while `= ANY` destroys both. See ADR-0007
-- Addendum 14 D123/D124 for the full audit, the four independently
-- reproduced attack constructions, and the two candidate fixes measured
-- before this one was chosen.
--
-- The fix: `cardinality(...)` replaces `array_length(...,1)` as the
-- SOLE length measure (one measure, not two disagreeing ones -- CAP
-- #13's own invalidation condition forbids comparing array_length
-- against cardinality, which keeps two descriptions and asserts a
-- relationship between them, exactly the shape of the finding), and the
-- subscript loop is replaced by `unnest(...) WITH ORDINALITY`, which
-- ranges over exactly the element set `= ANY` tests, in storage order,
-- pairing all three arrays positionally. The subscript is removed; it is
-- not made safe (D31's own move: do not make the dangerous construct
-- safe, remove the construct). The ordinality value is read ONLY inside
-- the RAISE EXCEPTION diagnostic text below -- it never selects, never
-- filters and never decides, D46's own arrangement.
--
-- ADR-0007 Addendum 14 D131's withdrawal conditions apply verbatim: this
-- is NOT discharged by validating the array inside or before the loop
-- (array_lower = 1, array_ndims = 1, or comparing array_length against
-- cardinality, as "defence in depth" or otherwise -- a precondition
-- asserting two element sets coincide is strictly weaker than having one
-- element set), and NOT by revoking EXECUTE on this overload from
-- owl_migrator (that retires the reachability and leaves the arithmetic
-- wrong).
--
-- D125: SchemaSQL's own array-form copy (internal/screeningledger/
-- postgres.go's SchemaSQL constant) carries the identical pre-fix text
-- and is live on the SchemaSQL bootstrap path -- it gets the
-- byte-equivalent repair in the SAME change, not a separate one; D117's
-- finding (a control declared for one bootstrap path and not the other)
-- is exactly this shape read from the other side.
--
-- Migration 022's superseded literal and migration 023's own
-- now-superseded literal both stay as committed history, untouched --
-- D99(c)'s precedent: on the full migration path this migration's
-- CREATE OR REPLACE wins, so 022's and 023's literals are live on no
-- database this repository provisions, and D99(b)'s already-shipped
-- stronger property (every superseded committed literal must digest to
-- something outside every declared accepted set) covers the newly
-- superseded 023 literal without an edit.
--
-- Fail-closed preamble, matching 015/017/019/020/021/022/023's style,
-- per CLAUDE.md's trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 14 D124: screening_ledger_retention_tombstone does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 14 D124: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 14 D124: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

-- Array-form overload: the leading corroboration is now driven entirely
-- by cardinality()/unnest() -- no array_length(...,1) and no subscript
-- anywhere in this body. Every other property (the GLOBAL, unscoped
-- mirror aggregate; the p_ledger_id non-vacuity check; the eligible/
-- updated CTE; the unique_violation handler) is UNCHANGED from 023.
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
DECLARE rec record;
DECLARE mirror_count int;
DECLARE mirror_max timestamptz;
BEGIN
  IF coalesce(cardinality(p_snapshot_sha256), 0) IS DISTINCT FROM coalesce(cardinality(p_expected_count), 0)
     OR coalesce(cardinality(p_snapshot_sha256), 0) IS DISTINCT FROM coalesce(cardinality(p_expected_max), 0) THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 14 D124: p_snapshot_sha256, p_expected_count and p_expected_max must carry the same number of ELEMENTS (cardinality %, %, %)', cardinality(p_snapshot_sha256), cardinality(p_expected_count), cardinality(p_expected_max);
  END IF;
  -- ADR-0007 Addendum 13 D116(b): p_ledger_id is a checked claim, not a
  -- population selector -- it must resolve to a ledger this mirror
  -- actually knows about, refused by name otherwise. Checked once,
  -- before any per-element comparison, so a caller cannot satisfy the
  -- corroboration below by naming a ledger that never wrote a row. An
  -- empty (or NULL) p_snapshot_sha256 is a legitimate no-op and must not
  -- be refused merely because the ledger itself has no rows yet
  -- (D116(b)/(c), unchanged).
  IF coalesce(cardinality(p_snapshot_sha256), 0) > 0 THEN
    IF NOT EXISTS (SELECT 1 FROM screening_ledger_event WHERE ledger_id = p_ledger_id) THEN
      RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: ledger % has no rows in this mirror: refusing rather than adjudicating a claim against a ledger that does not exist here', p_ledger_id;
    END IF;
    -- ADR-0007 Addendum 14 D124: unnest(...) WITH ORDINALITY ranges over
    -- exactly the element set `= ANY(p_snapshot_sha256)` below tests, in
    -- storage order, for all three arrays paired positionally. `ord` (the
    -- element's 1-based position in iteration order, NOT a subscript
    -- into any array) is read ONLY inside the diagnostic text -- it never
    -- selects, filters or decides anything.
    FOR rec IN
      SELECT * FROM unnest(p_snapshot_sha256, p_expected_count, p_expected_max)
        WITH ORDINALITY AS t(sha, expected_count, expected_max, ord)
    LOOP
      SELECT count(*), max(e.expires_at) INTO mirror_count, mirror_max
        FROM screening_ledger_event e
        WHERE (e.request_snapshot_sha256 = rec.sha OR e.response_snapshot_sha256 = rec.sha);
      IF mirror_count IS DISTINCT FROM rec.expected_count OR mirror_max IS DISTINCT FROM rec.expected_max THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 13 D116: snapshot % (element % of %)''s GLOBAL mirror screening_ledger_event aggregate (count=%, max=%) disagrees with the caller-supplied chain-authenticated obligation (count=%, max=%, claimed ledger=%): refusing rather than purging under an unverified claim', rec.sha, rec.ord, cardinality(p_snapshot_sha256), mirror_count, mirror_max, rec.expected_count, rec.expected_max, p_ledger_id;
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

-- This IS a re-provisioning event on an already-provisioned database,
-- same as 020's/021's/022's/023's own change was. Both declared digests
-- for this overload move; the documented recovery window
-- (docs/operations/sec7-database-copies.md) covers this migration by the
-- same procedure. On a fresh database this cost does not apply.
--
-- This migration runs as owl_migrator, in db/migrations/ order, on a
-- FRESH database -- before grant-ddl-ownership ever installs the event
-- triggers, exactly as 019/020/021/022/023 already established.

COMMIT;
