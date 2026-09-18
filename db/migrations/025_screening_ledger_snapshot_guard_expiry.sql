-- ADR-0007 Addendum 21 (D163/D164): screening_ledger_snapshot_guard()'s
-- allowed purge transition was adjudicated against NOTHING -- any UPDATE
-- that set purged_at, left every other column pinned to its own prior
-- value, and removed 'ciphertext_base64' was accepted regardless of
-- whether the snapshot's referencing screening_ledger_event rows were
-- still under a live retention obligation (R40, carried since Addendum
-- 10 D89, sharpened by Addendum 19 D150, designed by Addendum 21).
-- Measured directly against the shipped guard before this migration:
-- both owl_migrator and owl_ledger_ddl can strip protected ciphertext
-- from a snapshot under a 2100-01-01 obligation with NO DROP TRIGGER and
-- NO key of any kind, and nothing observes it afterward -- not
-- Migrate(), not grant-ddl-ownership, and not the D89/D97 divergence
-- check, whose only two entry points (internal/screeningledger/anchor.go
-- purgeLowerBoundSource.forSnapshot, called from the local purge-claims
-- loop and the tombstone-row loop) a direct mirror-side strip reaches
-- neither of, since it writes no local claim and leaves no tombstone.
--
-- D163: the fix is expiry-aware, adjudicated against the set of
-- screening_ledger_event rows referencing the snapshot, using the
-- IDENTICAL EXISTS/NOT EXISTS pair the definer overloads' own eligible
-- CTE already uses (024:166-174, and both of 021's copies) -- both
-- halves, not one. The NOT EXISTS half alone is vacuously true for a
-- snapshot no event references, which would permit stripping exactly
-- the rows the mirror knows nothing about (D116(b)'s own vacuity trap);
-- shipping only that half would make this guard weaker than the definer
-- it aligns with.
--
-- Two referents were measured and refused rather than adopted:
--   - screening_ledger_snapshot's OWN expires_at/created_at/retention_
--     class (the envelope's copies included): D89 ground two's exact
--     shape one column over, covered by no MAC anywhere (D156), and the
--     guard's existing OLD.expires_at=NEW.expires_at pin makes it
--     un-rewritable at THIS statement while doing nothing about its
--     having been freely chosen at INSERT by owl_migrator. Un-rewritable
--     is not unforgeable (N-A's lesson).
--   - "reachable only through the SECURITY DEFINER purge path"
--     (D150's offered equivalence): not an equivalent. The only way a
--     trigger can implement it is a current_user test naming
--     owl_ledger_ddl -- a NAME as terminating literal (D68), and
--     measured to admit exactly the path this migration closes, since
--     owl_ledger_ddl holds UPDATE on screening_ledger_snapshot directly
--     and needs no definer to use it.
--
-- D164: found while prototyping D163, not inherited from any CAP. The
-- guard runs with INVOKER rights (no SECURITY DEFINER), so a bare
-- relation name inside it is resolved through the caller's own
-- search_path -- and pg_temp is searched before the listed path whenever
-- it is not itself listed. TEMP is granted to PUBLIC by default, so
-- every role in the live population can CREATE TEMP TABLE
-- screening_ledger_event and shadow the guard's own referent. Measured:
-- a bare name defeats the D163 check even WITH
-- "SET search_path = pg_catalog, public" present, because pg_temp is
-- still searched ahead of an unlisted schema regardless of what IS
-- listed; a public.-qualified name refuses correctly with or without
-- that clause. The fix is qualification -- every mirror reference below
-- is public.screening_ledger_event -- and the SET search_path clause
-- below is kept for style consistency with 019-024 only; it is NOT what
-- makes this guard sound (R81).
--
-- The shipped definer overloads (019-024) are NOT exposed to this class:
-- they run SECURITY DEFINER as owl_ledger_ddl, which holds no USAGE on
-- the caller's temp schema, so the same pg_temp decoy is refused with
-- "permission denied for table screening_ledger_event" -- a privilege
-- accident, not a designed property (R84), since it holds only while
-- owl_ledger_ddl is distinct from every role holding EXECUTE.
--
-- This is a re-provisioning event on every already-provisioned database
-- (docs/operations/sec7-database-copies.md covers it); on a fresh
-- database this migration runs in db/migrations/ order, as owl_migrator,
-- before grant-ddl-ownership ever installs the D34 event triggers, so no
-- disable window is needed there.
--
-- Fail-closed preamble, matching 015/017/019/020/021/022/023/024's
-- style, per CLAUDE.md's trap on 009g's silent-skip style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_snapshot') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: screening_ledger_snapshot does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regclass('screening_ledger_event') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: screening_ledger_event does not exist; 008g_screening_ledger.sql must run first';
  END IF;
  IF to_regprocedure('screening_ledger_snapshot_guard()') IS NULL THEN
    RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: screening_ledger_snapshot_guard() does not exist; 008g_screening_ledger.sql must run first';
  END IF;
END $$;

-- This CREATE OR REPLACE runs unconditionally, as every migration in
-- this directory does: db/migrations/*.sql is applied exactly once, in
-- order, deliberately (under the documented disable window once the
-- function is registered, per docs/operations/sec7-database-copies.md)
-- -- unlike SchemaSQL (internal/screeningledger/postgres.go), which runs
-- as owl_migrator on every migrate/sync/import-audit invocation and
-- therefore needs D78's assert-and-fail treatment instead (mirrored
-- there, byte-identically, so the two bootstrap paths produce the same
-- committed body -- D165, this addendum).
--
-- The trigger itself (screening_ledger_snapshot_guard_trigger,
-- installed by 008g) is unchanged: it is bound to this function by NAME,
-- and CREATE OR REPLACE FUNCTION does not change the function's OID, so
-- the existing trigger picks up this new body with no DROP/CREATE
-- TRIGGER statement needed here.
CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard()RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN IF TG_OP='DELETE'THEN RAISE EXCEPTION 'screening snapshots cannot be deleted';END IF;IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL AND OLD.snapshot_sha256=NEW.snapshot_sha256 AND OLD.kind=NEW.kind AND OLD.created_at=NEW.created_at AND OLD.expires_at=NEW.expires_at AND OLD.retention_class=NEW.retention_class AND NOT(NEW.envelope_json?'ciphertext_base64')THEN IF NOT EXISTS(SELECT 1 FROM public.screening_ledger_event e WHERE e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256)THEN RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: snapshot % has no referencing screening_ledger_event row: refusing to strip protected content rather than reading an absent obligation as an expired one',OLD.snapshot_sha256;END IF;IF EXISTS(SELECT 1 FROM public.screening_ledger_event e WHERE(e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256)AND e.expires_at>=clock_timestamp())THEN RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: snapshot % is still under a live retention obligation (mirror MAX(screening_ledger_event.expires_at)=%): refusing to strip protected content',OLD.snapshot_sha256,(SELECT max(e.expires_at)FROM public.screening_ledger_event e WHERE e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256);END IF;RETURN NEW;END IF;RAISE EXCEPTION 'screening snapshot mutation is not an allowed retention transition';END $$;

-- Migration 022's/008g's now-superseded literal stays as committed
-- history, untouched -- D99(c)'s precedent: on the full migration path
-- this migration's CREATE OR REPLACE wins, so 008g's body is live on no
-- database this repository provisions, and D99(b)'s already-shipped
-- property (every superseded committed literal must digest outside
-- every declared accepted set) covers it without a new pinned constant.
-- Measured: 008g's literal digests to
-- f9cb95289a3fdead146dc24a3f8d0824dc225e37bfa98a0dc120731f09872330,
-- OUTSIDE the one-member accepted set this migration's own literal (and
-- SchemaSQL's byte-identical copy of it) digest to,
-- 24b20526089312abbe8b07acb7ecdf94bc24c4bba7eb140c742f0d3b1534d616.

COMMIT;
