-- SEC-7 repair (ADR-0007 Addendum 1 D19/F5): screening_ledger_replication
-- gains verified_at and verification_mode, written in the same
-- transaction as the replication row they describe.
--
-- Not belt-and-braces: screening_ledger_replication already carries the
-- BEFORE UPDATE OR DELETE immutability trigger every Class C table in
-- this schema has (012_truncate_guards.sql's trigger, applied via
-- postgres.go's SchemaSQL), so a row mirrored without recording whether
-- it was verified can never afterwards be corrected, annotated or
-- removed by the identity that wrote it. The fact must be recorded at
-- write time or it is unrecordable.
--
-- Fail-closed preamble, matching 015's and 017's style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_replication') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 repair: screening_ledger_replication does not exist; earlier migrations must run first';
  END IF;
END $$;

ALTER TABLE screening_ledger_replication
  ADD COLUMN IF NOT EXISTS verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS verification_mode text;

COMMIT;
