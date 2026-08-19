-- SEC-7 repair (ADR-0007 Addendum 1 D11, D16): bind each anchor row to
-- the signed verification policy it was written under, add the audit
-- chain's own sequence number so AR7 can cross-check it the same way
-- the event chain always was, and give the anchor table the
-- row-immutability trigger F7 found missing (D16).
--
-- This changes anchor_mac's input (see internal/screeningledger/anchor.go's
-- anchorMAC) and therefore invalidates every existing anchor row. There
-- are none, in any environment (F1b: nothing writes them until this same
-- repair adds the `screening-ledger anchor` subcommand), so this is free
-- now and never free again -- the same argument ADR-0007 §6 and Addendum
-- 1's D11 make about their own migrations.
--
-- Fail-closed preamble, per CLAUDE.md's trap on 009g's silent-skip style,
-- matching 015's own style.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_anchor') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 repair: screening_ledger_anchor does not exist; 015_screening_ledger_anchor.sql must run first';
  END IF;
  IF to_regprocedure('screening_ledger_reject_mutation()') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 repair: screening_ledger_reject_mutation() is missing; it must already exist for the row-immutability trigger below';
  END IF;
END $$;

ALTER TABLE screening_ledger_anchor
  ADD COLUMN IF NOT EXISTS audit_sequence bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS policy_sha256 text NOT NULL DEFAULT '';

ALTER TABLE screening_ledger_anchor ALTER COLUMN audit_sequence DROP DEFAULT;
ALTER TABLE screening_ledger_anchor ALTER COLUMN policy_sha256 DROP DEFAULT;

-- D16 (F7): the anchor table has had only the TRUNCATE guard since 015 --
-- every other protected table in this schema has had both since 012.
-- Combined with F6 (the writer used to be the owner) this let the writer
-- UPDATE or DELETE an existing anchor row in place; D17's role split
-- closes F6 in scripts/ci/provision_test_roles.sh, this closes F7.
DROP TRIGGER IF EXISTS screening_ledger_anchor_immutable ON screening_ledger_anchor;
CREATE TRIGGER screening_ledger_anchor_immutable BEFORE UPDATE OR DELETE ON screening_ledger_anchor
  FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();

COMMIT;
