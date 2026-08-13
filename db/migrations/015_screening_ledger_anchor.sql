-- SEC-7 Stage 2 (2/3): external anchor table (ADR-0007 §5.3, D3).
--
-- screening_ledger_anchor holds a periodic commitment to the screening
-- ledger's chain head, written by a DB role (owl_ledger_anchor) distinct
-- from the ledger writer (owl_migrator), under a key (K_anchor) that is
-- deliberately not derived from the chain-MAC root secret (ADR-0007 §5.1).
-- This is what defeats an adversary who holds the chain key but not the
-- anchor role/key together -- see §5.3's threat argument.
--
-- Schema is exactly ADR-0007 §5.3's CREATE TABLE -- no columns beyond what
-- the ADR specifies. Ownership transfer to owl_ledger_anchor and the
-- corresponding permanent membership drop for owl_migrator happen in
-- scripts/ci/provision_test_roles.sh, not here: ADR-0001 §"Roles and DSNs"
-- (docs/adr/0001-tenant-isolation.md:208) states "No migration contains
-- CREATE ROLE or GRANT," and ADR-0007 did not reconcile the new role with
-- that existing rule when it was written -- see the correction note added
-- to ADR-0007 §5.3 in this same PR. This migration only creates the table
-- (as owl_migrator, which owns it until the provisioning step transfers
-- ownership away) and its TRUNCATE guard.
BEGIN;

CREATE TABLE IF NOT EXISTS screening_ledger_anchor (
  ledger_id text NOT NULL,
  sequence bigint NOT NULL,
  event_sha256 text NOT NULL,
  audit_sha256 text NOT NULL,
  anchored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  anchor_mac text NOT NULL,
  PRIMARY KEY (ledger_id, sequence)
);

-- Fail-closed preamble, per CLAUDE.md's trap on 009g's silent-skip style:
-- owl_reject_truncate() must already exist (012_truncate_guards.sql) and
-- the table above must exist before the trigger statement runs.
DO $$
BEGIN
  IF to_regprocedure('owl_reject_truncate()') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 anchor migration: owl_reject_truncate() is missing; 012_truncate_guards.sql must run before 015';
  END IF;
  IF to_regclass('screening_ledger_anchor') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 anchor migration: screening_ledger_anchor does not exist after CREATE TABLE';
  END IF;
END $$;

-- The TRUNCATE guard the rest of the schema was missing when ADR-0007 was
-- drafted (§5.3 point 3) -- this table gets it from the start, using the
-- same function 012_truncate_guards.sql already established.
DROP TRIGGER IF EXISTS screening_ledger_anchor_no_truncate ON screening_ledger_anchor;
CREATE TRIGGER screening_ledger_anchor_no_truncate BEFORE TRUNCATE ON screening_ledger_anchor FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();

COMMIT;
